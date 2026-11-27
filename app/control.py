"""显式启用的本地闭环验收：只模拟外部身份、风险事实与目标接收状态。"""
from __future__ import annotations

import asyncio
import base64
import binascii
from contextvars import ContextVar
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import secrets
from threading import RLock
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.config import get_settings
from app.security_operations.state import BUSINESS_STATE, FAMILIES, MockError


MARKERS = ("MOCK_CONTROL_DENY_INPUT", "MOCK_CONTROL_DENY_WRITE", "MOCK_CONTROL_SENSITIVE_REPORT")
RESOURCE_URI = "mock-control://soc/asset-summary"
RESOURCE_TEXT = "测试资产 9106、9107 在线；9200 无告警。仅为本地固定模拟资源。"
FIXTURES: dict[str, dict] = {}
LOCK = RLock()
CURRENT_FIXTURE: ContextVar[dict | None] = ContextVar("mock_control_fixture", default=None)
CURRENT_SUBJECT: ContextVar[str | None] = ContextVar("mock_control_subject", default=None)
Subject = Literal["subject-a", "subject-b"]


def stamp(delta: float = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=delta)).isoformat().replace("+00:00", "Z")


def expired(value: str) -> bool:
    return datetime.fromisoformat(value.replace("Z", "+00:00")) <= datetime.now(timezone.utc)


def fingerprint(value: Any) -> str:
    data = value if isinstance(value, bytes) else json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    return "sha256:" + sha256(data).hexdigest()


def enabled() -> None:
    if not get_settings().mock_control_enabled:
        raise HTTPException(404, "未启用本地验收接口。")


def fixture(test_run_id: str) -> dict:
    with LOCK:
        result = FIXTURES.get(test_run_id)
        if result is None:
            raise HTTPException(404, "未找到对应验收 fixture。")
        return result


class FixtureInput(BaseModel):
    testRunId: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,128}$", description="隔离本次验收状态的稳定标识。")


class CredentialInput(BaseModel):
    action: Literal["rotate", "revoke", "expire"]
    expiresInSeconds: int = Field(default=600, ge=1, le=3600)


class CredentialResponse(BaseModel):
    subjectId: Subject
    credentialId: str
    expiresAt: str
    credential: str | None = Field(default=None, description="仅创建或轮换响应返回，不进入账本。")


class FixtureResponse(BaseModel):
    testRunId: str
    credentials: list[CredentialResponse]


class AuthenticationInput(BaseModel):
    credential: str = Field(min_length=1, max_length=4096, description="仅用于比对摘要，不保存原值。")


class AuthenticationResponse(BaseModel):
    authenticated: bool
    subjectId: Subject | None = None
    credentialId: str | None = None
    expiresAt: str | None = None
    reason: str | None = None


class TrustInput(BaseModel):
    subjectId: Subject
    credentialId: str = Field(pattern=r"^credential_[a-f0-9]{32}$")


class TrustResponse(BaseModel):
    valid: bool
    subjectId: Subject
    expiresAt: str | None = None
    reason: str | None = None


class RiskScope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    workspaceId: str = Field(min_length=1, max_length=500)
    agentId: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$", max_length=128)
    instanceId: str = Field(min_length=1, max_length=256)
    runtimeGeneration: str = Field(min_length=1, max_length=256)
    subjectId: Subject
    sessionId: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.-]{1,128}$")
    serverId: str | None = Field(default=None, min_length=1, max_length=256)

    @field_validator("workspaceId", "instanceId", "runtimeGeneration", "serverId")
    @classmethod
    def meaningful_identifier(cls, value: str | None) -> str | None:
        if value is not None and (not value.strip() or any(ord(char) < 32 for char in value)):
            raise ValueError("风险范围标识无效。")
        return value


class RiskOperationBinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    serverId: str = Field(min_length=1, max_length=256)
    operationId: str = Field(min_length=1, max_length=256)
    target: str = Field(min_length=1, max_length=4096)
    method: str = Field(min_length=1, max_length=32)
    kind: Literal["read", "write", "resource", "publish"]

    @field_validator("serverId", "operationId", "target", "method")
    @classmethod
    def meaningful_binding(cls, value: str) -> str:
        if not value.strip() or any(ord(char) < 32 for char in value):
            raise ValueError("实际操作描述无效。")
        return value


class RiskInput(FixtureInput):
    subjectId: Subject
    sessionId: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.-]{1,128}$")
    operation: str = Field(min_length=1, max_length=256)
    phase: Literal["input", "execute", "report"] = "execute"
    input: Any = Field(default=None, description="只检测固定无害标记，任意正文不保存不回显。")
    scope: RiskScope | None = Field(default=None, description="调用方已解析的 Agent 范围；与外层主体及 Session 必须一致，不以 Header 补充身份。")
    sourceDigest: str | None = Field(default=None, min_length=1, max_length=500, pattern=r"^\S+$", description="实际装载来源摘要；只用于外部事实请求，不保存或回显。")
    operationBinding: RiskOperationBinding | None = Field(default=None, description="可选的已解析实际工具或资源描述；输入阶段没有具体操作时可省略。")

    @model_validator(mode="after")
    def consistent_scope(self) -> "RiskInput":
        if self.operationBinding and self.operationBinding.kind != self.operation:
            raise ValueError("风险动作与实际操作类型不一致。")
        if self.scope and (self.scope.subjectId != self.subjectId
                           or (self.sessionId is not None and self.scope.sessionId is not None
                               and self.scope.sessionId != self.sessionId)
                           or (self.operationBinding and self.scope.serverId is not None
                               and self.operationBinding.serverId != self.scope.serverId)):
            raise ValueError("风险请求范围与实际主体或操作不一致。")
        return self


class RiskUpdate(BaseModel):
    subjectId: Subject
    agentId: str | None = Field(default=None, pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$", max_length=128,
                                description="限定业务 Agent；省略时兼容原有跨 Agent 主体限制。")
    sessionId: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.-]{1,128}$")
    deniedOperations: list[str] = Field(max_length=64, description="支持 *、write、publish、read 或实际 operationId；空数组解除该范围限制。")
    expiresInSeconds: int = Field(default=60, ge=-3600, le=3600, description="非正值用于验证过期风险事实。")


class RiskResponse(BaseModel):
    scope: dict[str, str]
    version: int
    expiresAt: str
    level: Literal["low", "high"]
    constraints: dict[str, list[str]]
    reasons: list[str]


class FaultInput(BaseModel):
    operation: str = Field(min_length=1, max_length=256)
    mode: Literal["delay", "block", "committed-timeout"]
    seconds: float = Field(default=1, gt=0, le=30, description="延迟、阻塞上限或提交后响应延迟秒数。")


class FaultResponse(BaseModel):
    faultId: str
    operation: str
    mode: str


class RequestRecord(BaseModel):
    requestId: str
    subjectId: Subject | None
    operation: str
    target: str
    argumentsHash: str
    phase: Literal["started", "committed", "finished"]
    startedAt: str
    committedAt: str | None = None
    finishedAt: str | None = None
    outcome: str | None = None
    reportBodyHash: str | None = None
    reportMarkers: list[str] = Field(default_factory=list)


def new_credential(current: dict, subject_id: str, lifetime: int = 600) -> dict:
    credential = "mock_" + secrets.token_urlsafe(32)
    record = {"subjectId": subject_id, "credentialId": "credential_" + secrets.token_hex(16),
              "expiresAt": stamp(lifetime), "revoked": False, "digest": fingerprint(credential)}
    current["credentials"][subject_id] = record
    return {key: record[key] for key in ("subjectId", "credentialId", "expiresAt")} | {"credential": credential}


router = APIRouter(prefix="/api/v1/control", tags=["本地闭环验收"], dependencies=[Depends(enabled)])


@router.post("/fixtures", response_model=FixtureResponse, summary="创建隔离验收状态",
             description="仅显式启用的独立验收实例可用；重复标识返回 409，不覆盖历史账本。")
def create_fixture(body: FixtureInput):
    with LOCK:
        if body.testRunId in FIXTURES:
            raise HTTPException(409, "验收 fixture 已存在。")
        current = {"testRunId": body.testRunId, "credentials": {}, "risk": {}, "assessments": {}, "version": 1,
                   "requests": [], "faults": [], "business": {name: {} for name in FAMILIES}}
        credentials = [new_credential(current, subject) for subject in ("subject-a", "subject-b")]
        FIXTURES[body.testRunId] = current
        return {"testRunId": body.testRunId, "credentials": credentials}


@router.post("/fixtures/{test_run_id}/credentials/{subject_id}", response_model=CredentialResponse,
             summary="轮换、撤销或过期模拟凭据", description="轮换保持主体身份，旧凭据立即失效；原凭据不回显。")
def change_credential(test_run_id: str, subject_id: Subject, body: CredentialInput):
    current = fixture(test_run_id)
    with LOCK:
        if body.action == "rotate":
            return new_credential(current, subject_id, body.expiresInSeconds)
        record = current["credentials"][subject_id]
        if body.action == "revoke":
            record["revoked"] = True
        else:
            record["expiresAt"] = stamp(-1)
        return {key: record[key] for key in ("subjectId", "credentialId", "expiresAt")}


@router.post("/identity/authenticate", response_model=AuthenticationResponse, summary="认证本地测试凭据",
             description="只识别 fixture 生成的凭据；仅保存其摘要。未知、撤销及过期统一拒绝。")
def authenticate(body: AuthenticationInput):
    digest = fingerprint(body.credential)
    with LOCK:
        for current in FIXTURES.values():
            for record in current["credentials"].values():
                if secrets.compare_digest(digest, record["digest"]) and not record["revoked"] and not expired(record["expiresAt"]):
                    return {"authenticated": True, **{key: record[key] for key in ("subjectId", "credentialId", "expiresAt")}}
    return {"authenticated": False, "reason": "credential-invalid"}


@router.post("/identity/trust", response_model=TrustResponse, summary="核对主体当前可信状态",
             description="主体和凭据标识必须仍绑定且未失效；不能仅以稳定主体名证明身份。")
def trust(body: TrustInput):
    with LOCK:
        for current in FIXTURES.values():
            record = current["credentials"][body.subjectId]
            if record["credentialId"] == body.credentialId and not record["revoked"] and not expired(record["expiresAt"]):
                return {"valid": True, "subjectId": body.subjectId, "expiresAt": record["expiresAt"]}
    return {"valid": False, "subjectId": body.subjectId, "reason": "identity-invalid"}


@router.put("/fixtures/{test_run_id}/risk", response_model=RiskResponse, summary="调整指定 Agent、主体或 Session 的风险事实",
            description="可选 Agent 范围独立保存；每次修改递增 fixture 版本，空约束只解除指定范围限制。")
def update_risk(test_run_id: str, body: RiskUpdate):
    current = fixture(test_run_id)
    if any(not item or len(item) > 256 or not all(char.isalnum() or char in "_*:./-" for char in item)
           for item in body.deniedOperations):
        raise HTTPException(422, "受限操作标识无效。")
    with LOCK:
        current["version"] += 1
        scope = {"subjectId": body.subjectId}
        if body.agentId:
            scope["agentId"] = body.agentId
        if body.sessionId:
            scope["sessionId"] = body.sessionId
        record = {"scope": scope, "version": current["version"], "expiresAt": stamp(body.expiresInSeconds),
                  "level": "high" if body.deniedOperations else "low",
                  "constraints": {"deniedOperations": list(dict.fromkeys(body.deniedOperations))},
                  "reasons": ["fixture-risk"] if body.deniedOperations else []}
        current["risk"][(body.agentId, body.subjectId, body.sessionId)] = record
        return deepcopy(record)


def detected_markers(value: Any) -> list[str]:
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, dict) and isinstance(value.get("fileContentBase64"), str):
        try:
            text += base64.b64decode(value["fileContentBase64"], validate=True).decode("utf-8", errors="replace")
        except (ValueError, binascii.Error):
            pass
    return [marker for marker in MARKERS if marker in text]


@router.post("/risk/evaluate", response_model=RiskResponse, summary="评估当前 Agent、主体、实际操作与固定测试信号",
             description="默认允许；接受已解析的 Agent 范围、来源摘要和实际操作，合并兼容主体限制及本 Agent 限制；不将请求或 Header 当作认证证明。")
def evaluate_risk(body: RiskInput):
    current = fixture(body.testRunId)
    agent_id = body.scope.agentId if body.scope else None
    session_id = (body.scope.sessionId if body.scope else None) or body.sessionId
    with LOCK:
        keys = dict.fromkeys((agent, body.subjectId, session)
                             for agent in (None, agent_id) for session in (None, session_id))
        records = [current["risk"][key] for key in keys
                   if key in current["risk"]]
        denied = list(dict.fromkeys(item for record in records for item in record["constraints"]["deniedOperations"]))
        markers = detected_markers(body.input)
        if MARKERS[0] in markers and body.phase == "input":
            denied.append("*")
        if MARKERS[1] in markers and body.phase == "execute":
            denied.append("write")
        if MARKERS[2] in markers and body.phase == "report":
            denied.append("publish")
        scope = body.scope.model_dump(exclude_none=True) if body.scope else {"subjectId": body.subjectId}
        if session_id:
            scope["sessionId"] = session_id
        constraints = {"deniedOperations": list(dict.fromkeys(denied))}
        reasons = (["fixture-risk"] if any(record["reasons"] for record in records) else []) + markers
        level = "high" if denied else "low"
        # 只记每个评估范围最近事实的摘要和版号，避免标记变化复用同版不同义。
        # 有效期自然刷新不改变事实含义，也不推进版号。
        key = tuple(sorted(scope.items()))
        meaning = fingerprint({"level": level, "constraints": constraints, "reasons": reasons})
        previous = current["assessments"].get(key)
        if previous and previous["meaning"] != meaning and current["version"] <= previous["version"]:
            current["version"] = previous["version"] + 1
        current["assessments"][key] = {"meaning": meaning, "version": current["version"]}
        return {"scope": scope, "version": current["version"],
                "expiresAt": min((row["expiresAt"] for row in records), default=stamp(30)),
                "level": level, "constraints": constraints, "reasons": reasons}


@router.get("/fixtures/{test_run_id}/requests", response_model=list[RequestRecord], summary="读取脱敏目标请求账本",
            description="记录 started、committed、finished 及固定目标和摘要；不含原始正文、凭据或任意输入。")
def request_ledger(test_run_id: str):
    current = fixture(test_run_id)
    with LOCK:
        return deepcopy(current["requests"])


@router.post("/fixtures/{test_run_id}/faults", response_model=FaultResponse, summary="注入一次性目标故障",
             description="按真实操作名匹配下一次调用；延迟、可释放阻塞或已提交后响应超时，最长 30 秒。")
def create_fault(test_run_id: str, body: FaultInput):
    current = fixture(test_run_id)
    fault = {**body.model_dump(), "faultId": "fault_" + secrets.token_hex(16), "released": False, "consumed": False}
    with LOCK:
        current["faults"].append(fault)
    return fault


@router.post("/fixtures/{test_run_id}/faults/{fault_id}/release", response_model=FaultResponse, summary="释放已阻塞调用",
             description="只更新本 fixture 中的故障；释放后原请求继续，不重发业务调用。")
def release_fault(test_run_id: str, fault_id: str):
    current = fixture(test_run_id)
    with LOCK:
        for fault in current["faults"]:
            if fault["faultId"] == fault_id:
                fault["released"] = True
                return fault
    raise HTTPException(404, "未找到对应故障。")


async def control_context(request: Request, call_next):
    """测试 Header 仅选择隔离状态，不提供或替代授权证明。"""
    test_run_id = request.headers.get("x-test-run-id")
    if not test_run_id:
        return await call_next(request)
    try:
        enabled()
        current = fixture(test_run_id)
    except HTTPException as error:
        return JSONResponse({"detail": error.detail}, status_code=error.status_code)
    subject = request.headers.get("x-control-subject-id")
    if subject not in (None, "subject-a", "subject-b"):
        return JSONResponse({"detail": "测试主体标识无效。"}, status_code=422)
    tokens = (CURRENT_FIXTURE.set(current), CURRENT_SUBJECT.set(subject), BUSINESS_STATE.set(current["business"]))
    try:
        return await call_next(request)
    finally:
        CURRENT_FIXTURE.reset(tokens[0])
        CURRENT_SUBJECT.reset(tokens[1])
        BUSINESS_STATE.reset(tokens[2])


async def observed_call(operation: str, target: str, arguments: Any, callback):
    """在真实处理器前后记录；故障不替换处理器结果或假造提交。"""
    current = CURRENT_FIXTURE.get()
    if current is None:
        return callback()
    record = {"requestId": "request_" + secrets.token_hex(16), "subjectId": CURRENT_SUBJECT.get(),
              "operation": operation, "target": target, "argumentsHash": fingerprint(arguments),
              "phase": "started", "startedAt": stamp()}
    if operation == "save_persistence_result" and isinstance(arguments, dict):
        try:
            body = base64.b64decode(arguments.get("fileContentBase64", ""), validate=True)
            record.update(reportBodyHash=fingerprint(body), reportMarkers=detected_markers(arguments))
        except (ValueError, binascii.Error):
            pass
    with LOCK:
        current["requests"].append(record)
        fault = next((item for item in current["faults"] if item["operation"] == operation and not item["consumed"]), None)
        if fault:
            fault["consumed"] = True
    try:
        if fault and fault["mode"] == "delay":
            await asyncio.sleep(fault["seconds"])
        if fault and fault["mode"] == "block":
            loop = asyncio.get_running_loop()
            deadline = loop.time() + fault["seconds"]
            while not fault["released"]:
                if loop.time() >= deadline:
                    raise MockError(504, "模拟调用阻塞超时，未提交。")
                await asyncio.sleep(0.01)
        result = callback()
        with LOCK:
            record.update(phase="committed", committedAt=stamp())
        if fault and fault["mode"] == "committed-timeout":
            await asyncio.sleep(fault["seconds"])
            raise MockError(504, "模拟业务已提交，响应超时；请查询状态，禁止自动重发。")
        with LOCK:
            record.update(phase="finished", finishedAt=stamp(), outcome="succeeded")
        return result
    except BaseException as error:
        with LOCK:
            record.update(phase="finished", finishedAt=stamp(),
                          outcome="committed-response-unknown" if "committedAt" in record else
                          "cancelled-before-commit" if isinstance(error, asyncio.CancelledError) else "failed-before-commit")
        raise
