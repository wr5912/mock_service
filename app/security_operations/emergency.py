"""单目标应急草案的基础状态模拟，不执行设备动作。"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address
import re

from jsonschema import Draft202012Validator

from .catalog import EMERGENCY_CONFIRMATION_SCHEMA
from .confirmation import validate_proof
from .state import MockError, STATE, asset, digest, identifier, lookup, remember, replay, validate_identifier


ACTIONS = {
    "host-isolate": "隔离测试主机", "host-unisolate": "解除测试主机隔离",
    "host-block-ip": "添加测试访问限制", "host-unblock-ip": "移除测试访问限制",
    "host-block-ip-port": "添加测试端口访问限制", "host-unblock-ip-port": "移除测试端口访问限制",
    "account-disable": "停用测试账号", "account-enable": "启用测试账号",
    "host-restart": "模拟重启测试主机",
}


def action_for(body, previous=None):
    key = body.get("action_key")
    text = body["intent"]
    if not key:
        if "解除隔离" in text or "取消隔离" in text:
            key = "host-unisolate"
        elif "隔离" in text:
            key = "host-isolate"
        elif "解除封禁" in text or "取消封禁" in text:
            key = "host-unblock-ip-port" if body.get("params", {}).get("port") else "host-unblock-ip"
        elif "封禁" in text:
            key = "host-block-ip-port" if body.get("params", {}).get("port") else "host-block-ip"
        elif "停用" in text or "禁用" in text:
            key = "account-disable"
        elif "启用" in text:
            key = "account-enable"
        elif "重启" in text:
            key = "host-restart"
        else:
            key = previous
    if key not in ACTIONS:
        raise MockError(422, "该意图不属于当前基础模拟动作")
    return key


def snapshot(body, previous=None):
    old = previous or {}
    target = asset(body.get("target_hint", old.get("target", {}).get("assetId", "")))
    key = action_for(body, old.get("action_key"))
    params = body.get("params", {})
    safe_params = {}
    if key.startswith("host-block-ip") or key.startswith("host-unblock-ip"):
        try:
            safe_params["src_ip"] = str(IPv4Address(params.get("src_ip", "")))
        except ValueError:
            raise MockError(422, "该模拟动作需要有效的源 IPv4 地址") from None
        if key.endswith("-port"):
            port = params.get("port")
            if isinstance(port, bool) or not re.fullmatch(r"[0-9]{1,5}", str(port)) or not 1 <= int(port) <= 65535:
                raise MockError(422, "该模拟动作需要有效端口")
            safe_params["port"] = str(int(port))
    if key.startswith("account-"):
        user = params.get("user", "")
        if not isinstance(user, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", user):
            raise MockError(422, "该模拟动作需要基础测试账号")
        safe_params["user"] = user
    return {"action_key": key, "action_name": ACTIONS[key], "intent": ACTIONS[key],
            "target": target, "target_name": target["name"], "target_hint": target["ip"], "params": safe_params,
            "simulated": True, "commands": []}


def freeze(operation, frozen):
    operation.update(snapshot=frozen, snapshot_digest=digest(frozen), phase="READY",
                     required_next_action="CONFIRM", execution_status="NOT_SUBMITTED",
                     approval_status="NOT_REQUESTED", simulated=True,
                     expires_at=(datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat(),
                     readiness={"ready": True, "missing_capabilities": []})


def invoke_emergency(name, args, base_url):
    if name == "list_emergency_actions":
        if args.get("cursor"):
            raise MockError(422, "基础模拟目录没有后续分页")
        return {"items": deepcopy(list(STATE["emergency"].values()))[:args.get("limit", 20)], "next_cursor": None}
    if name == "prepare_emergency_action":
        body = args["body"]
        previous = replay("emergency.prepare", body["request_id"], body)
        if previous is not None:
            return previous
        operation = {"operation_id": identifier("op_"), "version": 1}
        freeze(operation, snapshot(body))
        STATE["emergency"][operation["operation_id"]] = operation
        return remember("emergency.prepare", body["request_id"], body, operation)
    operation = lookup("emergency", args["operationId"])
    if name in {"get_emergency_action", "get_emergency_action_result"}:
        return deepcopy(operation)
    body = args["body"]
    family = "emergency." + name
    request = {"operationId": args["operationId"], **body}
    previous = replay(family, body["request_id"], request)
    if previous is not None:
        return previous
    if operation["phase"] != "READY" or body["expected_version"] != operation["version"]:
        raise MockError(409, "模拟操作状态或版本不允许此变更")
    if name == "revise_emergency_action":
        frozen = snapshot(body, operation["snapshot"])
        operation["version"] += 1
        freeze(operation, frozen)
    elif name == "cancel_emergency_action":
        operation.update(phase="CANCELLED", required_next_action="NONE", execution_status="CANCELLED")
    else:
        raise MockError(404, "未找到对应模拟工具")
    return remember(family, body["request_id"], request, operation)


def confirm_emergency(operation_id, body):
    validate_identifier(operation_id)
    operation = lookup("emergency", operation_id)
    if not Draft202012Validator(EMERGENCY_CONFIRMATION_SCHEMA).is_valid(body):
        raise MockError(422, "模拟确认参数不符合输入合同")
    request = {"operationId": operation_id, **body}
    previous = replay("emergency.confirm", body["request_id"], request)
    if previous is not None:
        return previous
    if (operation["phase"] != "READY" or body["expected_version"] != operation["version"]
            or body["snapshot_digest"] != operation["snapshot_digest"]
            or datetime.fromisoformat(operation["expires_at"]) <= datetime.now(timezone.utc)):
        raise MockError(409, "确认未绑定当前有效模拟草案")
    validate_proof(body.get("proof", body.get("confirmation_event_ref")), operation,
                   "snapshot_digest", "emergency.execute", legacy="proof" not in body)
    operation.update(phase="TERMINAL", required_next_action="NONE", approval_status="APPROVED",
                     execution_status="SUCCEEDED", soc_execution_id=identifier("mock_execution_"),
                     soc_observation={"evidence": {"status": "SUCCESS", "simulated": True}},
                     confirmation_proof_verified=False)
    return remember("emergency.confirm", body["request_id"], request, operation)


def emergency_result(operation_id):
    validate_identifier(operation_id)
    return deepcopy(lookup("emergency", operation_id))
