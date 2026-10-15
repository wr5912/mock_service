"""SOC 调用兼容接口、应急回执与基础报告下载。"""

from typing import Any

from fastapi import APIRouter, Request
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from app.security_operations.catalog import EMERGENCY_CONFIRMATION_SCHEMA, POLICY_CONFIRMATION_SCHEMA, POLICY_DECISION_SCHEMA, POLICY_ENDPOINT_SELECTION, SOC_TOOLS, TOOL_INPUT_SCHEMAS
from app.security_operations.handlers import (
    confirm_emergency,
    emergency_result,
    decide_policy,
    invoke,
    invoke_soc,
    report_html,
    validate,
)
from app.security_operations.state import MockError


class GatewayBusinessResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    code: int = Field(description="模拟业务结果码；成功为 200。")
    data: Any = Field(description="当前 SOC 工具对应的基础模拟结果。")


class GatewayResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    status: str = Field(description="Gateway 调用状态；成功为 success。")
    status_code: int = Field(description="模拟上游 HTTP 状态码。")
    result: GatewayBusinessResponse


class BusinessResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    code: str = Field(description="成功为字符串 200；这里只提供基础模拟状态。")
    data: dict[str, Any] = Field(description="当前绑定的模拟草案、端点候选或操作结果，不代表真实设备执行。")


async def _body(request: Request) -> dict[str, Any]:
    try:
        value = await request.json()
    except (ValueError, UnicodeDecodeError):
        raise MockError(422, "请求体必须是 JSON 对象。") from None
    if not isinstance(value, dict):
        raise MockError(422, "请求体必须是 JSON 对象。")
    return value


def _error(error: MockError) -> JSONResponse:
    return JSONResponse({"detail": error.message}, status_code=error.status_code)


def _request_schema(schema):
    return {"requestBody": {"required": True, "content": {"application/json": {"schema": schema}}}}


def _soc_endpoint(resource_id: str, tool_name: str):
    async def endpoint(request: Request):
        try:
            body = await _body(request)
            arguments = body.get("arguments")
            if not isinstance(arguments, dict):
                raise MockError(422, "arguments 必须是 JSON 对象。")
            base_url = f"{request.url.scheme}://{request.url.netloc}"
            return invoke_soc(resource_id, tool_name, arguments, base_url)
        except MockError as error:
            return _error(error)

    return endpoint


def create_router() -> APIRouter:
    router = APIRouter()
    for tool_name, tool in SOC_TOOLS.items():
        router.add_api_route(
            f"/api/v1/mcp-resources/{tool['resource_id']}/tools/{tool_name}/invoke",
            _soc_endpoint(tool["resource_id"], tool_name),
            methods=["POST"],
            response_model=GatewayResponse,
            operation_id=tool_name,
            summary=f"基础 SOC 模拟调用：{tool_name}",
            description="兼容现有 SOC gateway；仅返回基础模拟数据。OpenAPI 工具参数为 body.arguments。",
            tags=["SOC 兼容接口"],
            openapi_extra={
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {"arguments": tool["inputSchema"]},
                                "required": ["arguments"],
                            }
                        }
                    },
                }
            },
        )

    # 规范只由上面实际注册的 SOC 路由派生；不维护第二份可编辑契约。
    soc_routes = list(router.routes)

    @router.get("/api/v1/security-operations/openapi.json", include_in_schema=False)
    def soc_openapi():
        return get_openapi(
            title="security-operations-expert SOC 模拟接口",
            version="0.1.0",
            description="现有 SOC gateway 调用路径的基础模拟实现。",
            routes=soc_routes,
            servers=[{"url": "/"}],
        )

    @router.post(
        "/api/v1/policy-configurations/endpoint-resolution/selection",
        summary="选择当前冻结的基础模拟端点", tags=["策略模拟"], response_model=BusinessResponse,
        description="复用端点工具的冻结请求、候选摘要及两个端点标识；不创建或执行策略。",
        openapi_extra=_request_schema(POLICY_ENDPOINT_SELECTION),
    )
    async def select_endpoints(request: Request):
        try:
            return invoke("policy-configuration", "choose_ambiguous_policy_endpoints", {"body": await _body(request)}, "")
        except MockError as error:
            return _error(error)

    @router.get(
        "/api/v1/policy-configurations/{operation_id}", summary="读取模拟策略当前状态",
        description="仅返回该操作当前版本与冻结候选；未知操作返回 404。",
        tags=["策略模拟"], response_model=BusinessResponse,
    )
    def policy_status(operation_id: str):
        try:
            return invoke("policy-configuration", "get_policy_configuration_status", {"operationId": operation_id}, "")
        except MockError as error:
            return _error(error)

    @router.get(
        "/api/v1/policy-configurations/{operation_id}/result", summary="读取模拟策略结果",
        description="仅返回已经创建的模拟操作结果，不准备或重复执行。",
        tags=["策略模拟"], response_model=BusinessResponse,
    )
    def policy_result(operation_id: str):
        try:
            return invoke("policy-configuration", "get_policy_configuration_result", {"operationId": operation_id}, "")
        except MockError as error:
            return _error(error)

    @router.post(
        "/api/v1/policy-configurations/{operation_id}/candidate-selection",
        summary="选择模拟策略的冻结路径候选", tags=["策略模拟"], response_model=BusinessResponse,
        description="提交当前全部候选的排序及摘要；仅继续当前内存草案。",
        openapi_extra=_request_schema(TOOL_INPUT_SCHEMAS["select_policy_configuration_candidate"]["properties"]["body"]),
    )
    async def select_candidate(operation_id: str, request: Request):
        try:
            return invoke("policy-configuration", "select_policy_configuration_candidate", {"operationId": operation_id, "body": await _body(request)}, "")
        except MockError as error:
            return _error(error)

    @router.post(
        "/api/v1/policy-configurations/{operation_id}/confirmation",
        summary="确认绑定当前版本的模拟策略", tags=["策略模拟"], response_model=BusinessResponse,
        description="校验模拟载荷对象、摘要、版本与时效；不验证生产 RSA 签名或审批身份，不操作真实设备。",
        openapi_extra=_request_schema(POLICY_CONFIRMATION_SCHEMA),
    )
    async def policy_confirmation(operation_id: str, request: Request):
        try:
            body = await _body(request)
            validate(POLICY_CONFIRMATION_SCHEMA, body)
            return invoke("policy-configuration", "confirm_policy_configuration", {"operationId": operation_id, "body": body}, "")
        except MockError as error:
            return _error(error)

    @router.post(
        "/api/v1/policy-configurations/{operation_id}/decisions",
        summary="取消当前模拟策略或请求修改", tags=["策略模拟"], response_model=BusinessResponse,
        description="决定绑定当前草案或候选的摘要及版本，reason 不回显；修改后需重新准备。",
        openapi_extra=_request_schema(POLICY_DECISION_SCHEMA),
    )
    async def policy_decision(operation_id: str, request: Request):
        try:
            return {"code": "200", "data": decide_policy(operation_id, await _body(request))}
        except MockError as error:
            return _error(error)

    @router.post(
        "/api/v1/emergency-actions/{operation_id}/confirmations",
        summary="确认模拟应急操作",
        description="仅确认准备工具已返回的当前草案；operation_id 未找到时返回 404，版本或摘要不一致时返回 409。",
        response_model=BusinessResponse,
        tags=["应急模拟"],
        openapi_extra=_request_schema(EMERGENCY_CONFIRMATION_SCHEMA),
    )
    async def confirm(operation_id: str, request: Request):
        try:
            return {"code": "200", "data": confirm_emergency(operation_id, await _body(request))}
        except MockError as error:
            return _error(error)

    @router.get(
        "/api/v1/emergency-actions/{operation_id}/result",
        summary="查询模拟应急操作结果",
        description="operation_id 使用准备工具返回的标识；未知标识返回 404，结果只包含当前基础模拟状态。",
        response_model=BusinessResponse,
        tags=["应急模拟"],
    )
    def result(operation_id: str):
        try:
            return {"code": "200", "data": emergency_result(operation_id)}
        except MockError as error:
            return _error(error)

    @router.get(
        "/reports/{report_id}.html",
        response_class=HTMLResponse,
        summary="下载基础模拟报告",
        description="report_id 使用模拟服务回执中的标识；未知标识返回 404，正文为固定基础 HTML 样例。",
        tags=["报告模拟"],
    )
    def download_report(report_id: str):
        try:
            return HTMLResponse(report_html(report_id))
        except MockError as error:
            return _error(error)

    return router
