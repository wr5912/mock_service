"""SOC 调用兼容接口、应急回执与基础报告下载。"""

from typing import Any

from fastapi import APIRouter, Request
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from app.security_operations.catalog import SOC_TOOLS
from app.security_operations.handlers import (
    confirm_emergency,
    emergency_result,
    invoke_soc,
    report_html,
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


class EmergencyResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    operation_id: str = Field(description="准备工具返回的模拟操作标识。")
    version: int = Field(description="当前模拟草案版本。")
    phase: str = Field(description="当前模拟操作阶段。")
    execution_status: str = Field(description="模拟执行状态。")
    simulated: bool = Field(description="始终为 true；不会操作真实设备。")


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
        "/api/v1/emergency-actions/{operation_id}/confirmations",
        summary="确认模拟应急操作",
        description="仅确认准备工具已返回的当前草案；operation_id 未找到时返回 404，版本或摘要不一致时返回 409。",
        response_model=EmergencyResponse,
        tags=["应急模拟"],
        openapi_extra={"requestBody": {"required": True, "content": {"application/json": {"schema": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string", "description": "本次模拟确认的请求标识。"},
                "expected_version": {"type": "integer", "description": "准备结果中的当前版本。"},
                "snapshot_digest": {"type": "string", "description": "准备结果中的当前摘要。"},
                "confirmation_event_ref": {"type": "string", "description": "确认运行时提供的绑定载荷；Mock 不声明生产签名验证。"},
            },
            "required": ["request_id", "expected_version", "snapshot_digest", "confirmation_event_ref"],
        }}}}},
    )
    async def confirm(operation_id: str, request: Request):
        try:
            return confirm_emergency(operation_id, await _body(request))
        except MockError as error:
            return _error(error)

    @router.get(
        "/api/v1/emergency-actions/{operation_id}/result",
        summary="查询模拟应急操作结果",
        description="operation_id 使用准备工具返回的标识；未知标识返回 404，结果只包含当前基础模拟状态。",
        response_model=EmergencyResponse,
        tags=["应急模拟"],
    )
    def result(operation_id: str):
        try:
            return emergency_result(operation_id)
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
