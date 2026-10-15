"""在现有 FastAPI 进程中装载分组 MCP 服务。"""

import json
from contextlib import AsyncExitStack, asynccontextmanager

from fastapi import FastAPI
from mcp.server import Server, ServerRequestContext
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.exceptions import MCPError
import mcp.types as types
from pydantic import ValidationError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.security_operations.catalog import TOOL_GROUPS
from app.security_operations.handlers import invoke
from app.security_operations.state import MockError


async def _protocol_errors(ctx, call_next):
    try:
        return await call_next(ctx)
    except ValidationError:
        raise MCPError(-32602, "MCP 请求参数无效。") from None
    except MCPError as error:
        raise MCPError(error.code, "MCP 请求未被接受。") from None


async def _http_errors(request, call_next):
    response = await call_next(request)
    if response.status_code >= 400:
        # SDK 的顶层校验错误含 input_value；Mock 仅返回简短协议错误。
        return JSONResponse(
            {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "MCP 请求未被接受。"}},
            status_code=response.status_code,
        )
    return response


def _server(group: str) -> Server:
    catalog = {tool["name"]: tool for tool in TOOL_GROUPS[group]}

    async def list_tools(
        ctx: ServerRequestContext, params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        return types.ListToolsResult(tools=[types.Tool(**tool) for tool in catalog.values()])

    async def call_tool(
        ctx: ServerRequestContext, params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        try:
            if params.name not in catalog:
                raise MockError(404, "未找到模拟工具。")
            request = ctx.request
            base_url = f"{request.url.scheme}://{request.url.netloc}"
            payload = invoke(group, params.name, params.arguments or {}, base_url)
            failed = False
        except MockError as error:
            payload = {"code": error.status_code, "message": error.message}
            failed = True
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=json.dumps(payload, ensure_ascii=False))],
            structuredContent=payload,
            isError=failed,
        )

    async def list_resources(
        ctx: ServerRequestContext, params: types.PaginatedRequestParams | None
    ) -> types.ListResourcesResult:
        return types.ListResourcesResult(resources=[])

    async def list_resource_templates(
        ctx: ServerRequestContext, params: types.PaginatedRequestParams | None
    ) -> types.ListResourceTemplatesResult:
        return types.ListResourceTemplatesResult(resourceTemplates=[])

    server = Server(
        group,
        version="0.1.0",
        on_list_tools=list_tools,
        on_call_tool=call_tool,
        on_list_resources=list_resources,
        on_list_resource_templates=list_resource_templates,
        get_tool_input_schema=lambda name: catalog.get(name, {}).get("inputSchema"),
    )
    server.middleware.append(_protocol_errors)
    return server


def mount_mcp(app: FastAPI) -> None:
    """每个业务组使用一个端点；客户端地址保留结尾的斜杠。"""

    servers = [_server(group) for group in TOOL_GROUPS]
    app.state.security_operations_mcp = servers
    for group, server in zip(TOOL_GROUPS, servers):
        mcp_app = server.streamable_http_app(
            streamable_http_path="/",
            stateless_http=True,
            json_response=True,
            # 与现有 Mock API 共用本地联调网络，允许隔离容器通过主机地址访问。
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        )
        mcp_app.add_middleware(BaseHTTPMiddleware, dispatch=_http_errors)
        app.mount(f"/mcp/{group}", mcp_app)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """挂载子应用时，由主应用启动与释放每个 SDK session manager。"""

    async with AsyncExitStack() as stack:
        for server in app.state.security_operations_mcp:
            await stack.enter_async_context(server.session_manager.run())
        yield
