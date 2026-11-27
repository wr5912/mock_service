"""供平台 MCP 管理页联调的本地主机接口。"""

from typing import Annotated, Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Request, Security
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict, Field


HostId = Annotated[str, Field(min_length=1)]
FirewallRule = Annotated[dict[str, str], Field(min_length=1)]


class HostRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    hostIp: str | None = Field(default=None, description="可选的目标主机地址。", examples=["192.0.2.10"])


class HostCommandRequest(HostRequest):
    commandId: str = Field(min_length=1, description="指令标识，按字符串传递。", examples=["mock-command-01"])
    delay: int | None = Field(default=None, description="可选的延迟秒数。", examples=[0])
    hostIds: list[HostId] = Field(min_length=1, description="目标主机标识数组。", examples=[["test-host-01"]])
    params: dict[str, Any] = Field(description="指令参数对象，可传空对象。", examples=[{}])


class HostPolicyRequest(HostRequest):
    hostId: HostId = Field(description="目标主机标识，保留前导零。", examples=["test-host-01"])
    devicePolicy: dict[str, str] = Field(description="外设设置与字符串取值的映射，可传空对象。", examples=[{"usbstor": "3"}])
    loginPolicy: dict[str, str] = Field(description="登录设置与字符串取值的映射，可传空对象。", examples=[{}])
    fwPolicy: list[FirewallRule] = Field(description="网络规则对象数组，规则值为字符串，可传空数组。", examples=[[]])


class HostReceipt(BaseModel):
    code: Literal[200] = 200
    accepted: Literal[True] = True
    simulated: Literal[True] = True
    sideEffect: Literal[False] = False
    message: str = "模拟请求已受理。"


class ErrorResponse(BaseModel):
    detail: str


authorization_header = APIKeyHeader(
    name="Authorization", auto_error=False, description="本地模拟仅检查 Authorization 请求头是否存在。",
)


def require_authorization(authorization: Annotated[str | None, Security(authorization_header)]) -> None:
    if not authorization or not authorization.strip():
        raise HTTPException(status_code=401, detail="缺少 Authorization 请求头。")


host_api = FastAPI(
    title="主机管理模拟 API",
    description="用于 MCP 管理页联调。主机指令和策略仅返回固定的模拟受理回执。",
    version="0.1.0",
    openapi_url="/v2/api-docs",
    docs_url=None,
    redoc_url=None,
    servers=[{"url": "/app"}],
    root_path_in_servers=False,
    dependencies=[Depends(require_authorization)],
    responses={
        401: {"model": ErrorResponse, "description": "缺少 Authorization 请求头"},
        422: {"model": ErrorResponse, "description": "请求参数无效"},
    },
)


@host_api.exception_handler(RequestValidationError)
async def invalid_request(_request: Request, _error: RequestValidationError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"detail": "请求参数无效。"})


@host_api.post("/ai/sendHmCmd", operation_id="sendHmCmdUsingPOST", summary="模拟提交主机指令")
def send_host_command(_command: HostCommandRequest) -> HostReceipt:
    """接收指令标识、目标和参数，返回固定的模拟受理回执。"""
    return HostReceipt()


@host_api.post("/ai/sendHmPolicy", operation_id="sendHmPolicyUsingPOST", summary="模拟提交主机策略")
def send_host_policy(_policy: HostPolicyRequest) -> HostReceipt:
    """接收主机标识和三个控制分支，返回固定的模拟受理回执。"""
    return HostReceipt()


app = FastAPI(openapi_url=None)
app.mount("/app", host_api)


@app.get("/health", include_in_schema=False)
def health() -> dict[str, str | bool]:
    return {"status": "ok", "service": "host", "simulated": True}
