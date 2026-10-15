from typing import Annotated

from fastapi import Depends, FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.config import Settings, get_settings
from app.llm import LOCAL_MODEL, generate_scenario
from app.security_operations.router import create_router
from app.security_operations.transport import lifespan, mount_mcp
from app.mock_data import (
    build_alerts,
    build_assets,
    build_events,
    build_incidents,
    build_indicators,
    build_summary,
    build_vulnerabilities,
)
from app.models import (
    Alert,
    Asset,
    DashboardSummary,
    HealthResponse,
    Incident,
    Indicator,
    ScenarioRequest,
    ScenarioResponse,
    SecurityEvent,
    Vulnerability,
)
from app.threat_analysis_mock_data.router import router as threat_analysis_router

CountQuery = Annotated[int, Query(ge=1, le=200, description="返回记录数，范围 1-200。")]
SeedQuery = Annotated[int | None, Query(description="随机种子。传入相同 seed 可得到稳定的模拟数据。")]


tags_metadata = [
    {"name": "系统", "description": "服务健康检查与运行状态。"},
    {"name": "资产", "description": "生成 CMDB、EDR 或漏洞管理中常见的资产样例。"},
    {"name": "告警", "description": "生成正常运维与基础状态的测试告警。"},
    {"name": "事件", "description": "生成基础事件、版本记录、示例指标和常规日志。"},
    {"name": "看板", "description": "生成 SOC 首页或运营大屏常用汇总指标。"},
    {"name": "AI 场景", "description": "本地返回确定性的基本运维场景，无需模型或 API Key。"},
    {"name": "Threat Analysis Mock", "description": "Threat Analysis 外部查询接口 mock 数据。"},
]

app = FastAPI(
    lifespan=lifespan,
    title="网络安全运营模拟数据 API",
    summary="用于 SOC、SIEM、SOAR、EDR、漏洞管理等系统演示和联调的模拟数据服务。",
    description=(
        "本服务提供网络安全运营系统中最常用的数据对象：资产、告警、事件、漏洞、威胁情报、事件单和看板指标。"
        "所有接口仅提供基本模拟数据，不执行外部动作，不调用模型生成内容。"
    ),
    version="0.1.0",
    openapi_tags=tags_metadata,
)
app.include_router(threat_analysis_router)
app.include_router(create_router())
mount_mcp(app)


@app.exception_handler(RequestValidationError)
async def invalid_request(_request: Request, _error: RequestValidationError) -> JSONResponse:
    """验证失败时不把请求值复制到公开响应。"""
    return JSONResponse(status_code=422, content={"detail": "请求参数无效"})


@app.get("/health", tags=["系统"], response_model=HealthResponse, summary="健康检查")
def health(settings: Settings = Depends(get_settings)) -> HealthResponse:
    """用于负载均衡、容器探活或部署检查。"""

    return HealthResponse(status="ok", service=settings.app_name, version=settings.app_version)


@app.get("/api/v1/assets", tags=["资产"], response_model=list[Asset], summary="生成资产列表")
def list_assets(count: CountQuery = 20, seed: SeedQuery = None) -> list[Asset]:
    """返回模拟资产，适合 CMDB、资产画像、风险评分页面联调。"""

    return build_assets(count=count, seed=seed)


@app.get("/api/v1/alerts", tags=["告警"], response_model=list[Alert], summary="生成告警列表")
def list_alerts(count: CountQuery = 20, seed: SeedQuery = None) -> list[Alert]:
    """返回基本测试告警，保留严重性、状态和来源字段。"""

    return build_alerts(count=count, seed=seed)


@app.get("/api/v1/incidents", tags=["事件"], response_model=list[Incident], summary="生成安全事件单")
def list_incidents(count: CountQuery = 10, seed: SeedQuery = None) -> list[Incident]:
    """返回模拟事件单，适合 SOAR、工单流转和事件响应页面联调。"""

    return build_incidents(count=count, seed=seed)


@app.get("/api/v1/vulnerabilities", tags=["事件"], response_model=list[Vulnerability], summary="生成漏洞列表")
def list_vulnerabilities(count: CountQuery = 20, seed: SeedQuery = None) -> list[Vulnerability]:
    """返回基础版本维护记录，不提供漏洞利用细节。"""

    return build_vulnerabilities(count=count, seed=seed)


@app.get("/api/v1/indicators", tags=["事件"], response_model=list[Indicator], summary="生成威胁情报 IOC")
def list_indicators(count: CountQuery = 20, seed: SeedQuery = None) -> list[Indicator]:
    """返回使用保留地址和示例域名的基本测试指标。"""

    return build_indicators(count=count, seed=seed)


@app.get("/api/v1/events", tags=["事件"], response_model=list[SecurityEvent], summary="生成原始安全日志")
def list_events(count: CountQuery = 50, seed: SeedQuery = None) -> list[SecurityEvent]:
    """返回模拟原始日志，可用于日志检索、规则调试和时间线展示。"""

    return build_events(count=count, seed=seed)


@app.get("/api/v1/dashboard/summary", tags=["看板"], response_model=DashboardSummary, summary="生成 SOC 看板汇总")
def dashboard_summary(seed: SeedQuery = None) -> DashboardSummary:
    """返回基本运维看板指标。"""

    return build_summary(seed=seed)


@app.post("/api/v1/ai/scenarios", tags=["AI 场景"], response_model=ScenarioResponse, summary="获取基本运维场景")
async def create_ai_scenario(
    request: ScenarioRequest,
    settings: Settings = Depends(get_settings),
) -> ScenarioResponse:
    """本地返回基本运维场景，请求主题不进入响应。"""

    content = await generate_scenario(settings=settings, topic=request.topic, language=request.language)
    return ScenarioResponse(model=LOCAL_MODEL, content=content)
