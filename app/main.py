from typing import Annotated

from fastapi import Depends, FastAPI, Query

from app.config import Settings, get_settings
from app.llm import generate_scenario
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

CountQuery = Annotated[int, Query(ge=1, le=200, description="返回记录数，范围 1-200。")]
SeedQuery = Annotated[int | None, Query(description="随机种子。传入相同 seed 可得到稳定的模拟数据。")]


tags_metadata = [
    {"name": "系统", "description": "服务健康检查与运行状态。"},
    {"name": "资产", "description": "生成 CMDB、EDR 或漏洞管理中常见的资产样例。"},
    {"name": "告警", "description": "生成 SIEM、EDR、NDR、WAF 和云安全告警样例。"},
    {"name": "事件", "description": "生成安全事件、漏洞、威胁情报和原始日志样例。"},
    {"name": "看板", "description": "生成 SOC 首页或运营大屏常用汇总指标。"},
    {"name": "AI 场景", "description": "调用 DeepSeek 生成安全运营演练文本；需要配置 DEEPSEEK_API_KEY。"},
]

app = FastAPI(
    title="网络安全运营模拟数据 API",
    summary="用于 SOC、SIEM、SOAR、EDR、漏洞管理等系统演示和联调的模拟数据服务。",
    description=(
        "本服务提供网络安全运营系统中最常用的数据对象：资产、告警、事件、漏洞、威胁情报、事件单和看板指标。"
        "所有模拟数据均为合成数据，不包含真实攻击目标或真实凭据。"
    ),
    version="0.1.0",
    openapi_tags=tags_metadata,
)


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
    """返回模拟安全告警，包含严重性、状态、来源、MITRE ATT&CK 战术和技术。"""

    return build_alerts(count=count, seed=seed)


@app.get("/api/v1/incidents", tags=["事件"], response_model=list[Incident], summary="生成安全事件单")
def list_incidents(count: CountQuery = 10, seed: SeedQuery = None) -> list[Incident]:
    """返回模拟事件单，适合 SOAR、工单流转和事件响应页面联调。"""

    return build_incidents(count=count, seed=seed)


@app.get("/api/v1/vulnerabilities", tags=["事件"], response_model=list[Vulnerability], summary="生成漏洞列表")
def list_vulnerabilities(count: CountQuery = 20, seed: SeedQuery = None) -> list[Vulnerability]:
    """返回模拟漏洞数据，包含 CVE、CVSS、受影响资产、修复版本和暴露面。"""

    return build_vulnerabilities(count=count, seed=seed)


@app.get("/api/v1/indicators", tags=["事件"], response_model=list[Indicator], summary="生成威胁情报 IOC")
def list_indicators(count: CountQuery = 20, seed: SeedQuery = None) -> list[Indicator]:
    """返回模拟 IOC，覆盖 IP、域名、URL、哈希和邮箱。"""

    return build_indicators(count=count, seed=seed)


@app.get("/api/v1/events", tags=["事件"], response_model=list[SecurityEvent], summary="生成原始安全日志")
def list_events(count: CountQuery = 50, seed: SeedQuery = None) -> list[SecurityEvent]:
    """返回模拟原始日志，可用于日志检索、规则调试和时间线展示。"""

    return build_events(count=count, seed=seed)


@app.get("/api/v1/dashboard/summary", tags=["看板"], response_model=DashboardSummary, summary="生成 SOC 看板汇总")
def dashboard_summary(seed: SeedQuery = None) -> DashboardSummary:
    """返回 SOC 首页常用核心指标，包括告警、事件、漏洞资产和高频攻击战术。"""

    return build_summary(seed=seed)


@app.post("/api/v1/ai/scenarios", tags=["AI 场景"], response_model=ScenarioResponse, summary="生成安全运营演练场景")
async def create_ai_scenario(
    request: ScenarioRequest,
    settings: Settings = Depends(get_settings),
) -> ScenarioResponse:
    """调用 DeepSeek 生成演练文本。

    未配置 `DEEPSEEK_API_KEY` 时返回 503，不影响其他模拟数据接口使用。
    """

    content = await generate_scenario(settings=settings, topic=request.topic, language=request.language)
    return ScenarioResponse(model=settings.deepseek_model, content=content)
