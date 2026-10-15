from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


Severity = Literal["critical", "high", "medium", "low", "info"]
Status = Literal["new", "triaged", "investigating", "contained", "closed"]


class HealthResponse(BaseModel):
    status: str = Field(examples=["ok"])
    service: str = Field(examples=["网络安全运营模拟数据 API"])
    version: str = Field(examples=["0.1.0"])


class Asset(BaseModel):
    asset_id: str = Field(examples=["asset-0001"])
    hostname: str = Field(examples=["edr-gateway-01"])
    ip: str = Field(examples=["10.24.8.15"])
    owner: str = Field(examples=["安全运营中心"])
    business_unit: str = Field(examples=["生产网"])
    asset_type: Literal["server", "workstation", "firewall", "database", "kubernetes"]
    risk_score: int = Field(ge=0, le=100, examples=[82])
    tags: list[str] = Field(examples=[["internet-facing", "linux"]])


class Alert(BaseModel):
    alert_id: str = Field(examples=["alert-0001"])
    title: str = Field(examples=["资产状态更新"])
    severity: Severity
    status: Status
    source: Literal["SIEM", "EDR", "NDR", "WAF", "Cloud"]
    asset_id: str = Field(examples=["asset-0001"])
    tactic: str = Field(examples=[""], description="兼容字段，基本模拟数据留空。")
    technique: str = Field(examples=[""], description="兼容字段，基本模拟数据留空。")
    event_time: datetime
    description: str


class Incident(BaseModel):
    incident_id: str = Field(examples=["inc-0001"])
    title: str = Field(examples=["演示资产信息核对"])
    severity: Severity
    status: Status
    assignee: str = Field(examples=["analyst01"])
    related_alerts: list[str] = Field(examples=[["alert-0001", "alert-0003"]])
    affected_assets: list[str] = Field(examples=[["asset-0001"]])
    created_at: datetime
    summary: str


class Vulnerability(BaseModel):
    cve_id: str = Field(examples=["MOCK-ISSUE-0001"], description="模拟组件状态编号，不对应真实安全问题。")
    asset_id: str = Field(examples=["asset-0002"])
    severity: Severity
    cvss: float = Field(ge=0, le=10, examples=[0.0])
    package: str = Field(examples=["demo-service"])
    fixed_version: str | None = Field(examples=["3.0.13"])
    exposed: bool
    description: str


class Indicator(BaseModel):
    indicator_id: str = Field(examples=["ioc-0001"])
    type: Literal["ip", "domain", "url", "hash", "email"]
    value: str = Field(examples=["203.0.113.42"])
    threat_type: Literal["none"]
    confidence: int = Field(ge=0, le=100, examples=[91])
    first_seen: datetime
    last_seen: datetime


class SecurityEvent(BaseModel):
    event_id: str = Field(examples=["evt-0001"])
    event_time: datetime
    source: Literal["auth", "network", "endpoint", "cloud", "application"]
    asset_id: str = Field(examples=["asset-0001"])
    username: str = Field(examples=["svc_backup"])
    action: str = Field(examples=["login_success"])
    src_ip: str = Field(examples=["198.51.100.23"])
    dst_ip: str = Field(examples=["10.24.8.15"])
    outcome: Literal["success", "failure", "blocked"]
    raw: dict[str, str]


class DashboardSummary(BaseModel):
    alert_count: int
    critical_alert_count: int
    open_incident_count: int
    vulnerable_asset_count: int
    top_tactics: list[str]
    generated_at: datetime


class ScenarioRequest(BaseModel):
    topic: str = Field(
        min_length=2,
        max_length=80,
        examples=["基础资产状态"],
        description="兼容主题参数，不回显，不用于生成内容。",
    )
    language: Literal["zh", "en"] = Field(default="zh", description="返回语言。")


class ScenarioResponse(BaseModel):
    model: str = Field(examples=["local-basic-mock"])
    content: str = Field(examples=["核对演示资产信息并确认示例服务可用。"])


ThreatIntelligenceType = Literal["ioc", "actor_profile", "campaign", "vulnerability", "malware", "situational"]
IndicatorType = Literal["ip", "domain", "url", "hash", "email", "cve"]


class ThreatIntelligenceRequest(BaseModel):
    topic: str = Field(
        min_length=2,
        max_length=120,
        examples=["基础资产状态"],
        description="兼容主题参数，不回显，不用于生成内容。",
    )
    intelligence_type: ThreatIntelligenceType = Field(
        default="situational",
        description="兼容分类参数，响应统一返回基本运营状态简报。",
    )
    language: Literal["zh", "en"] = Field(default="zh", description="返回语言。")
    include_iocs: bool = Field(default=True, description="是否在返回内容中包含模拟 IOC。")


class ThreatIntelligenceIndicator(BaseModel):
    type: IndicatorType = Field(description="IOC 类型。", examples=["domain"])
    value: str = Field(description="模拟 IOC 值。", examples=["update-check.example"])
    threat_type: str = Field(description="基本模拟值固定为 none。", examples=["none"])
    confidence: int = Field(ge=0, le=100, description="IOC 可信度，范围 0-100。", examples=[82])
    description: str = Field(description="基本地址的模拟说明。", examples=["演示服务地址。"])


class ThreatIntelligenceResponse(BaseModel):
    model: str = Field(description="本地模拟实现标识。", examples=["local-basic-mock"])
    topic: str = Field(description="固定的基本状态主题。", examples=["基础资产状态"])
    intelligence_type: ThreatIntelligenceType = Field(description="威胁情报类型。")
    generated_at: datetime = Field(description="生成时间。")
    title: str = Field(description="基本运营状态标题。", examples=["基础运营状态简报"])
    summary: str = Field(description="威胁情报摘要。")
    severity: Severity = Field(description="基本记录级别。", examples=["info"])
    confidence: int = Field(ge=0, le=100, description="整体情报可信度，范围 0-100。", examples=[78])
    threat_actor: str | None = Field(default=None, description="兼容字段，基本模拟数据固定为 null。")
    ttps: list[str] = Field(default_factory=list, description="兼容字段，基本模拟数据固定为空列表。")
    indicators: list[ThreatIntelligenceIndicator] = Field(default_factory=list, description="模拟 IOC 列表。")
    recommendations: list[str] = Field(default_factory=list, description="处置和检测建议。")
    raw_content: str = Field(description="兼容字段，基本模拟数据固定为空字符串。")
