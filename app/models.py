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
    title: str = Field(examples=["疑似横向移动行为"])
    severity: Severity
    status: Status
    source: Literal["SIEM", "EDR", "NDR", "WAF", "Cloud"]
    asset_id: str = Field(examples=["asset-0001"])
    tactic: str = Field(examples=["Lateral Movement"])
    technique: str = Field(examples=["T1021 Remote Services"])
    event_time: datetime
    description: str


class Incident(BaseModel):
    incident_id: str = Field(examples=["inc-0001"])
    title: str = Field(examples=["生产服务器疑似被植入 WebShell"])
    severity: Severity
    status: Status
    assignee: str = Field(examples=["analyst01"])
    related_alerts: list[str] = Field(examples=[["alert-0001", "alert-0003"]])
    affected_assets: list[str] = Field(examples=[["asset-0001"]])
    created_at: datetime
    summary: str


class Vulnerability(BaseModel):
    cve_id: str = Field(examples=["CVE-2025-12345"])
    asset_id: str = Field(examples=["asset-0002"])
    severity: Severity
    cvss: float = Field(ge=0, le=10, examples=[9.8])
    package: str = Field(examples=["openssl"])
    fixed_version: str | None = Field(examples=["3.0.13"])
    exposed: bool
    description: str


class Indicator(BaseModel):
    indicator_id: str = Field(examples=["ioc-0001"])
    type: Literal["ip", "domain", "url", "hash", "email"]
    value: str = Field(examples=["203.0.113.42"])
    threat_type: Literal["malware", "phishing", "c2", "scanner", "ransomware"]
    confidence: int = Field(ge=0, le=100, examples=[91])
    first_seen: datetime
    last_seen: datetime


class SecurityEvent(BaseModel):
    event_id: str = Field(examples=["evt-0001"])
    event_time: datetime
    source: Literal["auth", "network", "endpoint", "cloud", "application"]
    asset_id: str = Field(examples=["asset-0001"])
    username: str = Field(examples=["svc_backup"])
    action: str = Field(examples=["login_failed"])
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
        examples=["勒索软件告警调查"],
        description="希望生成的安全运营演练主题。",
    )
    language: Literal["zh", "en"] = Field(default="zh", description="返回语言。")


class ScenarioResponse(BaseModel):
    model: str = Field(examples=["deepseek-chat"])
    content: str = Field(examples=["演练目标：验证 SOC 对勒索软件早期行为的识别与处置能力..."])
