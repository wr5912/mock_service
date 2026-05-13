from datetime import datetime, timedelta, timezone
from random import Random

from app.models import Alert, Asset, DashboardSummary, Incident, Indicator, SecurityEvent, Vulnerability


ASSET_NAMES = ["edr-gateway", "prod-web", "db-core", "waf-edge", "k8s-node", "jumpbox", "vpn"]
OWNERS = ["安全运营中心", "基础架构组", "应用平台组", "数据平台组"]
BUSINESS_UNITS = ["生产网", "办公网", "云上业务", "DMZ"]
SEVERITIES = ["critical", "high", "medium", "low", "info"]
STATUSES = ["new", "triaged", "investigating", "contained", "closed"]
TACTICS = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Lateral Movement", "Exfiltration"]
TECHNIQUES = ["T1059 Command and Scripting Interpreter", "T1021 Remote Services", "T1190 Exploit Public-Facing Application", "T1078 Valid Accounts"]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _base_time(seed: int | None) -> datetime:
    if seed is None:
        return _now()
    return datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(days=seed % 365)


def build_assets(count: int, seed: int | None = None) -> list[Asset]:
    rnd = Random(seed)
    assets: list[Asset] = []
    for index in range(1, count + 1):
        name = rnd.choice(ASSET_NAMES)
        assets.append(
            Asset(
                asset_id=f"asset-{index:04d}",
                hostname=f"{name}-{index:02d}",
                ip=f"10.{rnd.randint(1, 254)}.{rnd.randint(1, 254)}.{rnd.randint(1, 254)}",
                owner=rnd.choice(OWNERS),
                business_unit=rnd.choice(BUSINESS_UNITS),
                asset_type=rnd.choice(["server", "workstation", "firewall", "database", "kubernetes"]),
                risk_score=rnd.randint(1, 100),
                tags=rnd.sample(["linux", "windows", "internet-facing", "critical", "pci", "vpn"], k=2),
            )
        )
    return assets


def build_alerts(count: int, seed: int | None = None) -> list[Alert]:
    rnd = Random(seed)
    alerts: list[Alert] = []
    base_time = _base_time(seed)
    titles = ["疑似暴力破解", "异常 PowerShell 执行", "疑似横向移动行为", "高危漏洞利用尝试", "异常出站连接"]
    sources = ["SIEM", "EDR", "NDR", "WAF", "Cloud"]
    for index in range(1, count + 1):
        tactic = rnd.choice(TACTICS)
        technique = rnd.choice(TECHNIQUES)
        alerts.append(
            Alert(
                alert_id=f"alert-{index:04d}",
                title=rnd.choice(titles),
                severity=rnd.choice(SEVERITIES),
                status=rnd.choice(STATUSES),
                source=rnd.choice(sources),
                asset_id=f"asset-{rnd.randint(1, max(count, 3)):04d}",
                tactic=tactic,
                technique=technique,
                event_time=base_time - timedelta(minutes=rnd.randint(1, 1440)),
                description=f"检测到 {tactic} 相关行为，匹配技术 {technique}，建议分析进程、账号与网络连接上下文。",
            )
        )
    return alerts


def build_incidents(count: int, seed: int | None = None) -> list[Incident]:
    rnd = Random(seed)
    incidents: list[Incident] = []
    base_time = _base_time(seed)
    titles = ["生产服务器疑似被植入 WebShell", "VPN 账号异常登录", "终端疑似感染恶意软件", "数据库异常导出"]
    for index in range(1, count + 1):
        alerts = [f"alert-{rnd.randint(1, max(count * 2, 3)):04d}" for _ in range(rnd.randint(1, 3))]
        assets = [f"asset-{rnd.randint(1, max(count, 3)):04d}" for _ in range(rnd.randint(1, 2))]
        incidents.append(
            Incident(
                incident_id=f"inc-{index:04d}",
                title=rnd.choice(titles),
                severity=rnd.choice(SEVERITIES[:4]),
                status=rnd.choice(STATUSES),
                assignee=f"analyst{rnd.randint(1, 6):02d}",
                related_alerts=alerts,
                affected_assets=assets,
                created_at=base_time - timedelta(hours=rnd.randint(1, 240)),
                summary="该事件由多条告警聚合生成，需要确认影响范围、初始入口、持久化痕迹和处置闭环。",
            )
        )
    return incidents


def build_vulnerabilities(count: int, seed: int | None = None) -> list[Vulnerability]:
    rnd = Random(seed)
    packages = ["openssl", "nginx", "spring-core", "log4j-core", "linux-kernel", "tomcat"]
    vulns: list[Vulnerability] = []
    for index in range(1, count + 1):
        package = rnd.choice(packages)
        cvss = round(rnd.uniform(3.1, 10.0), 1)
        vulns.append(
            Vulnerability(
                cve_id=f"CVE-2025-{10000 + index}",
                asset_id=f"asset-{rnd.randint(1, max(count, 3)):04d}",
                severity="critical" if cvss >= 9 else "high" if cvss >= 7 else "medium",
                cvss=cvss,
                package=package,
                fixed_version=f"{rnd.randint(1, 5)}.{rnd.randint(0, 20)}.{rnd.randint(1, 30)}",
                exposed=rnd.choice([True, False]),
                description=f"{package} 存在可被利用的安全缺陷，建议按暴露面和资产重要性排序修复。",
            )
        )
    return vulns


def build_indicators(count: int, seed: int | None = None) -> list[Indicator]:
    rnd = Random(seed)
    indicators: list[Indicator] = []
    base_time = _base_time(seed)
    for index in range(1, count + 1):
        indicator_type = rnd.choice(["ip", "domain", "url", "hash", "email"])
        value = _indicator_value(indicator_type, rnd, index)
        first_seen = base_time - timedelta(days=rnd.randint(2, 90))
        indicators.append(
            Indicator(
                indicator_id=f"ioc-{index:04d}",
                type=indicator_type,
                value=value,
                threat_type=rnd.choice(["malware", "phishing", "c2", "scanner", "ransomware"]),
                confidence=rnd.randint(50, 99),
                first_seen=first_seen,
                last_seen=first_seen + timedelta(days=rnd.randint(1, 20)),
            )
        )
    return indicators


def _indicator_value(indicator_type: str, rnd: Random, index: int) -> str:
    if indicator_type == "ip":
        return f"203.0.113.{rnd.randint(1, 254)}"
    if indicator_type == "domain":
        return f"malicious-{index}.example.net"
    if indicator_type == "url":
        return f"https://drop-{index}.example.net/update.bin"
    if indicator_type == "email":
        return f"invoice-{index}@example.net"
    return f"{index:064x}"[-64:]


def build_events(count: int, seed: int | None = None) -> list[SecurityEvent]:
    rnd = Random(seed)
    actions = ["login_success", "login_failed", "process_start", "dns_query", "file_write", "connection_blocked"]
    events: list[SecurityEvent] = []
    base_time = _base_time(seed)
    for index in range(1, count + 1):
        action = rnd.choice(actions)
        events.append(
            SecurityEvent(
                event_id=f"evt-{index:04d}",
                event_time=base_time - timedelta(seconds=rnd.randint(1, 86400)),
                source=rnd.choice(["auth", "network", "endpoint", "cloud", "application"]),
                asset_id=f"asset-{rnd.randint(1, max(count, 3)):04d}",
                username=rnd.choice(["admin", "svc_backup", "ops_user", "db_reader", "unknown"]),
                action=action,
                src_ip=f"198.51.100.{rnd.randint(1, 254)}",
                dst_ip=f"10.{rnd.randint(1, 254)}.{rnd.randint(1, 254)}.{rnd.randint(1, 254)}",
                outcome=rnd.choice(["success", "failure", "blocked"]),
                raw={"action": action, "sensor": f"sensor-{rnd.randint(1, 5)}"},
            )
        )
    return events


def build_summary(seed: int | None = None) -> DashboardSummary:
    alerts = build_alerts(50, seed)
    incidents = build_incidents(12, seed)
    vulnerabilities = build_vulnerabilities(20, seed)
    return DashboardSummary(
        alert_count=len(alerts),
        critical_alert_count=sum(1 for alert in alerts if alert.severity == "critical"),
        open_incident_count=sum(1 for incident in incidents if incident.status != "closed"),
        vulnerable_asset_count=len({vuln.asset_id for vuln in vulnerabilities}),
        top_tactics=TACTICS[:5],
        generated_at=_base_time(seed),
    )
