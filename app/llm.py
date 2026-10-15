from datetime import datetime, timezone

from app.config import Settings
from app.models import ThreatIntelligenceRequest, ThreatIntelligenceResponse


LOCAL_MODEL = "local-basic-mock"
GENERATED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)


async def generate_scenario(settings: Settings, topic: str, language: str) -> str:
    """保留调用合同，返回本地固定场景，不使用请求主题生成或拼接内容。"""

    if language == "en":
        return (
            "Basic operations example: review the demo asset inventory, confirm a routine login, "
            "and record that the sample service is available. All records are synthetic."
        )
    return "基础运营示例：核对演示资产清单，确认一条常规登录记录，并登记示例服务可用状态。所有记录均为基本模拟数据。"


async def generate_threat_intelligence(
    settings: Settings,
    request: ThreatIntelligenceRequest,
) -> ThreatIntelligenceResponse:
    """兼容原情报入口，只返回基本状态数据，不调用外部模型。"""

    english = request.language == "en"
    indicators = []
    if request.include_iocs:
        indicators = [
            {
                "type": "domain",
                "value": "status.example.com",
                "threat_type": "none",
                "confidence": 100,
                "description": "Demo service address." if english else "演示服务地址。",
            }
        ]
    return ThreatIntelligenceResponse(
        model=LOCAL_MODEL,
        topic="Basic asset status" if english else "基础资产状态",
        intelligence_type="situational",
        generated_at=GENERATED_AT,
        title="Basic operations summary" if english else "基础运营状态简报",
        summary="The demo service is available." if english else "演示服务处于正常可用状态。",
        severity="info",
        confidence=100,
        threat_actor=None,
        ttps=[],
        indicators=indicators,
        recommendations=[],
        raw_content="",
    )
