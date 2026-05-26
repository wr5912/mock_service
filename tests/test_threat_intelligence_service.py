from __future__ import annotations

from datetime import datetime, timezone

from app.config import Settings
from app.models import ThreatIntelligenceResponse
from app.threat_intelligence import create_threat_intelligence_app


def settings_without_api_key() -> Settings:
    return Settings(DEEPSEEK_API_KEY=None)


def test_threat_intelligence_requires_api_key(monkeypatch) -> None:
    monkeypatch.setattr("app.threat_intelligence.get_settings", settings_without_api_key)
    client = create_threat_intelligence_app().test_client()

    response = client.post(
        "/generate",
        json={"topic": "近期针对制造业的勒索软件活动", "intelligence_type": "campaign", "language": "zh"},
    )

    assert response.status_code == 503
    assert "DEEPSEEK_API_KEY" in response.get_json()["message"]


def test_threat_intelligence_health() -> None:
    client = create_threat_intelligence_app().test_client()

    response = client.get("/health")

    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"


def test_threat_intelligence_generate_success(monkeypatch) -> None:
    async def fake_generate(settings, request):
        return ThreatIntelligenceResponse(
            model="deepseek-chat",
            topic=request.topic,
            intelligence_type=request.intelligence_type,
            generated_at=datetime.now(timezone.utc),
            title="制造业勒索软件活动模拟简报",
            summary="这是用于联调的模拟威胁情报。",
            severity="high",
            confidence=82,
            threat_actor="Mock-Ransomware-Group",
            ttps=["T1059 Command and Scripting Interpreter"],
            indicators=[
                {
                    "type": "domain",
                    "value": "update-check.example",
                    "threat_type": "c2",
                    "confidence": 80,
                    "description": "模拟 C2 域名。",
                }
            ],
            recommendations=["在 SIEM 中添加模拟 IOC 规则。"],
            raw_content='{"title":"制造业勒索软件活动模拟简报"}',
        )

    monkeypatch.setattr("app.threat_intelligence.generate_threat_intelligence", fake_generate)
    client = create_threat_intelligence_app().test_client()

    response = client.post(
        "/generate",
        json={"topic": "近期针对制造业的勒索软件活动", "intelligence_type": "campaign", "language": "zh"},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["title"] == "制造业勒索软件活动模拟简报"
    assert payload["indicators"][0]["value"] == "update-check.example"


def test_threat_intelligence_swagger2_document() -> None:
    client = create_threat_intelligence_app().test_client()

    response = client.get("/swagger.json")
    schema = response.get_json()

    assert response.status_code == 200
    assert schema["swagger"] == "2.0"
    assert schema["info"]["title"] == "模拟威胁情报服务 API"
    assert schema["basePath"] == "/"
    assert "/generate" in schema["paths"]
    assert "ThreatIntelligenceRequest" in schema["definitions"]
    assert "ThreatIntelligenceResponse" in schema["definitions"]
