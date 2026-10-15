from __future__ import annotations

from typing import get_args

import pytest

from app.models import ThreatIntelligenceType
from app.threat_intelligence import create_threat_intelligence_app


def test_threat_intelligence_health() -> None:
    response = create_threat_intelligence_app().test_client().get("/health")

    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"


@pytest.mark.parametrize("intelligence_type", get_args(ThreatIntelligenceType))
def test_threat_intelligence_is_local_basic_data(intelligence_type, monkeypatch) -> None:
    def fail_network(*args, **kwargs):
        pytest.fail("基本数据接口不应调用外部网络。")

    monkeypatch.setattr("httpx.AsyncClient.request", fail_network)
    client = create_threat_intelligence_app().test_client()
    response = client.post(
        "/generate",
        json={"topic": "neutral-topic-marker", "intelligence_type": intelligence_type, "language": "zh"},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["model"] == "local-basic-mock"
    assert payload["intelligence_type"] == "situational"
    assert payload["topic"] == "基础资产状态"
    assert payload["threat_actor"] is None
    assert payload["ttps"] == []
    assert payload["raw_content"] == ""
    assert payload["recommendations"] == []
    assert payload["indicators"][0]["threat_type"] == "none"
    assert "neutral-topic-marker" not in response.get_data(as_text=True)


def test_threat_intelligence_language_and_include_iocs() -> None:
    client = create_threat_intelligence_app().test_client()
    response = client.post("/generate", json={"topic": "基础状态", "language": "en", "include_iocs": False})
    repeated = client.post("/generate", json={"topic": "另一主题", "language": "en", "include_iocs": False})

    assert response.status_code == 200
    assert response.get_json() == repeated.get_json()
    assert response.get_json()["topic"] == "Basic asset status"
    assert response.get_json()["indicators"] == []


@pytest.mark.parametrize(
    "payload",
    [
        {"topic": "基础状态", "language": "neutral-validation-marker"},
        {"topic": ["neutral-validation-marker"]},
        {"topic": "基础状态", "intelligence_type": "neutral-validation-marker"},
        ["neutral-validation-marker"],
    ],
)
def test_threat_intelligence_errors_do_not_echo_input(payload) -> None:
    response = create_threat_intelligence_app().test_client().post("/generate", json=payload)

    assert response.status_code == 400
    assert response.get_json() == {"message": "请求参数校验失败。"}
    assert "neutral-validation-marker" not in response.get_data(as_text=True)


def test_threat_intelligence_malformed_json_is_generic() -> None:
    response = create_threat_intelligence_app().test_client().post(
        "/generate", data="neutral-validation-marker", content_type="application/json"
    )

    assert response.status_code == 400
    assert "neutral-validation-marker" not in response.get_data(as_text=True)


def test_threat_intelligence_swagger2_document() -> None:
    response = create_threat_intelligence_app().test_client().get("/swagger.json")
    schema = response.get_json()

    assert response.status_code == 200
    assert schema["swagger"] == "2.0"
    assert schema["info"]["title"] == "模拟威胁情报服务 API"
    assert schema["basePath"] == "/"
    assert "/generate" in schema["paths"]
    assert "ThreatIntelligenceRequest" in schema["definitions"]
    assert "ThreatIntelligenceResponse" in schema["definitions"]
