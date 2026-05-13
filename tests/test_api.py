from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_health() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_alerts_count_and_seed_are_stable() -> None:
    first = client.get("/api/v1/alerts", params={"count": 3, "seed": 7})
    second = client.get("/api/v1/alerts", params={"count": 3, "seed": 7})

    assert first.status_code == 200
    assert len(first.json()) == 3
    assert first.json()[0]["alert_id"] == "alert-0001"
    assert first.json() == second.json()


def test_count_validation() -> None:
    response = client.get("/api/v1/assets", params={"count": 201})

    assert response.status_code == 422


def test_openapi_contains_docs() -> None:
    response = client.get("/openapi.json")
    schema = response.json()

    assert response.status_code == 200
    assert schema["info"]["title"] == "网络安全运营模拟数据 API"
    assert "/api/v1/alerts" in schema["paths"]
    assert schema["paths"]["/api/v1/ai/scenarios"]["post"]["summary"] == "生成安全运营演练场景"


def test_ai_scenario_requires_api_key() -> None:
    response = client.post("/api/v1/ai/scenarios", json={"topic": "勒索软件告警调查", "language": "zh"})

    assert response.status_code == 503
    assert "DEEPSEEK_API_KEY" in response.json()["detail"]
