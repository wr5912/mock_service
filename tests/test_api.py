from fastapi.testclient import TestClient
import pytest

from app.main import app


client = TestClient(app)
LIST_ROUTES = ["assets", "alerts", "incidents", "vulnerabilities", "indicators", "events"]


def test_health() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@pytest.mark.parametrize("route", LIST_ROUTES)
def test_lists_count_and_seed_are_stable(route: str) -> None:
    first = client.get(f"/api/v1/{route}", params={"count": 3, "seed": 7})
    second = client.get(f"/api/v1/{route}", params={"count": 3, "seed": 7})

    assert first.status_code == 200
    assert len(first.json()) == 3
    assert first.json() == second.json()


@pytest.mark.parametrize("count", [0, 201, "neutral-validation-marker"])
def test_count_validation_does_not_echo_input(count) -> None:
    response = client.get("/api/v1/assets", params={"count": count})

    assert response.status_code == 422
    assert "neutral-validation-marker" not in response.text
    assert "input" not in response.json()


def test_openapi_contains_docs() -> None:
    response = client.get("/openapi.json")
    schema = response.json()

    assert response.status_code == 200
    assert schema["info"]["title"] == "网络安全运营模拟数据 API"
    assert "/api/v1/alerts" in schema["paths"]
    assert "基本" in schema["paths"]["/api/v1/ai/scenarios"]["post"]["summary"]


@pytest.mark.parametrize("language", ["zh", "en"])
def test_ai_scenario_is_local_and_does_not_echo_topic(language: str, monkeypatch) -> None:
    def fail_network(*args, **kwargs):
        pytest.fail("基本场景不应调用外部网络。")

    monkeypatch.setattr("httpx.AsyncClient.request", fail_network)
    first = client.post("/api/v1/ai/scenarios", json={"topic": "neutral-topic-marker", "language": language})
    second = client.post("/api/v1/ai/scenarios", json={"topic": "another-topic-marker", "language": language})

    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()
    assert first.json()["model"] == "local-basic-mock"
    assert "neutral-topic-marker" not in first.text


def test_ai_scenario_validation_does_not_echo_input() -> None:
    response = client.post(
        "/api/v1/ai/scenarios", json={"topic": "基础资产状态", "language": "neutral-validation-marker"}
    )

    assert response.status_code == 422
    assert "neutral-validation-marker" not in response.text
