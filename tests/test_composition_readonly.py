from copy import deepcopy
from datetime import datetime

from fastapi.testclient import TestClient
import pytest

from app.main import app
from app.security_operations.state import STATE


client = TestClient(app)
BASE = "/api/v1/security-operations/readonly"


def test_composition_spec_has_only_the_two_actual_get_operations() -> None:
    response = client.get(BASE + "/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert schema["servers"] == [{"url": "/"}]
    assert len(schema["paths"]) == 2
    assert {operation["get"]["operationId"] for operation in schema["paths"].values()} == {
        "get_soc_asset_by_asset_id", "list_detect_alert",
    }
    query = schema["paths"][BASE + "/alerts"]["get"]["parameters"]
    assert len(query) == 1
    assert query[0]["name"] == "req"
    assert query[0]["in"] == "query"
    assert query[0]["style"] == "form" and query[0]["explode"] is True
    assert query[0]["schema"]["properties"]["assetId"]["type"] == "string"
    assert query[0]["schema"]["properties"]["pageSize"]["maximum"] == 20


@pytest.mark.parametrize("asset_id,alert_id", [(9106, "MOCK-ALERT-000001"), (9107, "MOCK-ALERT-000002")])
def test_two_steps_keep_asset_identity_and_return_basic_groups(asset_id, alert_id) -> None:
    before = deepcopy(STATE)
    first = client.get(f"{BASE}/assets/{asset_id}")
    assert first.status_code == 200
    asset = first.json()
    assert type(asset["code"]) is int and asset["code"] == 200
    assert type(asset["data"]["assetId"]) is int
    assert asset["data"]["assetId"] == asset_id
    # OpenAPI 的 req 使用 form/explode，因此上游对象应展开成这四个查询参数。
    second = client.get(BASE + "/alerts", params={
        "assetId": str(asset["data"]["assetId"]), "pageNum": 1, "pageSize": 1, "windowSeconds": 2592000,
    })
    assert second.status_code == 200
    data = second.json()["data"]
    assert second.json()["code"] == 200
    assert data["totalGroups"] == data["totalAlerts"] == 1
    assert data["pageNum"] == data["pageSize"] == 1
    assert data["truncated"] is False
    assert len(data["groups"]) == 1
    group = data["groups"][0]
    assert group["assetId"] == asset_id
    assert group["alerts"][0]["alert_id"] == alert_id
    assert group["alerts"][0]["affectedAssetId"] == asset_id
    assert group["alerts"][0]["title"] == "正常运维测试告警"
    start = datetime.fromisoformat(data["from"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(data["to"].replace("Z", "+00:00"))
    assert (end - start).total_seconds() == 2592000
    assert STATE == before


def test_alert_pagination_keeps_totals_and_does_not_invent_more_groups() -> None:
    response = client.get(BASE + "/alerts", params={"assetId": "9106", "pageNum": 2, "pageSize": 1})
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["groups"] == []
    assert data["totalGroups"] == data["totalAlerts"] == 1
    assert data["pageNum"] == 2


def test_existing_asset_without_alerts_returns_an_empty_success() -> None:
    assert client.get(BASE + "/assets/9200").status_code == 200
    response = client.get(BASE + "/alerts", params={"assetId": "9200"})
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["groups"] == []
    assert data["totalGroups"] == data["totalAlerts"] == 0


@pytest.mark.parametrize("path", [BASE + "/assets/9999", BASE + "/alerts?assetId=9999"])
def test_unknown_asset_is_not_reported_as_a_success(path: str) -> None:
    response = client.get(path)
    assert response.status_code == 404
    assert response.json() == {"detail": "未找到对应模拟资产"}


@pytest.mark.parametrize("params", [
    {"assetId": "neutral-validation-marker"},
    {"assetId": "0"},
    {"assetId": "-1"},
    {"assetId": "9106", "pageNum": 0},
    {"assetId": "9106", "pageSize": 0},
    {"assetId": "9106", "pageSize": 21},
    {"assetId": "9106", "windowSeconds": 0},
    {"assetId": "9106", "windowSeconds": 2592001},
    {"assetId": "9106", "topic": "neutral-validation-marker"},
    {"req": "[object Object]"},
    {},
])
def test_invalid_alert_queries_do_not_echo_values(params) -> None:
    response = client.get(BASE + "/alerts", params=params)
    assert response.status_code == 422
    assert response.json() == {"detail": "告警查询参数无效"}
    assert "neutral-validation-marker" not in response.text


def test_invalid_asset_path_does_not_echo_values() -> None:
    response = client.get(BASE + "/assets/neutral-validation-marker")
    assert response.status_code == 422
    assert "neutral-validation-marker" not in response.text


def test_existing_soc_spec_remains_the_same_nineteen_gateway_operations() -> None:
    schema = client.get("/api/v1/security-operations/openapi.json").json()
    assert len(schema["paths"]) == 19
    assert all(set(operation) == {"post"} for operation in schema["paths"].values())
    assert all(path.startswith("/api/v1/mcp-resources/") for path in schema["paths"])
