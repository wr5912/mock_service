import pytest
from fastapi.testclient import TestClient

from app.host_mock import app


client = TestClient(app)
AUTHORIZATION = {"Authorization": "Bearer local-host-test"}
COMMAND = {"commandId": "mock-command-10", "hostIds": ["00071"], "params": {}, "delay": 0}
POLICY = {"hostId": "00071", "devicePolicy": {"usbstor": "3"}, "loginPolicy": {}, "fwPolicy": []}


def test_host_specification_publishes_only_the_two_platform_operations() -> None:
    response = client.get("/app/v2/api-docs")
    assert response.status_code == 200
    spec = response.json()
    assert spec["servers"] == [{"url": "/app"}]
    assert {path: entry["post"]["operationId"] for path, entry in spec["paths"].items()} == {
        "/ai/sendHmCmd": "sendHmCmdUsingPOST",
        "/ai/sendHmPolicy": "sendHmPolicyUsingPOST",
    }
    for path, body in (("/ai/sendHmCmd", COMMAND), ("/ai/sendHmPolicy", POLICY)):
        operation = spec["paths"][path]["post"]
        request = operation["requestBody"]
        assert request["required"] is True
        name = request["content"]["application/json"]["schema"]["$ref"].rsplit("/", 1)[-1]
        fields = spec["components"]["schemas"][name]
        assert set(fields["required"]) == body.keys() - {"delay"}
        assert set(fields["properties"]) == body.keys() | {"hostIp"}


@pytest.mark.parametrize(("path", "body"), [
    ("sendHmCmd", COMMAND),
    ("sendHmCmd", {"commandId": "mock-command-11", "hostIds": ["00071", "00072"], "params": {"note": "must-not-echo"}}),
    ("sendHmPolicy", POLICY),
    ("sendHmPolicy", {**POLICY, "devicePolicy": {}, "fwPolicy": [{"rulename": "本地规则"}], "hostIp": "192.0.2.10"}),
])
def test_host_commands_and_policies_return_fixed_receipts(path: str, body: dict) -> None:
    response = client.post(f"/app/ai/{path}", headers=AUTHORIZATION, json=body)
    assert response.status_code == 200
    assert response.json() == {
        "code": 200, "accepted": True, "simulated": True, "sideEffect": False, "message": "模拟请求已受理。",
    }


@pytest.mark.parametrize(("path", "body"), [
    ("sendHmCmd", {**COMMAND, "hostIds": "must-not-echo"}),
    ("sendHmCmd", {**COMMAND, "delay": "0"}),
    ("sendHmCmd", {**COMMAND, "params": []}),
    ("sendHmCmd", {"body": COMMAND}),
    ("sendHmPolicy", {key: value for key, value in POLICY.items() if key != "loginPolicy"}),
    ("sendHmPolicy", {**POLICY, "devicePolicy": {"usbstor": 3}}),
    ("sendHmPolicy", {**POLICY, "fwPolicy": [{}]}),
])
def test_invalid_host_requests_return_only_a_fixed_error(path: str, body: dict) -> None:
    response = client.post(f"/app/ai/{path}", headers=AUTHORIZATION, json=body)
    assert response.status_code == 422
    assert response.json() == {"detail": "请求参数无效。"}


def test_host_write_requires_the_configured_request_header() -> None:
    response = client.post("/app/ai/sendHmCmd", json=COMMAND)
    assert response.status_code == 401
    assert response.json() == {"detail": "缺少 Authorization 请求头。"}
