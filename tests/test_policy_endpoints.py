"""新运行时边界合同：仅基础资产及进程内状态，不验证真实签名或设备动作。"""
import base64
from copy import deepcopy
import json
import time

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from app.security_operations.handlers import invoke, reset_state
from app.security_operations.router import create_router
from app.security_operations.state import MockError, STATE


@pytest.fixture(autouse=True)
def isolated_state():
    reset_state()
    yield
    reset_state()


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(create_router())
    with TestClient(app) as value:
        yield value


def call(name, **args):
    return invoke("policy-configuration", name, args, "http://mock.test")["data"]


def endpoint_body(**changes):
    return {"contract_version": "workbench-policy-endpoint-resolution/v1", "request_id": "basic-policy-1",
            "operation": "ADD", "action": "ALLOW", "source_query": "192.0.2.10", "destination_query": "mock-db",
            "protocol": "TCP", "destination_port": 443, **changes}


def proof(operation, field="candidate_digest", **changes):
    issued = int(time.time())
    payload = {"operation_id": operation["operation_id"], "version": operation["version"],
               field: operation[field], "decision": "CONFIRM", "audience": "operation-confirmation-v1",
               "event_type": "UserPromptSubmit", "purpose": "strategy.apply" if field == "candidate_digest" else "emergency.execute",
               "issued_at": issued, "expires_at": issued + 120, **changes}
    encode = lambda value: base64.urlsafe_b64encode(value).decode().rstrip("=")
    # 仅构造自定义二段格式的基本载荷，刻意不宣称这是有效的 RSA 签名。
    return encode(json.dumps(payload).encode()) + "." + encode(b"basic-mock-signature")


def prepared(**changes):
    resolved = call("resolve_policy_endpoints", body=endpoint_body(**changes))
    return call("prepare_policy_configuration", body=resolved["prepare_body"])


def ready(client):
    operation = prepared()
    selection = operation["selection"]
    response = client.post(f'/api/v1/policy-configurations/{operation["operation_id"]}/candidate-selection', json={
        "candidate_set_digest": selection["candidate_set_digest"],
        "ranked_candidate_ids": [row["candidate_id"] for row in selection["candidates"]], "reason_codes": ["user_explicit_device_selection"],
    })
    assert response.status_code == 200
    return response.json()["data"]


def test_resolve_exact_normal_assets_preserves_action_and_frozen_prepare():
    body = endpoint_body(action="DENY", device_query="测试防火墙")
    resolved = call("resolve_policy_endpoints", body=body)
    assert resolved == call("resolve_policy_endpoints", body=body)
    assert resolved["resolution_status"] == "RESOLVED"
    assert resolved["source"]["candidates"][0]["ip"] == "192.0.2.10"
    assert resolved["destination"]["candidates"][0]["ip"] == "192.0.2.20"
    assert resolved["prepare_body"]["intent"]["action"] == "DENY"
    assert resolved["result_markdown"].startswith("### 需求理解")
    operation = call("prepare_policy_configuration", body=resolved["prepare_body"])
    assert operation["task_status"] == "DRAFT"
    assert operation["version"] == 1
    assert operation["confirmation_expires_at"]
    assert operation["intent"]["action"] == "DENY"


def test_ambiguous_endpoint_http_choice_freezes_same_request_and_replays(client):
    body = endpoint_body(source_query="服务器")
    resolved = call("resolve_policy_endpoints", body=body)
    assert resolved["resolution_status"] == "SELECTION_REQUIRED"
    assert len(resolved["source"]["candidates"]) == 2
    choice = {**body, "candidate_set_digest": resolved["candidate_set_digest"],
              "selected_source_candidate_id": resolved["source"]["candidates"][0]["candidate_id"],
              "selected_destination_candidate_id": resolved["destination"]["selected_candidate_id"]}
    response = client.post("/api/v1/policy-configurations/endpoint-resolution/selection", json=choice)
    assert response.status_code == 200
    selected = response.json()["data"]
    assert response.json()["code"] == "200"
    assert selected["resolution_status"] == "RESOLVED"
    assert selected["request_id"] == body["request_id"]
    assert selected["prepare_body"]["intent"]["source"]["value"] == "192.0.2.10"
    assert client.post("/api/v1/policy-configurations/endpoint-resolution/selection", json=choice).json()["data"] == selected
    assert call("choose_ambiguous_policy_endpoints", body=choice) == selected
    assert call("prepare_policy_configuration", body=selected["prepare_body"])["accepted"]
    other = {**choice, "selected_source_candidate_id": resolved["source"]["candidates"][1]["candidate_id"]}
    assert client.post("/api/v1/policy-configurations/endpoint-resolution/selection", json=other).status_code == 409


@pytest.mark.parametrize("change", [{"candidate_set_digest": "sha256:stale"}, {"selected_source_candidate_id": "unknown-basic-id"}])
def test_endpoint_choice_rejects_forged_candidate_or_digest(client, change):
    body = endpoint_body(source_query="服务器")
    resolved = call("resolve_policy_endpoints", body=body)
    choice = {**body, "candidate_set_digest": resolved["candidate_set_digest"],
              "selected_source_candidate_id": resolved["source"]["candidates"][0]["candidate_id"],
              "selected_destination_candidate_id": resolved["destination"]["selected_candidate_id"], **change}
    assert client.post("/api/v1/policy-configurations/endpoint-resolution/selection", json=choice).status_code in {409, 422}
    assert not STATE["policy"]
    assert call("resolve_policy_endpoints", body=body)["resolution_status"] == "SELECTION_REQUIRED"


def test_preparation_rejects_changed_frozen_intent_and_request_id_reuse():
    body = endpoint_body()
    resolved = call("resolve_policy_endpoints", body=body)
    changed = deepcopy(resolved["prepare_body"])
    changed["intent"]["action"] = "DENY"
    with pytest.raises(MockError) as failure:
        call("prepare_policy_configuration", body=changed)
    assert failure.value.status_code == 409
    with pytest.raises(MockError):
        call("resolve_policy_endpoints", body={**body, "destination_port": 8443})
    assert not STATE["policy"]


def test_policy_http_confirmation_and_result_share_bound_version(client):
    draft = ready(client)
    path = f'/api/v1/policy-configurations/{draft["operation_id"]}'
    assert client.get(path).json()["data"]["task_status"] == "DRAFT"
    assert client.get(path + "/result").json()["data"]["candidate_digest"] == draft["candidate_digest"]
    body = {"request_id": "basic-confirm-1", "candidate_digest": draft["candidate_digest"], "proof": proof(draft)}
    response = client.post(path + "/confirmation", json=body)
    assert response.status_code == 200
    completed = response.json()["data"]
    assert response.json()["code"] == "200"
    assert completed["confirmation"]["accepted"] is True
    assert completed["confirmation"]["approval_receipt_id"]
    assert completed["failure_scope"] == "NONE"
    assert completed["execution"]["result_code"] == completed["result_code"] == "SUCCESS"
    assert completed["confirmation_proof_verified"] is False
    assert completed["simulated"] is True
    assert "真实设备" in completed["result_markdown"]
    assert client.post(path + "/confirmation", json=body).json()["data"] == completed
    assert client.get(path + "/result").json()["data"] == completed


@pytest.mark.parametrize("field,value", [("version", True), ("version", 2), ("operation_id", "other-basic-operation"),
                                        ("purpose", "emergency.execute"), ("expires_at", 1)])
def test_policy_confirmation_rejects_stale_wrong_or_expired_payload(client, field, value):
    draft = ready(client)
    response = client.post(f'/api/v1/policy-configurations/{draft["operation_id"]}/confirmation', json={
        "request_id": "basic-confirm-1", "candidate_digest": draft["candidate_digest"], "proof": proof(draft, **{field: value}),
    })
    assert response.status_code == 422
    assert STATE["policy"][draft["operation_id"]]["task_status"] == "DRAFT"


@pytest.mark.parametrize("decision,result_code", [("REJECT", "POLICY_REJECTED"), ("REQUEST_CHANGES", "POLICY_CHANGES_REQUESTED")])
def test_policy_decision_closes_bound_draft_without_echoing_reason(client, decision, result_code):
    draft = ready(client)
    path = f'/api/v1/policy-configurations/{draft["operation_id"]}'
    body = {"request_id": "basic-decision-1", "candidate_digest": draft["candidate_digest"],
            "business_revision": draft["version"], "decision": decision, "reason": "basic-unreturned-reason-marker"}
    response = client.post(path + "/decisions", json=body)
    assert response.status_code == 200
    assert response.json()["data"]["operation_status"] == "cancelled"
    assert "basic-unreturned-reason-marker" not in response.text
    assert client.get(path + "/result").json()["data"]["result_code"] == result_code
    assert client.post(path + "/decisions", json=body).json() == response.json()
    assert client.post(path + "/confirmation", json={"request_id": "basic-confirm", "candidate_digest": draft["candidate_digest"], "proof": proof(draft)}).status_code == 409


def test_policy_candidate_cancel_cannot_be_reopened_by_selection(client):
    operation = prepared()
    path = f'/api/v1/policy-configurations/{operation["operation_id"]}'
    selection = operation["selection"]
    body = {"request_id": "basic-cancel-selection", "candidate_digest": selection["candidate_set_digest"],
            "business_revision": selection["business_revision"], "decision": "REJECT", "reason": "取消基础模拟选择"}
    assert client.post(path + "/decisions", json=body).status_code == 200
    assert client.post(path + "/candidate-selection", json={"candidate_set_digest": selection["candidate_set_digest"],
        "ranked_candidate_ids": [row["candidate_id"] for row in selection["candidates"]], "reason_codes": []}).status_code == 409


def test_emergency_new_proof_http_envelope_matches_runtime_and_keeps_mock_boundary(client):
    draft = invoke("emergency-action", "prepare_emergency_action", {"body": {
        "request_id": "basic-emergency-1", "intent": "模拟重启测试主机", "target_hint": "192.0.2.10"}}, "http://mock.test")["data"]
    assert draft["snapshot"]["target_hint"] == "192.0.2.10"
    path = f'/api/v1/emergency-actions/{draft["operation_id"]}'
    response = client.post(path + "/confirmations", json={"request_id": "basic-emergency-confirm", "expected_version": 1,
        "snapshot_digest": draft["snapshot_digest"], "proof": proof(draft, "snapshot_digest")})
    assert response.status_code == 200
    assert response.json()["code"] == "200"
    completed = response.json()["data"]
    assert completed["phase"] == "TERMINAL"
    assert completed["execution_status"] == "SUCCEEDED"
    assert completed["confirmation_proof_verified"] is False
    assert client.get(path + "/result").json()["data"] == completed


def test_new_http_contracts_reject_unknown_objects_invalid_body_without_echo(client):
    marker = "basic-unreturned-input-marker"
    for suffix in ["/confirmation", "/candidate-selection", "/decisions"]:
        response = client.post("/api/v1/policy-configurations/basic-unknown" + suffix, json={"request_id": marker})
        assert response.status_code in {404, 422}
        assert marker not in response.text
    assert client.get("/api/v1/policy-configurations/basic-unknown/result").status_code == 404
    with pytest.raises(MockError) as failure:
        call("resolve_policy_endpoints", body=endpoint_body(source_query=marker))
    assert marker not in failure.value.message


def test_openapi_uses_same_native_confirmation_and_endpoint_schemas(client):
    spec = client.get("/openapi.json").json()
    for path in ["/api/v1/policy-configurations/{operation_id}/confirmation", "/api/v1/emergency-actions/{operation_id}/confirmations"]:
        body = spec["paths"][path]["post"]["requestBody"]["content"]["application/json"]["schema"]
        assert "proof" in body["properties"]
    assert len(client.get("/api/v1/security-operations/openapi.json").json()["paths"]) == 19
