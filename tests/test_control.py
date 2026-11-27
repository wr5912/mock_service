"""真实 FastAPI/MCP 接口验证模拟边界、隔离、故障与脱敏观察。"""
import base64
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
import time

from fastapi.testclient import TestClient
import pytest

from app.config import get_settings
from app.control import FIXTURES, MARKERS, RESOURCE_URI
from app.main import app
from app.security_operations.catalog import SOC_TOOLS
from app.security_operations.state import INCIDENT_IDS


@pytest.fixture(scope="module")
def client():
    # MCP SDK 的 session manager 单实例只能启动一次，整组共用服务生命周期。
    with pytest.MonkeyPatch.context() as settings:
        settings.setenv("MOCK_CONTROL_ENABLED", "true")
        get_settings.cache_clear()
        with TestClient(app) as service:
            yield service
        get_settings.cache_clear()


@pytest.fixture(autouse=True)
def clean_fixtures():
    FIXTURES.clear()
    yield
    FIXTURES.clear()


def create(client, run="run-a"):
    response = client.post("/api/v1/control/fixtures", json={"testRunId": run})
    assert response.status_code == 200
    return response.json()["credentials"]


def headers(run="run-a", subject="subject-a"):
    return {"X-Test-Run-Id": run, "X-Control-Subject-Id": subject}


def ledger(client, run="run-a"):
    response = client.get(f"/api/v1/control/fixtures/{run}/requests")
    assert response.status_code == 200
    return response.json()


def soc(client, operation, arguments, run="run-a"):
    path = f"/api/v1/mcp-resources/{SOC_TOOLS[operation]['resource_id']}/tools/{operation}/invoke"
    return client.post(path, headers=headers(run), json={"arguments": arguments})


def rpc(client, method, params=None, group="sec-ops", run="run-a"):
    response = client.post(f"/mcp/{group}/", headers={**headers(run),
        "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-11-25"},
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}})
    assert response.status_code == 200, response.text
    return response.json()


def test_controls_are_disabled_without_explicit_setting(monkeypatch):
    monkeypatch.setenv("MOCK_CONTROL_ENABLED", "false")
    get_settings.cache_clear()
    service = TestClient(app)
    assert service.post("/api/v1/control/fixtures", json={"testRunId": "disabled"}).status_code == 404
    assert service.get("/health", headers=headers()).status_code == 404
    get_settings.cache_clear()


def test_credential_lifecycle_keeps_subject_and_never_records_secret(client):
    credentials = create(client)
    assert [item["subjectId"] for item in credentials] == ["subject-a", "subject-b"]
    auth = lambda credential: client.post("/api/v1/control/identity/authenticate", json={"credential": credential}).json()
    original = credentials[0]
    assert auth(original["credential"])["authenticated"]
    trusted = client.post("/api/v1/control/identity/trust", json={key: original[key] for key in ("subjectId", "credentialId")})
    assert trusted.json()["valid"]
    rotated = client.post("/api/v1/control/fixtures/run-a/credentials/subject-a", json={"action": "rotate"}).json()
    assert rotated["subjectId"] == original["subjectId"]
    assert rotated["credentialId"] != original["credentialId"]
    assert not auth(original["credential"])["authenticated"]
    assert auth(rotated["credential"])["authenticated"]
    assert not client.post("/api/v1/control/identity/trust", json={key: original[key] for key in ("subjectId", "credentialId")}).json()["valid"]
    client.post("/api/v1/control/fixtures/run-a/credentials/subject-a", json={"action": "revoke"})
    assert not auth(rotated["credential"])["authenticated"]
    client.post("/api/v1/control/fixtures/run-a/credentials/subject-b", json={"action": "expire"})
    assert not auth(credentials[1]["credential"])["authenticated"]
    assert not auth("NEVER_REFLECT_THIS_CREDENTIAL")["authenticated"]
    assert "NEVER_REFLECT" not in json.dumps(auth("NEVER_REFLECT_THIS_CREDENTIAL"))
    assert all(item["credential"] not in json.dumps(FIXTURES) for item in credentials)
    assert ledger(client) == []
    assert client.post("/api/v1/control/fixtures", json={"testRunId": "run-a"}).status_code == 409


def test_risk_scope_version_expiry_markers_and_recovery(client):
    create(client)
    payload = {"testRunId": "run-a", "subjectId": "subject-a", "sessionId": "session-a", "operation": "update_result"}
    assess = lambda **changes: client.post("/api/v1/control/risk/evaluate", json={**payload, **changes}).json()
    assert assess()["constraints"] == {"deniedOperations": []}
    first = client.put("/api/v1/control/fixtures/run-a/risk", json={"subjectId": "subject-a", "deniedOperations": ["write"]}).json()
    scoped = client.put("/api/v1/control/fixtures/run-a/risk", json={"subjectId": "subject-a", "sessionId": "session-a", "deniedOperations": ["publish"]}).json()
    assert scoped["version"] > first["version"]
    assert assess()["constraints"]["deniedOperations"] == ["write", "publish"]
    assert assess(subjectId="subject-b")["level"] == "low"
    assert assess(sessionId="other")["constraints"]["deniedOperations"] == ["write"]
    client.put("/api/v1/control/fixtures/run-a/risk", json={"subjectId": "subject-a", "deniedOperations": []})
    assert assess()["constraints"]["deniedOperations"] == ["publish"]
    cleared = client.put("/api/v1/control/fixtures/run-a/risk", json={"subjectId": "subject-a", "sessionId": "session-a", "deniedOperations": [], "expiresInSeconds": -1}).json()
    assert assess()["expiresAt"] == cleared["expiresAt"]
    for phase, marker, operation in (("input", MARKERS[0], "*"), ("execute", MARKERS[1], "write"), ("report", MARKERS[2], "publish")):
        result = assess(phase=phase, input={"text": "private-original-text " + marker})
        assert result["level"] == "high" and operation in result["constraints"]["deniedOperations"]
        assert "private-original-text" not in json.dumps(result)
    assert ledger(client) == []


def test_agent_risk_scope_isolates_same_user_and_echoes_only_explicit_scope(client):
    create(client)
    scope = {"workspaceId": "workspace-control", "agentId": "soc-a", "instanceId": "instance-a",
             "runtimeGeneration": "generation-a", "subjectId": "subject-a", "sessionId": "session-shared", "serverId": "soc"}
    payload = {"testRunId": "run-a", "subjectId": "subject-a", "sessionId": "session-shared", "operation": "write",
               "scope": scope, "sourceDigest": "sha256:fixed-a",
               "operationBinding": {"serverId": "soc", "operationId": "writeback", "target": "https://upstream.invalid/item?private=DO_NOT_RETURN",
                                    "method": "POST", "kind": "write"}}
    assess = lambda value: client.post("/api/v1/control/risk/evaluate", json=value).json()
    changed = client.put("/api/v1/control/fixtures/run-a/risk", json={"agentId": "soc-a", "subjectId": "subject-a", "deniedOperations": ["write"]})
    assert changed.status_code == 200
    assert changed.json()["scope"] == {"agentId": "soc-a", "subjectId": "subject-a"}
    a = assess(payload)
    assert a["scope"] == scope and a["constraints"]["deniedOperations"] == ["write"]
    assert "DO_NOT_RETURN" not in json.dumps(a) and "sourceDigest" not in a and "operationBinding" not in a
    b_payload = {**payload, "scope": {**scope, "agentId": "soc-b", "instanceId": "instance-b", "runtimeGeneration": "generation-b"},
                 "sourceDigest": "sha256:fixed-b"}
    assert assess(b_payload)["level"] == "low"
    # 旧合同没有明确 Agent 范围，不猜测其所属 Agent，也不从 Header 提升为认证事实。
    legacy = {key: payload[key] for key in ("testRunId", "subjectId", "sessionId", "operation")}
    response = client.post("/api/v1/control/risk/evaluate", headers={**headers(subject="subject-b"), "X-Control-Agent-Id": "soc-a"}, json=legacy)
    assert response.json()["scope"] == {"subjectId": "subject-a", "sessionId": "session-shared"}
    assert response.json()["level"] == "low"
    client.put("/api/v1/control/fixtures/run-a/risk", json={"agentId": "soc-a", "subjectId": "subject-a", "sessionId": "session-shared", "deniedOperations": ["read"]})
    client.put("/api/v1/control/fixtures/run-a/risk", json={"subjectId": "subject-a", "deniedOperations": ["publish"]})
    assert assess(payload)["constraints"]["deniedOperations"] == ["publish", "write", "read"]
    assert assess(b_payload)["constraints"]["deniedOperations"] == ["publish"]
    client.put("/api/v1/control/fixtures/run-a/risk", json={"agentId": "soc-a", "subjectId": "subject-a", "deniedOperations": []})
    assert assess(payload)["constraints"]["deniedOperations"] == ["publish", "read"]
    assert assess(b_payload)["constraints"]["deniedOperations"] == ["publish"]
    assert ledger(client) == []


def test_agent_risk_rejects_inconsistent_scope_and_invalid_operation_without_echo(client):
    create(client)
    scope = {"workspaceId": "workspace-control", "agentId": "soc-a", "instanceId": "instance-a",
             "runtimeGeneration": "generation-a", "subjectId": "subject-a", "sessionId": "session-a", "serverId": "soc"}
    payload = {"testRunId": "run-a", "subjectId": "subject-a", "sessionId": "session-a", "operation": "write", "scope": scope,
               "sourceDigest": "sha256:fixed-a", "operationBinding": {"serverId": "soc", "operationId": "writeback", "target": "https://upstream.invalid/item",
                                                                         "method": "POST", "kind": "write"}}
    invalid = [{"scope": {**scope, "subjectId": "subject-b"}}, {"scope": {**scope, "sessionId": "session-b"}},
               {"scope": {**scope, "serverId": "other"}}, {"scope": {**scope, "agentId": "INVALID_AGENT"}},
               {"scope": {**scope, "workspaceId": " "}}, {"scope": {**scope, "credential": "DO_NOT_RETURN"}},
               {"sourceDigest": "DO_NOT_RETURN has spaces"}, {"operationBinding": {**payload["operationBinding"], "kind": "read"}},
               {"operationBinding": {**payload["operationBinding"], "method": "POST\nDO_NOT_RETURN"}},
               {"operationBinding": {**payload["operationBinding"], "credential": "DO_NOT_RETURN"}}]
    for change in invalid:
        response = client.post("/api/v1/control/risk/evaluate", json={**payload, **change})
        assert response.status_code == 422 and "DO_NOT_RETURN" not in response.text
    assert FIXTURES["run-a"]["risk"] == {}
    # 输入事件没有具体工具时，只提供真实 Agent 范围及来源也可评估。
    input_payload = {key: value for key, value in payload.items() if key != "operationBinding"}
    input_payload.update(operation="input", phase="input")
    assert client.post("/api/v1/control/risk/evaluate", json=input_payload).status_code == 200


def test_risk_marker_meaning_changes_advance_version_and_clean_recovery_is_stable(client):
    create(client)
    payload = {"testRunId": "run-a", "subjectId": "subject-a", "sessionId": "session-a", "operation": "write", "phase": "execute",
               "scope": {"workspaceId": "workspace-control", "agentId": "soc-a", "instanceId": "instance-a",
                         "runtimeGeneration": "generation-a", "subjectId": "subject-a", "sessionId": "session-a"}}
    assess = lambda value=None: client.post("/api/v1/control/risk/evaluate", json={**payload, "input": value}).json()
    first = assess("clean input")
    assert first["level"] == "low"
    assert assess("another clean input")["version"] == first["version"]
    marked = assess(MARKERS[1])
    assert marked["level"] == "high" and marked["version"] > first["version"]
    assert assess("unchanged meaning " + MARKERS[1])["version"] == marked["version"]
    recovered = assess("clean after marker")
    assert recovered["level"] == "low" and recovered["constraints"]["deniedOperations"] == []
    assert recovered["version"] > marked["version"]
    assert assess("further clean input")["version"] == recovered["version"]
    updated = client.put("/api/v1/control/fixtures/run-a/risk", json={"agentId": "soc-a", "subjectId": "subject-a", "deniedOperations": ["publish"]}).json()
    manual = assess("clean input")
    assert manual["version"] == updated["version"] > recovered["version"]
    assert manual["constraints"]["deniedOperations"] == ["publish"]
    assert assess("more clean input")["version"] == manual["version"]
    assert ledger(client) == []


def test_business_state_and_target_ledger_are_isolated_per_fixture(client):
    create(client)
    create(client, "run-b")
    operation = "ai_soc_correlate__create_incident_judgement_claim"
    args = {"incidentId": INCIDENT_IDS[0]}
    a = soc(client, operation, args).json()["result"]["data"]
    b = soc(client, operation, args, "run-b").json()["result"]["data"]
    assert a["judgementId"] != b["judgementId"]
    assert soc(client, operation, args).status_code == 409
    assert [row["outcome"] for row in ledger(client)] == ["succeeded", "failed-before-commit"]
    assert len(ledger(client, "run-b")) == 1
    assert client.get("/health", headers=headers("missing")).status_code == 404
    assert client.get("/health", headers=headers(subject="arbitrary-private-value")).status_code == 422


def test_once_committed_timeout_exposes_real_commit_for_status_check(client):
    create(client)
    operation = "ai_soc_correlate__create_incident_judgement_claim"
    client.post("/api/v1/control/fixtures/run-a/faults", json={"operation": operation, "mode": "committed-timeout", "seconds": 0.01})
    response = soc(client, operation, {"incidentId": INCIDENT_IDS[0]})
    assert response.status_code == 504
    rows = ledger(client)
    assert len(rows) == 1 and rows[0]["committedAt"]
    assert rows[0]["outcome"] == "committed-response-unknown"
    pending = soc(client, "ai_soc_correlate__get_correlate_incident_judge_pending", {}).json()["result"]["data"]
    assert INCIDENT_IDS[0] not in [item["incidentId"] for item in pending["rows"]]
    # 相同故障只使用一次；另一个有效事件正常认领。
    assert soc(client, operation, {"incidentId": INCIDENT_IDS[1]}).status_code == 200


def test_block_release_and_delay_use_original_call_once(client):
    create(client)
    operation = "ai_soc_master__get_soc_asset_by_asset_id"
    fault = client.post("/api/v1/control/fixtures/run-a/faults", json={"operation": operation, "mode": "block", "seconds": 2}).json()
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(soc, client, operation, {"assetId": 9106})
        deadline = time.monotonic() + 2
        while not ledger(client) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert ledger(client)[0]["phase"] == "started"
        assert not pending.done()
        assert client.post(f"/api/v1/control/fixtures/run-a/faults/{fault['faultId']}/release").status_code == 200
        assert pending.result(timeout=2).status_code == 200
    assert len(ledger(client)) == 1 and ledger(client)[0]["outcome"] == "succeeded"
    client.post("/api/v1/control/fixtures/run-a/faults", json={"operation": operation, "mode": "delay", "seconds": 0.03})
    before = time.monotonic()
    assert soc(client, operation, {"assetId": 9107}).status_code == 200
    assert time.monotonic() - before >= 0.025


def test_report_arrival_records_decoded_hash_and_marker_without_original_content(client):
    create(client)
    original = "<article>PRIVATE_REPORT_CONTENT " + MARKERS[2] + "</article>"
    arguments = {"businessId": "control-report", "sourceModule": "threat-analysis", "revision": 1,
                 "resultType": "report", "contentType": "text/html", "fileName": "report.html",
                 "fileContentBase64": base64.b64encode(original.encode()).decode()}
    result = rpc(client, "tools/call", {"name": "save_persistence_result", "arguments": arguments}, group="report")["result"]
    assert not result["isError"]
    rows = ledger(client)
    assert rows[0]["reportBodyHash"] == "sha256:" + sha256(original.encode()).hexdigest()
    assert rows[0]["reportMarkers"] == [MARKERS[2]]
    assert "PRIVATE_REPORT_CONTENT" not in json.dumps(rows)
    assert arguments["fileContentBase64"] not in json.dumps(rows)
    report_id = result["structuredContent"]["data"]["id"]
    assert client.get(f"/reports/{report_id}.html", headers=headers("run-a")).status_code == 200
    create(client, "run-b")
    assert client.get(f"/reports/{report_id}.html", headers=headers("run-b")).status_code == 404
    assert client.get(f"/reports/{report_id}.html").status_code == 404
    assert ledger(client)[1]["operation"] == "download_report"


def test_fixed_resource_and_readonly_composition_observable(client):
    create(client)
    resources = rpc(client, "resources/list")["result"]["resources"]
    assert [item["uri"] for item in resources] == [RESOURCE_URI]
    resource = rpc(client, "resources/read", {"uri": RESOURCE_URI})["result"]["contents"][0]
    assert "9106" in resource["text"]
    assert "error" in rpc(client, "resources/read", {"uri": "mock-control://unknown/private"})
    assert client.get("/api/v1/security-operations/readonly/assets/9106", headers=headers()).status_code == 200
    assert client.get("/api/v1/security-operations/readonly/alerts?assetId=9200", headers=headers()).json()["data"]["totalAlerts"] == 0
    assert client.get("/api/v1/security-operations/readonly/assets/9999", headers=headers()).status_code == 404
    assert [row["operation"] for row in ledger(client)] == ["read_resource", "get_soc_asset_by_asset_id", "list_detect_alert", "get_soc_asset_by_asset_id"]


def test_control_openapi_and_invalid_body_do_not_echo_input(client):
    schema = client.get("/openapi.json").json()
    for path in ("/api/v1/control/fixtures", "/api/v1/control/identity/authenticate", "/api/v1/control/identity/trust", "/api/v1/control/risk/evaluate"):
        operation = schema["paths"][path]["post"]
        assert operation["summary"] and operation["description"]
        assert operation["responses"]["200"]["content"]["application/json"]["schema"]
    response = client.post("/api/v1/control/identity/trust", json={"subjectId": "NEVER_REFLECT_BODY", "credentialId": "NEVER_REFLECT_BODY"})
    assert response.status_code == 422 and "NEVER_REFLECT_BODY" not in response.text
