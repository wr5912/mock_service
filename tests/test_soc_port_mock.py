import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import time
from urllib.request import urlopen

import pytest
from fastapi.testclient import TestClient

from app.soc_port_mock import SERVICE_PORTS, SERVICE_SUMMARIES, COMPOSITION_INPUTS, _path_for, _service_tools, create_app
from scripts.render_local_mcp_manager import render

UNSAFE_TERMS = re.compile(r"攻击|渗透|恶意代码|攻击载荷|malware|exploit|payload|penetration", re.I)


@pytest.mark.parametrize("service_id", sorted(SERVICE_PORTS))
def test_each_port_service_exposes_health_and_openapi(service_id: str) -> None:
    with TestClient(create_app(service_id)) as client:
        health = client.get("/health")
        spec_response = client.get("/v3/api-docs/mcp")

    assert health.status_code == 200
    assert health.json() == {
        "status": "ok",
        "service": service_id,
        "port": SERVICE_PORTS[service_id],
        "simulated": True,
    }
    assert spec_response.status_code == 200
    spec = spec_response.json()
    assert spec["info"]["title"].startswith(service_id)
    assert spec["servers"] == [{"url": "http://testserver"}]
    assert spec["paths"]
    assert SERVICE_SUMMARIES[service_id] in spec["info"]["description"]
    assert not UNSAFE_TERMS.search(json.dumps(spec, ensure_ascii=False))


@pytest.mark.parametrize("service_id", sorted(SERVICE_PORTS))
def test_each_port_service_supports_mcp_discovery_and_safe_call(service_id: str) -> None:
    with TestClient(create_app(service_id)) as client:
        headers = {"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-11-25"}
        initialized = client.post(
            "/mcp/",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "mock", "version": "1"}},
            },
        )
        tools = client.post("/mcp/", headers=headers, json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        name = tools.json()["result"]["tools"][0]["name"]
        called = client.post("/mcp/", headers=headers, json={"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": name, "arguments": {"marker": "must-not-echo"}}})

    assert initialized.status_code == 200
    assert tools.status_code == 200
    assert tools.json()["result"]["tools"]
    assert called.status_code == 200
    payload = called.json()["result"]["structuredContent"]
    assert payload["simulated"] is True
    assert payload["sideEffect"] is False
    assert "must-not-echo" not in json.dumps(called.json(), ensure_ascii=False)
    assert not UNSAFE_TERMS.search(called.text)


def test_openapi_operation_returns_fixed_safe_content() -> None:
    with TestClient(create_app("ai-soc-master")) as client:
        response = client.get("/soc/asset/9106")

    assert response.status_code == 200
    body = response.json()
    assert body["simulated"] is True
    assert body["sideEffect"] is False
    assert "must-not-echo" not in json.dumps(body, ensure_ascii=False)


@pytest.mark.parametrize("service_id,operation", [
    ("ai-soc-graph", "get_graph_resolve_ip_host"),
    ("ai-soc-graph", "search_graph_assets"),
    ("ai-soc-graph", "get_graph_path_query"),
    ("ai-soc-ingest", "get_admin_baseline_report_latest"),
    ("ai-soc-ingest", "preview_admin_dispatch_task"),
    ("ai-soc-ingest", "create_admin_dispatch_task"),
    ("ai-soc-ingest", "precheck_admin_dispatch_task"),
    ("ai-soc-ingest", "submit_admin_dispatch_task"),
    ("ai-soc-ingest", "execute_admin_dispatch_task"),
    ("ai-soc-ingest", "rollback_admin_dispatch_task"),
    ("ai-soc-master", "list_soc_asset"),
    ("ai-soc-master", "get_soc_asset_source_identities_resolve"),
    ("ai-soc-master", "create_soc_asset_probe"),
    ("ai-soc-master", "create_soc_discovery_identify"),
    ("ai-soc-master", "create_soc_discovery_tasks"),
    ("ai-soc-master", "start_soc_discovery_tasks"),
    ("ai-soc-master", "create_soc_discovery_tasks_adopt"),
    ("ai-soc-master", "create_soc_asset"),
    ("ai-soc-response", "execute_resp_agent_actions"),
])
def test_manager_operation_ids_are_available_in_each_local_service(service_id: str, operation: str) -> None:
    names = {name for name, _ in _service_tools(service_id)}
    assert operation in names


def test_local_manager_render_replaces_only_ip(tmp_path: Path) -> None:
    source = tmp_path / "manager.json"
    output = tmp_path / "local" / "manager.json"
    source.write_text(json.dumps({"servers": [{"specUrl": "http://172.16.138.223:18085/v3/api-docs/mcp"}], "groups": [{"members": [{"resourceUris": ["http://172.16.138.223:18085/x"]}]}]}))

    render(source, output)
    value = json.loads(output.read_text())
    assert value["servers"][0]["specUrl"] == "http://127.0.0.1:18085/v3/api-docs/mcp"
    assert value["groups"][0]["members"][0]["resourceUris"][0] == "http://127.0.0.1:18085/x"


def mcp_call(client: TestClient, operation: str, arguments: dict) -> dict:
    response = client.post("/mcp/", headers={"Accept": "application/json, text/event-stream"}, json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": operation, "arguments": arguments},
    })
    assert response.status_code == 200
    return response.json()["result"]


@pytest.mark.parametrize("service_id", sorted(COMPOSITION_INPUTS))
def test_current_composition_operations_publish_their_real_parameter_schema(service_id: str) -> None:
    with TestClient(create_app(service_id)) as client:
        spec = client.get("/v3/api-docs/mcp").json()
    definitions = dict(_service_tools(service_id))
    for operation, schema in COMPOSITION_INPUTS[service_id].items():
        def without_examples(value):
            if isinstance(value, list):
                return [without_examples(item) for item in value]
            if isinstance(value, dict):
                return {key: without_examples(item) for key, item in value.items() if key != "example"}
            return value
        assert without_examples(definitions[operation]["inputSchema"]) == schema
        route = spec["paths"][_path_for(operation, service_id)]
        published = next(value for value in route.values() if value["operationId"] == operation)
        names = {item["name"] for item in published["parameters"]}
        assert names == set(schema["properties"]) - {"body"}
        assert ("requestBody" in published) == ("body" in schema["properties"])


def test_asset_detail_list_filter_and_unknown_identity_use_distinct_contracts() -> None:
    with TestClient(create_app("ai-soc-master")) as client:
        detail = client.get("/soc/asset/9106").json()
        listed = client.get("/soc/asset/list", params={"ip": "192.0.2.10", "pageNum": 1, "includeUnits": "true"}).json()
        following_page = client.get("/soc/asset/list", params={"pageNum": 2}).json()
        empty = client.get("/soc/asset/list", params={"ip": "198.51.100.99"}).json()
        missing = client.get("/soc/asset/9999")
        wrong_suffix = client.get("/soc/asset/9106/not-a-tool")
    assert detail["code"] == 200
    assert detail["data"]["assetId"] == 9106
    assert detail["data"]["online"] == "online"
    assert detail["data"]["stateEvidence"]["signals"][0]["observedAt"].endswith("Z")
    assert listed["total"] == 1
    assert [item["assetId"] for item in listed["data"]["rows"]] == [9106]
    assert following_page["total"] == 2 and following_page["data"]["rows"] == []
    assert empty["total"] == 0 and empty["data"]["rows"] == []
    assert missing.status_code == wrong_suffix.status_code == 404


def test_http_templates_keep_static_routes_specific_and_enforce_methods() -> None:
    with TestClient(create_app("ai-soc-response")) as client:
        definitions = client.get("/resp/action-defs")
        definition = client.get("/resp/action-defs/mock-action")
        candidates = client.get("/resp/actions/mock-action/target-candidates")
        unknown_action = client.get("/resp/actions/not-a-fixture/target-candidates")
        wrong_method = client.post("/resp/action-defs", json={})
    assert definitions.status_code == definition.status_code == candidates.status_code == 200
    assert definitions.json()["data"]["rows"][0]["actionKey"] == "mock-action"
    assert definition.json()["data"]["inputSchema"]["properties"]["note"] == {"type": "string"}
    assert candidates.json()["data"]["rows"][0]["deviceId"] == "mock-device-01"
    assert unknown_action.status_code == 404
    assert wrong_method.status_code == 405


def test_baseline_and_existing_observations_preserve_identity_and_list_shape() -> None:
    with TestClient(create_app("ai-soc-ingest")) as client:
        report = client.get("/admin/ingest/baseline/report/latest", params={"assetId": 9106, "includeChildren": "false"}).json()["data"]
        readiness = client.get("/admin/ingest/baseline/readiness", params={"assetId": 9106}).json()["data"]
        binding = client.get("/admin/ingest/devices/by-asset/9106").json()["data"]["rows"]
        missing = client.get("/admin/ingest/baseline/readiness", params={"assetId": 9999})
    assert report["run"]["assetId"] == readiness["assetId"] == binding[0]["assetId"] == 9106
    assert report["templateId"] == readiness["templateId"]
    assert report["run"]["passFlag"] == "1"
    assert readiness["templateScopeMatched"] is True
    assert readiness["memberCount"] == readiness["applicableCount"] == len(readiness["items"]) == 1
    assert readiness["items"][0]["applicabilityReason"] == "MATCHED"
    assert missing.status_code == 404
    with TestClient(create_app("ai-soc-master")) as client:
        for path in ["registration-children", "vulnerabilities", "online-transitions"]:
            result = client.get(f"/soc/asset/9106/{path}").json()
            assert result["data"] == {"rows": [], "total": 0}


def test_graph_rules_path_and_acl_form_consistent_fixed_evidence() -> None:
    with TestClient(create_app("ai-soc-graph")) as client:
        rule = client.get("/graph/compliance/rules").json()["data"]["rows"][0]
        pair = {"srcIp": "192.0.2.10", "dstIp": "192.0.2.20", "port": 443, "protocol": "tcp"}
        path = client.get("/reachability/path/by-ip", params=pair).json()["data"]
        query = client.get("/graph/path/query", params=pair).json()["data"]
        acl = client.get("/reachability/acl-hit", params={**pair, "devices": "9201"}).json()["data"]
        unknown = client.get("/graph/path/query", params={"srcIp": "198.51.100.1", "dstIp": "198.51.100.2"})
    assert rule["enabled"] is True and rule["ruleType"] == "REQUIRED"
    assert path["reachable"] is True and path["verdict"] == "REACHABLE"
    assert path["natApplied"] is False and path["routeOnlyPath"] == [acl["hops"][0]["deviceId"]]
    assert acl["hops"][0]["verdict"] == "PERMIT"
    assert query["diagnosis"]["sourceIp"] == pair["srcIp"]
    assert query["diagnosis"]["targetIp"] == pair["dstIp"]
    assert query["diagnosis"]["portEvaluated"] is True
    assert unknown.status_code == 404


def test_policy_discovery_and_preview_keep_body_without_echoing_its_content() -> None:
    with TestClient(create_app("ai-soc-ingest")) as client:
        devices = client.get("/admin/ingest/dispatch/dispatchable-devices", params={"configKind": "ACL"}).json()["data"]["rows"]
        query = {"deviceId": devices[0]["deviceId"], "configKind": "ACL", "operation": "ADD"}
        configs = client.get("/admin/dispatch/task/policy-configs", params=query).json()["data"]["rows"]
        fields = client.get("/admin/dispatch/task/input-fields", params={**query, "policyConfigKey": "mock-policy"}).json()["data"]["rows"]
        response = client.post("/admin/dispatch/task/preview", json={**query, "policyConfigKey": "mock-policy", "payload": {"note": "must-not-echo"}})
        missing = client.post("/admin/dispatch/task/preview", json={"deviceId": "not-a-fixture", "note": "must-not-echo"})
    assert configs[0]["value"] == "mock-policy" and configs[0]["inputMode"] == "PARAMETERS"
    assert fields == [{"fieldName": "note", "required": False, "type": "string"}]
    assert response.status_code == 200
    assert response.json()["data"]["success"] is response.json()["data"]["online"] is True
    assert response.json()["data"]["precheck"]["blocked"] is False
    assert "must-not-echo" not in response.text + missing.text
    assert missing.status_code == 404


def test_alert_snapshot_is_complete_empty_and_does_not_reflect_request_fields() -> None:
    query = {"req": json.dumps({"assetId": "9106", "from": "2026-11-15T00:00:00Z", "to": "2026-11-15T01:00:00Z", "pageNum": 1, "pageSize": 100})}
    with TestClient(create_app("ai-soc-detect")) as client:
        response = client.get("/detect/alert/list", params=query)
        exploded = client.get("/detect/alert/list", params=json.loads(query["req"]))
        malformed = client.get("/detect/alert/list", params={"req": "must-not-echo"})
        spec = client.get("/v3/api-docs/mcp").json()
    assert response.status_code == 200
    assert exploded.status_code == 200 and exploded.json() == response.json()
    req = spec["paths"]["/detect/alert/list"]["get"]["parameters"][0]
    assert req["name"] == "req" and req["style"] == "form" and req["explode"] is True
    snapshot = response.json()["data"]
    assert snapshot["groups"] == [] and snapshot["totalGroups"] == snapshot["totalAlerts"] == 0
    assert snapshot["truncated"] is False and snapshot["snapshotId"] and snapshot["asOf"].endswith("Z")
    assert malformed.status_code == 400 and "must-not-echo" not in malformed.text


@pytest.mark.parametrize("service_id,operation,path,arguments", [
    ("ai-soc-master", "get_soc_asset_by_asset_id", "/soc/asset/9106", {"assetId": 9106}),
    ("ai-soc-ingest", "get_admin_baseline_readiness", "/admin/ingest/baseline/readiness?assetId=9106", {"assetId": 9106}),
    ("ai-soc-response", "get_resp_actions_target_candidates", "/resp/actions/mock-action/target-candidates", {"actionKey": "mock-action"}),
])
def test_mcp_and_http_share_the_same_fixed_business_result(service_id: str, operation: str, path: str, arguments: dict) -> None:
    with TestClient(create_app(service_id)) as client:
        http = client.get(path).json()
        mcp = mcp_call(client, operation, arguments)
        invalid = mcp_call(client, operation, {"marker": "must-not-echo"})
    assert mcp["structuredContent"] == http
    assert mcp["isError"] is False
    assert invalid["isError"] is True
    assert invalid["structuredContent"]["code"] == 400
    assert invalid["structuredContent"]["simulated"] is True and invalid["structuredContent"]["sideEffect"] is False
    assert "must-not-echo" not in json.dumps(invalid)


def test_asset_list_query_template_matches_current_group_field_order() -> None:
    expected = [
        "pageNum", "pageSize", "ip", "hostname", "keyword", "source", "layerId", "excludeLayerId",
        "online", "assetType", "vendor", "status", "techStatus", "deptId", "sortField", "sortOrder",
        "collectionStatus", "collectAnomaly", "modelIds", "includeUnits", "assetView", "rootOnly",
        "hostAssetId", "bizIds", "bizAssociation",
    ]
    with TestClient(create_app("ai-soc-master")) as client:
        spec = client.get("/v3/api-docs/mcp").json()
    operation = spec["paths"]["/soc/asset/list"]["get"]
    assert operation["operationId"] == "list_soc_asset"
    assert [parameter["name"] for parameter in operation["parameters"]] == expected
    assert all(parameter["in"] == "query" for parameter in operation["parameters"])
    assert list(dict(_service_tools("ai-soc-master"))["list_soc_asset"]["inputSchema"]["properties"]) == expected


@pytest.mark.parametrize("operation,suffix", [
    ("get_soc_discovery_tasks_by_task_id", ""),
    ("get_soc_discovery_tasks_scope", "/scope"),
])
def test_discovery_task_resources_are_readonly_exact_templates(operation: str, suffix: str) -> None:
    with TestClient(create_app("ai-soc-master")) as client:
        spec = client.get("/v3/api-docs/mcp").json()
        http = client.get(f"/soc/discovery/tasks/8001{suffix}")
        mcp = mcp_call(client, operation, {"taskId": "8001"})
        unknown = client.get(f"/soc/discovery/tasks/must-not-echo{suffix}")
        extra_path = client.get(f"/soc/discovery/tasks/8001{suffix}/unknown")
        wrong_method = client.post(f"/soc/discovery/tasks/8001{suffix}", json={})
        missing_argument = mcp_call(client, operation, {})
    declaration = spec["paths"][f"/soc/discovery/tasks/{{taskId}}{suffix}"]
    assert list(declaration) == ["get"]
    assert declaration["get"]["operationId"] == operation
    assert declaration["get"]["parameters"] == [{"name": "taskId", "in": "path", "required": True, "schema": {"type": "string", "example": "8001"}}]
    assert http.status_code == 200 and mcp["isError"] is False
    assert http.json() == mcp["structuredContent"]
    assert http.json()["simulated"] is True and http.json()["sideEffect"] is False
    assert unknown.status_code == extra_path.status_code == 404
    assert "must-not-echo" not in unknown.text
    assert wrong_method.status_code == 405
    assert missing_argument["isError"] is True and missing_argument["structuredContent"]["code"] == 400
    identity = http.json()["data"].get("task", http.json()["data"])
    assert identity["taskId"] == "8001"



def declared_sample(schema: dict) -> object:
    if "default" in schema:
        return schema["default"]
    if "example" in schema:
        return schema["example"]
    if schema.get("examples"):
        return schema["examples"][0]
    if schema.get("enum"):
        return schema["enum"][0]
    if schema.get("anyOf"):
        branch = schema["anyOf"][0]
        schema = {**schema, **branch, "required": [*schema.get("required", []), *branch.get("required", [])]}
    properties = schema.get("properties", {})
    if schema.get("type") == "object" or properties:
        return {key: declared_sample(value) for key, value in properties.items()
                if key in schema.get("required", []) or "example" in value or "default" in value}
    if schema.get("type") == "array":
        return [declared_sample(schema.get("items", {})) for _ in range(schema.get("minItems", 0))]
    return None


@pytest.mark.parametrize("service_id", sorted(SERVICE_PORTS))
def test_all_published_fixed_samples_call_native_tools_and_http_operations(service_id: str) -> None:
    from urllib.parse import quote

    with TestClient(create_app(service_id)) as client:
        for operation, definition in _service_tools(service_id):
            arguments = declared_sample(definition["inputSchema"])
            result = mcp_call(client, operation, arguments)
            assert result.get("isError") is False, (operation, result)
            assert result["structuredContent"]["simulated"] is True
            assert result["structuredContent"]["sideEffect"] is False
        spec = client.get("/v3/api-docs/mcp").json()
        for template, methods in spec["paths"].items():
            for method, operation in methods.items():
                path = template
                query = {}
                for parameter in operation["parameters"]:
                    value = declared_sample(parameter["schema"])
                    if parameter["in"] == "path":
                        path = path.replace("{" + parameter["name"] + "}", quote(str(value), safe=""))
                    elif value is not None:
                        query[parameter["name"]] = json.dumps(value) if isinstance(value, (dict, list)) else value
                options = {"params": query}
                if "requestBody" in operation:
                    options["json"] = declared_sample(operation["requestBody"]["content"]["application/json"]["schema"])
                response = client.request(method, path, **options)
                assert response.status_code == 200, (operation["operationId"], response.text)
                assert response.json()["simulated"] is True
                assert response.json()["sideEffect"] is False


@pytest.mark.parametrize("service_id,operation,valid,unknown", [
    ("ai-soc-master", "get_soc_asset_by_asset_id", {"assetId": 9106}, {"assetId": 9999}),
    ("ai-soc-ingest", "get_admin_ingest_devices_run_state", {"deviceId": "mock-device-01"}, {"deviceId": "unknown-device"}),
    ("ai-soc-ingest", "preview_admin_dispatch_task", {"body": {"deviceId": "mock-device-01"}}, {"body": {"deviceId": "unknown-device"}}),
    ("ai-soc-ingest", "get_admin_dispatch_task_by_id", {"id": "7001"}, {"id": "9999"}),
    ("ai-soc-master", "get_soc_discovery_tasks_by_task_id", {"taskId": "8001"}, {"taskId": "9999"}),
    ("ai-soc-response", "get_resp_action_def", {"actionKey": "mock-action"}, {"actionKey": "unknown-action"}),
    ("ai-soc-graph", "get_graph_path_query", {"srcIp": "192.0.2.10", "dstIp": "192.0.2.20"}, {"srcIp": "198.51.100.10", "dstIp": "198.51.100.20"}),
])
def test_fixed_examples_do_not_make_unknown_identities_succeed(service_id, operation, valid, unknown) -> None:
    with TestClient(create_app(service_id)) as client:
        good = mcp_call(client, operation, valid)
        bad = mcp_call(client, operation, unknown)
    assert good["isError"] is False
    assert bad["isError"] is True
    assert bad["structuredContent"]["code"] == 404
    assert bad["structuredContent"]["simulated"] is True
    assert bad["structuredContent"]["sideEffect"] is False
    for value in unknown.values():
        if isinstance(value, str):
            assert value not in json.dumps(bad)


def test_dispatch_optional_body_has_same_native_and_http_contract() -> None:
    with TestClient(create_app("ai-soc-ingest")) as client:
        native = mcp_call(client, "submit_admin_dispatch_task", {"id": "7001"})
        http = client.post("/admin/dispatch/task/7001/submit")
        required = client.post("/admin/dispatch/task/preview")
    assert native["isError"] is False
    assert http.status_code == 200
    assert http.json() == native["structuredContent"]
    assert required.status_code == 400


@pytest.mark.parametrize("origin", ["http://127.0.0.1:28087", "http://localhost:38087", "https://mock.example.test:4443"])
@pytest.mark.parametrize("prefix", ["", "/uat/services"])
def test_openapi_uses_actual_request_origin_and_mount_prefix_without_changing_business(origin: str, prefix: str) -> None:
    from fastapi import FastAPI

    master = create_app("ai-soc-master")
    application = master
    if prefix:
        application = FastAPI()
        application.mount(prefix, master)
    with TestClient(create_app("ai-soc-master")) as original, TestClient(application, base_url=origin) as deployed:
        baseline_spec = original.get("/v3/api-docs/mcp").json()
        current_spec = deployed.get(prefix + "/v3/api-docs/mcp").json()
        assert current_spec["servers"] == [{"url": origin + prefix}]
        assert current_spec["paths"] == baseline_spec["paths"]
        assert current_spec["info"] == baseline_spec["info"]
        for path in ["/soc/asset/9106", "/soc/asset/1"]:
            baseline = original.get(path)
            current = deployed.get(prefix + path)
            assert current.status_code == baseline.status_code
            assert current.json() == baseline.json()


def test_mounted_service_keeps_public_discovery_and_fixed_credential_contract(monkeypatch) -> None:
    from fastapi import FastAPI

    monkeypatch.setenv("SOC_MOCK_API_KEY", "local-contract-key")
    application = FastAPI()
    application.mount("/uat/services", create_app("ai-soc-master"))
    with TestClient(application, base_url="http://localhost:28087") as client:
        health = client.get("/uat/services/health")
        spec = client.get("/uat/services/v3/api-docs/mcp")
        assert health.status_code == 200
        assert health.json()["service"] == "ai-soc-master"
        assert spec.status_code == 200
        assert spec.json()["servers"] == [{"url": "http://localhost:28087/uat/services"}]
        for headers in [{}, {"X-API-Key": "wrong-key"}]:
            response = client.get("/uat/services/soc/asset/9106", headers=headers)
            assert response.status_code == 401
            assert response.json() == {"detail": "本地模拟凭据无效"}
        valid_headers = {"X-API-Key": "local-contract-key"}
        known = client.get("/uat/services/soc/asset/9106", headers=valid_headers)
        unknown = client.get("/uat/services/soc/asset/1", headers=valid_headers)
        assert known.status_code == 200
        assert known.json()["simulated"] is True
        assert known.json()["sideEffect"] is False
        assert unknown.status_code == 404
        assert unknown.json()["simulated"] is True
        assert unknown.json()["sideEffect"] is False


@pytest.fixture
def owned_soc_process(tmp_path: Path):
    root = Path(__file__).resolve().parents[1]
    local = tmp_path / "mock service"
    (local / "scripts").mkdir(parents=True)
    (local / ".local/soc-mocks").mkdir(parents=True)
    (local / ".venv").symlink_to(root / ".venv", target_is_directory=True)
    shutil.copyfile(root / "scripts/stop_soc_mcp_mocks.sh", local / "scripts/stop_soc_mcp_mocks.sh")
    shutil.copyfile(root / "scripts/soc_mcp_mock_common.sh", local / "scripts/soc_mcp_mock_common.sh")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    service = "ai-soc-master"
    environment = {**os.environ, "PYTHONPATH": str(root), "SOC_MOCK_SERVICE_ID": service, "SOC_MOCK_API_KEY": ""}
    arguments = [str(local / ".venv/bin/python"), "-m", "uvicorn", "app.soc_port_mock:app", "--host", "127.0.0.1", "--port", str(port), "--no-access-log"]
    process = subprocess.Popen(arguments, cwd=local, env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 10
        while True:
            assert process.poll() is None, "专用 Mock 启动失败"
            try:
                with urlopen(f"http://127.0.0.1:{port}/health", timeout=0.2) as response:
                    if response.status == 200:
                        break
            except OSError:
                assert time.monotonic() < deadline, "专用 Mock 未及时监听"
                time.sleep(0.05)
        stat = Path(f"/proc/{process.pid}/stat").read_text().rsplit(") ", 1)[1].split()
        start = stat[19]
        record = local / ".local/soc-mocks" / f"{service}.pid"
        record.write_text(f"{process.pid} {start} {port}\n")
        yield local, process, record, start, port
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def test_stop_script_terminates_only_matching_mock_process_and_listener(owned_soc_process) -> None:
    local, process, record, _start, _port = owned_soc_process
    stopped = subprocess.run(["bash", "scripts/stop_soc_mcp_mocks.sh"], cwd=local, text=True, capture_output=True, timeout=15)
    assert stopped.returncode == 0, stopped.stderr
    process.wait(timeout=5)
    assert "stopped ai-soc-master" in stopped.stdout
    assert not record.exists()


@pytest.mark.parametrize("mismatch", ["start", "port", "legacy"])
def test_stop_script_does_not_signal_unconfirmed_process_or_erase_its_record(owned_soc_process, mismatch: str) -> None:
    local, process, record, start, port = owned_soc_process
    original = f"{process.pid}\n" if mismatch == "legacy" else f"{process.pid} {int(start) + 1 if mismatch == 'start' else start} {port + 1 if mismatch == 'port' else port}\n"
    record.write_text(original)
    stopped = subprocess.run(["bash", "scripts/stop_soc_mcp_mocks.sh"], cwd=local, text=True, capture_output=True, timeout=10)
    assert stopped.returncode == 0
    assert "无法确认" in stopped.stderr
    assert process.poll() is None
    assert record.read_text() == original
    with urlopen(f"http://127.0.0.1:{port}/health", timeout=1) as response:
        assert response.status == 200
