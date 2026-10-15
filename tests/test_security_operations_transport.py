import json
import logging
import socket
import threading
import time
from urllib.parse import urlsplit

import httpx
import pytest
import uvicorn
from fastapi import FastAPI

from app.security_operations.catalog import SOC_TOOLS
from app.security_operations.router import create_router
from app.security_operations.state import reset_state
from app.security_operations.transport import lifespan, mount_mcp


@pytest.fixture(scope="module")
def service_url():
    app = FastAPI(lifespan=lifespan)
    app.include_router(create_router())
    mount_mcp(app)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", access_log=False))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert server.started, "隔离测试服务未能启动。"
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        listener.close()
        assert not thread.is_alive(), "隔离测试服务未能停止。"


@pytest.fixture(autouse=True)
def clean_state():
    reset_state()


def rpc(service_url, group, method, params=None):
    response = httpx.post(
        f"{service_url}/mcp/{group}/",
        headers={
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2025-11-25",
        },
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
        timeout=10,
    )
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.parametrize(
    ("group", "count"),
    [("sec-ops", 15), ("inspection", 3), ("policy-configuration", 7), ("emergency-action", 6), ("report", 1)],
)
def test_each_mcp_group_initializes_and_discovers(service_url, group, count):
    response = rpc(
        service_url,
        group,
        "initialize",
        {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "mock-service-test", "version": "1.0"},
        },
    )
    assert response["result"]["protocolVersion"] == "2025-11-25"
    initialized = httpx.post(
        f"{service_url}/mcp/{group}/",
        headers={"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-11-25"},
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
    )
    assert initialized.status_code == 202
    tools = rpc(service_url, group, "tools/list")["result"]["tools"]
    assert len(tools) == count
    assert len({tool["name"] for tool in tools}) == count
    assert all(tool["inputSchema"]["type"] == "object" for tool in tools)
    assert rpc(service_url, group, "resources/list")["result"]["resources"] == []
    assert rpc(service_url, group, "resources/templates/list")["result"]["resourceTemplates"] == []


def test_mcp_text_and_structured_results_match(service_url):
    result = rpc(service_url, "sec-ops", "tools/call", {"name": "list_soc_asset", "arguments": {}})["result"]
    assert not result["isError"]
    payload = json.loads(result["content"][0]["text"])
    assert payload == result["structuredContent"]
    assert payload["code"] == 200
    assert payload["data"]


def test_policy_endpoint_tools_execute_over_real_mcp_transport(service_url):
    body = {"contract_version": "workbench-policy-endpoint-resolution/v1", "request_id": "mcp-basic-endpoints",
            "operation": "ADD", "action": "ALLOW", "source_query": "服务器", "destination_query": "mock-db",
            "protocol": "TCP", "destination_port": 443, "device_query": "测试防火墙"}

    def call(name, body):
        result = rpc(service_url, "policy-configuration", "tools/call", {"name": name, "arguments": {"body": body}})["result"]
        assert result["isError"] is False
        assert json.loads(result["content"][0]["text"]) == result["structuredContent"]
        assert result["structuredContent"]["code"] == "200"
        return result["structuredContent"]["data"]

    resolution = call("resolve_policy_endpoints", body)
    assert resolution["resolution_status"] == "SELECTION_REQUIRED"
    selected = call("choose_ambiguous_policy_endpoints", {**body,
        "candidate_set_digest": resolution["candidate_set_digest"],
        "selected_source_candidate_id": resolution["source"]["candidates"][0]["candidate_id"],
        "selected_destination_candidate_id": resolution["destination"]["selected_candidate_id"]})
    operation = call("prepare_policy_configuration", selected["prepare_body"])
    assert operation["task_status"] == "DRAFT"
    assert operation["version"] == 1
    assert operation["confirmation_expires_at"]


def test_unknown_mcp_tool_does_not_echo_input(service_url, caplog):
    caplog.set_level(logging.DEBUG)
    result = rpc(
        service_url,
        "inspection",
        "tools/call",
        {"name": "unknown-basic-input-marker", "arguments": {"value": "unreturned-basic-marker"}},
    )["result"]
    assert result["isError"] is True
    assert json.loads(result["content"][0]["text"]) == result["structuredContent"]
    assert "unknown-basic-input-marker" not in json.dumps(result)
    assert "unreturned-basic-marker" not in json.dumps(result)
    assert "unknown-basic-input-marker" not in caplog.text
    assert "unreturned-basic-marker" not in caplog.text


@pytest.mark.parametrize(
    "payload",
    [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_soc_asset", "arguments": "neutral-validation-marker"}},
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": ["neutral-validation-marker"]}},
        {"jsonrpc": "2.0", "id": 1, "method": ["neutral-validation-marker"]},
        {"jsonrpc": "2.0", "id": 1, "method": "neutral-validation-marker"},
    ],
)
def test_sdk_protocol_errors_do_not_echo_input(service_url, payload, caplog):
    caplog.set_level(logging.DEBUG)
    response = httpx.post(
        f"{service_url}/mcp/sec-ops/",
        headers={"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-11-25"},
        json=payload,
    )
    assert response.status_code in (200, 400)
    assert response.json()["error"]["code"] < 0
    assert "neutral-validation-marker" not in response.text
    assert "neutral-validation-marker" not in caplog.text


def test_soc_openapi_describes_real_fixed_gateway_routes(service_url):
    response = httpx.get(f"{service_url}/api/v1/security-operations/openapi.json")
    assert response.status_code == 200
    spec = response.json()
    assert spec["servers"] == [{"url": "/"}]
    assert len(spec["paths"]) == 19
    assert {item["post"]["operationId"] for item in spec["paths"].values()} == set(SOC_TOOLS)
    name = "ai_soc_master__get_soc_asset_by_asset_id"
    path = f"/api/v1/mcp-resources/{SOC_TOOLS[name]['resource_id']}/tools/{name}/invoke"
    operation = spec["paths"][path]["post"]
    schema = operation["requestBody"]["content"]["application/json"]["schema"]
    assert "arguments" in schema["properties"]
    result = httpx.post(f"{service_url}{path}", json={"arguments": {"assetId": 9106}})
    assert result.status_code == 200
    payload = result.json()
    assert payload["status"] == "success"
    assert payload["status_code"] == payload["result"]["code"] == 200
    assert payload["result"]["data"]["assetId"] == 9106


def test_report_mcp_returns_real_download_from_same_record(service_url):
    arguments = {
        "businessId": "mock-run",
        "sourceModule": "threat-analysis",
        "revision": 1,
        "resultType": "report",
        "contentType": "text/html",
        "fileName": "report.html",
        "fileContentBase64": "PGgxPk9LPC9oMT4=",
    }
    result = rpc(service_url, "report", "tools/call", {"name": "save_persistence_result", "arguments": arguments})["result"]
    assert not result["isError"]
    data = json.loads(result["content"][0]["text"])["data"]
    assert data["id"]
    assert urlsplit(data["downloadUrl"]).netloc == urlsplit(service_url).netloc
    download = httpx.get(data["downloadUrl"])
    assert download.status_code == 200
    assert download.headers["content-type"].startswith("text/html")
    assert "<html" in download.text
    assert "PGgxPk9LPC9oMT4=" not in download.text
    assert httpx.get(f"{service_url}/reports/unknown-basic-record.html").status_code == 404


def test_http_errors_do_not_reflect_invalid_body(service_url):
    name = "ai_soc_master__get_soc_asset_by_asset_id"
    path = f"/api/v1/mcp-resources/{SOC_TOOLS[name]['resource_id']}/tools/{name}/invoke"
    response = httpx.post(f"{service_url}{path}", json={"arguments": "basic-invalid-input-marker"})
    assert response.status_code == 422
    assert "basic-invalid-input-marker" not in response.text
    no_args_name = "ai_soc_detect__list_detect_whitelist"
    no_args_path = f"/api/v1/mcp-resources/{SOC_TOOLS[no_args_name]['resource_id']}/tools/{no_args_name}/invoke"
    response = httpx.post(f"{service_url}{no_args_path}", json={})
    assert response.status_code == 422
    assert response.json() == {"detail": "arguments 必须是 JSON 对象。"}
    response = httpx.post(
        f"{service_url}/api/v1/emergency-actions/unknown-basic-operation/confirmations",
        content="basic-invalid-json-marker",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert "basic-invalid-json-marker" not in response.text
    assert httpx.get(f"{service_url}/api/v1/emergency-actions/unknown-basic-operation/result").status_code == 404
