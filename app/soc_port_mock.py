"""8 个 SOC OpenAPI/MCP 服务的本地无害模拟入口。

每个进程由 ``SOC_MOCK_SERVICE_ID`` 选择服务，使用原服务端口监听在
127.0.0.1。接口只返回固定测试数据，不连接外部系统，也不执行真实动作。
"""
from __future__ import annotations

from contextlib import AsyncExitStack, asynccontextmanager
from copy import deepcopy
import json
import os
import re
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from mcp.server import Server, ServerRequestContext
from mcp.server.transport_security import TransportSecuritySettings
import mcp.types as types

from app.security_operations.catalog import SOC_TOOLS


SERVICE_PORTS = {
    "ai-soc-framework": 18080,
    "ai-soc-ingest": 18081,
    "ai-soc-response": 18083,
    "ai-soc-detect": 18084,
    "ai-soc-correlate": 18085,
    "ai-soc-master": 18087,
    "ai-soc-graph": 18088,
    "ai-soc-event": 8083,
}

SERVICE_SUMMARIES = {
    "ai-soc-correlate": "关联记录与信息查询的本地固定模拟服务。",
    "ai-soc-detect": "检测记录和白名单查询的本地固定模拟服务。",
    "ai-soc-event": "事件检索和统计查询的本地固定模拟服务。",
    "ai-soc-graph": "资产关系和连接状态查询的本地固定模拟服务。",
    "ai-soc-ingest": "采集器与设备绑定查询的本地固定模拟服务。",
    "ai-soc-master": "资产与业务系统基础信息查询的本地固定模拟服务。",
    "ai-soc-response": "响应动作定义和测试状态查询的本地固定模拟服务。",
    "ai-soc-framework": "流程待办和审批状态查询的本地固定模拟服务。",
}

GENERIC_TOOLS = {
    "ai-soc-graph": [
        "get_graph_resolve_ip_host",
        "search_graph_assets",
        "get_graph_path_query",
        "get_graph_composed",
        "get_graph_coverage",
        "get_graph_node_detail",
    ],
    "ai-soc-ingest": [
        "get_admin_baseline_report_latest",
        "preview_admin_dispatch_task",
        "create_admin_dispatch_task",
        "precheck_admin_dispatch_task",
        "submit_admin_dispatch_task",
        "execute_admin_dispatch_task",
        "rollback_admin_dispatch_task",
        "list_admin_dispatch_dispatchable_devices",
    ],
    "ai-soc-master": [
        "list_soc_asset",
        "get_soc_asset_source_identities_resolve",
        "create_soc_asset_probe",
        "create_soc_discovery_identify",
        "create_soc_discovery_tasks",
        "start_soc_discovery_tasks",
        "create_soc_discovery_tasks_adopt",
        "create_soc_asset",
    ],
    "ai-soc-response": [
        "list_resp_action_defs",
        "get_resp_action_def",
        "get_resp_actions_device_agents",
        "list_resp_action_executions",
        "get_resp_action_execution",
        "execute_resp_agent_actions",
        "get_resp_actions_by_workflow_tracking",
        "recommend_resp_actions",
        "get_resp_actions_target_candidates",
        "list_resp_agent_actions_executions",
    ],
    "ai-soc-framework": [
        "list_framework_todos",
        "get_framework_todo",
        "get_framework_approval_status",
    ],
}

SAFE_OPERATION_WORDS = re.compile(r"^(?:create|update|claim|fail|execute|start|submit|prepare|confirm|cancel|revise|preview|precheck|rollback)_", re.I)


def _schema(properties: dict[str, Any], required: tuple[str, ...] = ()) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": list(required), "additionalProperties": False}


TEXT = {"type": "string"}
INTEGER = {"type": "integer"}
BOOLEAN = {"type": "boolean"}
OBJECT = {"type": "object"}
ASSET_INPUT = _schema({"assetId": INTEGER}, ("assetId",))
DEVICE_INPUT = _schema({"deviceId": TEXT}, ("deviceId",))
PAIR_INPUT = {"srcIp": TEXT, "dstIp": TEXT, "port": INTEGER, "protocol": TEXT}
DISPATCH_INPUT = {"deviceId": TEXT, "configKind": TEXT, "operation": TEXT, "policyConfigKey": TEXT}
ALERT_QUERY = _schema({"assetId": TEXT, "from": TEXT, "to": TEXT, "pageNum": INTEGER, "pageSize": INTEGER, "snapshotId": TEXT, "groupKey": TEXT, "cursor": TEXT}, ("assetId",))

# 与当前组合的实际调用保持同一参数合同，避免 OpenAPI 适配器丢弃参数。
COMPOSITION_INPUTS = {
    "ai-soc-master": {
        "list_soc_asset": _schema({
            "pageNum": INTEGER, "pageSize": INTEGER, "ip": TEXT, "hostname": TEXT, "keyword": TEXT,
            "source": TEXT, "layerId": INTEGER, "excludeLayerId": INTEGER, "online": TEXT,
            "assetType": TEXT, "vendor": TEXT, "status": TEXT, "techStatus": TEXT, "deptId": INTEGER,
            "sortField": TEXT, "sortOrder": TEXT, "collectionStatus": TEXT, "collectAnomaly": BOOLEAN,
            "modelIds": TEXT, "includeUnits": BOOLEAN, "assetView": TEXT, "rootOnly": BOOLEAN,
            "hostAssetId": INTEGER, "bizIds": TEXT, "bizAssociation": TEXT,
        }),
        "get_soc_discovery_tasks_by_task_id": _schema({"taskId": TEXT}, ("taskId",)),
        "get_soc_discovery_tasks_scope": _schema({"taskId": TEXT}, ("taskId",)),
        "get_soc_asset_registration_children": _schema({"assetId": INTEGER, "page": INTEGER}, ("assetId",)),
        "get_soc_asset_vulnerabilities": ASSET_INPUT,
        "list_soc_layer": _schema({}),
        "get_soc_asset_port_evidence": _schema({"ip": TEXT, "port": INTEGER, "protocol": TEXT}, ("ip", "port", "protocol")),
        "get_soc_asset_collection_capability": ASSET_INPUT,
        "get_soc_asset_online_transitions": _schema({"assetId": INTEGER, "from": TEXT, "to": TEXT}, ("assetId",)),
        "get_soc_asset_source_identities_resolve": _schema({"ip": TEXT, "assetId": INTEGER}),
        **{name: _schema({"body": OBJECT}, ("body",)) for name in ["create_soc_asset_probe", "create_soc_discovery_identify", "create_soc_discovery_tasks", "create_soc_discovery_tasks_adopt", "create_soc_asset"]},
        "start_soc_discovery_tasks": _schema({"taskId": TEXT}, ("taskId",)),
    },
    "ai-soc-ingest": {
        "get_admin_baseline_report_latest": _schema({"assetId": INTEGER, "includeChildren": BOOLEAN}, ("assetId",)),
        "get_admin_baseline_readiness": ASSET_INPUT,
        "get_admin_ingest_devices_run_state": DEVICE_INPUT,
        "get_admin_ingest_devices_plugin_configs": DEVICE_INPUT,
        "get_ingest_dispatch_dispatchable_devices": _schema({"configKind": TEXT, "operation": TEXT}),
        "list_admin_dispatch_dispatchable_devices": _schema({"configKind": TEXT, "operation": TEXT}),
        "get_admin_dispatch_task_policy_configs": _schema(DISPATCH_INPUT, ("deviceId", "configKind", "operation")),
        "get_admin_dispatch_task_input_fields": _schema(DISPATCH_INPUT, ("deviceId", "configKind", "operation")),
        "get_admin_dispatch_task_by_id": _schema({"id": TEXT}, ("id",)),
        "preview_admin_dispatch_task": _schema({"body": OBJECT}, ("body",)),
        "preview_internal_ingest_dispatch": _schema({"body": OBJECT}, ("body",)),
        "create_admin_dispatch_task": _schema({"body": OBJECT}, ("body",)),
        "precheck_admin_dispatch_task": _schema({"id": TEXT}, ("id",)),
        "submit_admin_dispatch_task": _schema({"id": TEXT, "body": OBJECT}, ("id",)),
        "execute_admin_dispatch_task": _schema({"id": TEXT}, ("id",)),
        "rollback_admin_dispatch_task": _schema({"id": TEXT}, ("id",)),
        "get_admin_ingest_devices_scan_templates": DEVICE_INPUT,
    },
    "ai-soc-graph": {
        "get_graph_resolve_ip_host": _schema({"ip": TEXT}, ("ip",)),
        "search_graph_assets": _schema({"q": TEXT, "limit": INTEGER, "assetTypes": TEXT}, ("q",)),
        "get_graph_path_query": {**_schema({**PAIR_INPUT, "srcVid": TEXT, "dstVid": TEXT, "maxHops": INTEGER}), "anyOf": [{"required": ["srcIp", "dstIp"]}, {"required": ["srcVid", "dstVid"]}]},
        "get_graph_compliance_rules": _schema({}),
        "get_reachability_path_by_ip": _schema(PAIR_INPUT, ("srcIp", "dstIp")),
        "get_reachability_acl_hit": _schema({**PAIR_INPUT, "devices": TEXT}, ("srcIp", "dstIp", "devices")),
        "get_reachability_route_candidates": _schema(PAIR_INPUT, ("srcIp", "dstIp")),
        "get_reachability_policy_flow_evidence": _schema(PAIR_INPUT, ("srcIp", "dstIp", "port", "protocol")),
        "get_graph_path_evidence": _schema(PAIR_INPUT, ("srcIp", "dstIp", "port", "protocol")),
        "get_graph_composed": _schema({"assetIds": TEXT, "deptId": INTEGER, "bizId": TEXT, "zoneId": TEXT, "showEndpoints": BOOLEAN, "timeFrom": TEXT, "timeTo": TEXT, "includeSegments": BOOLEAN, "relationType": TEXT}),
        "get_graph_coverage": _schema({"assetIds": TEXT, "deptId": INTEGER, "bizId": TEXT, "zoneId": TEXT, "showEndpoints": BOOLEAN, "timeFrom": TEXT, "timeTo": TEXT}),
        "get_graph_node_detail": _schema({"vid": TEXT}, ("vid",)),
    },
    "ai-soc-detect": {
        "list_detect_alert": _schema({"req": ALERT_QUERY}, ("req",)),
        "get_detect_alert_group_members": _schema({"req": ALERT_QUERY}, ("req",)),
    },
    "ai-soc-response": {
        "get_resp_action_defs": _schema({}),
        "list_resp_action_defs": _schema({}),
        "get_resp_action_def": _schema({"actionKey": TEXT}, ("actionKey",)),
        "get_resp_actions_target_candidates": _schema({"actionKey": TEXT}, ("actionKey",)),
        "get_resp_actions_device_agents": DEVICE_INPUT,
        "execute_resp_agent_actions": _schema({"body": OBJECT}, ("body",)),
        "get_resp_agent_actions_executions": _schema({"requestId": TEXT}, ("requestId",)),
        "list_resp_agent_actions_executions": _schema({"requestId": TEXT}),
        "list_resp_action_executions": _schema({"pageNum": INTEGER, "pageSize": INTEGER, "incidentId": TEXT}),
        "get_resp_action_execution": _schema({"id": TEXT}, ("id",)),
        "get_resp_actions_by_workflow_tracking": _schema({"instanceId": TEXT}, ("instanceId",)),
        "recommend_resp_actions": _schema({"incidentId": TEXT}),
    },
    "ai-soc-framework": {
        "list_framework_todos": _schema({"status": TEXT, "pageNum": INTEGER, "pageSize": INTEGER}),
        "get_framework_todo": _schema({"todoId": TEXT}, ("todoId",)),
        "get_framework_approval_status": _schema({"approvalId": TEXT}, ("approvalId",)),
    },
}

OBSERVED_AT = "2026-11-15T00:00:00Z"
ASSETS = [
    {"assetId": 9106, "hostname": "mock-app", "ip": "192.0.2.10"},
    {"assetId": 9107, "hostname": "mock-db", "ip": "192.0.2.20"},
]
DEVICE = {"deviceId": "mock-device-01", "assetId": 9106, "hostname": "mock-app", "ip": "192.0.2.10", "vendor": "mock", "deviceType": "SIMULATED"}
ACTION = {"actionKey": "mock-action", "name": "本地测试动作", "enabled": True, "risk": "low", "reversible": False, "inputSchema": _schema({"note": TEXT}), "execConfig": {"configKind": "ACL", "capability": "mock-preview", "operation": "ADD"}}


def _with_examples(schema: dict[str, Any], service_id: str, name: str = "") -> dict[str, Any]:
    """发现合同中的样例引用现有固定对象，不改变参数类型与对象匹配规则。"""
    result = deepcopy(schema)
    if "properties" in schema:
        result["properties"] = {key: _with_examples(value, service_id, key) for key, value in schema["properties"].items()}
    if isinstance(schema.get("items"), dict):
        result["items"] = _with_examples(schema["items"], service_id)
    if "example" in schema or "default" in schema or schema.get("examples"):
        return result
    examples = {
        "assetId": ASSETS[0]["assetId"], "hostAssetId": ASSETS[0]["assetId"], "assetIds": "9106,9107",
        "deviceId": DEVICE["deviceId"], "devices": "9201", "ip": ASSETS[0]["ip"],
        "srcIp": ASSETS[0]["ip"], "dstIp": ASSETS[1]["ip"], "srcVid": "asset:9106", "dstVid": "asset:9107", "vid": "asset:9106",
        "q": ASSETS[0]["hostname"], "hostname": ASSETS[0]["hostname"], "keyword": ASSETS[0]["hostname"],
        "actionKey": ACTION["actionKey"], "configKind": "ACL", "operation": "ADD", "policyConfigKey": "mock-policy",
        "taskId": "8001", "id": "7001" if service_id == "ai-soc-ingest" else "mock-execution-01",
        "protocol": "tcp", "port": 443, "page": 1, "pageNum": 1, "pageSize": 20,
        "from": OBSERVED_AT, "to": "2026-11-15T01:00:00Z", "timeFrom": OBSERVED_AT, "timeTo": "2026-11-15T01:00:00Z",
        "windowStart": OBSERVED_AT, "windowEnd": "2026-11-15T01:00:00Z",
    }
    value = examples.get(name)
    kind = schema.get("type")
    if schema.get("enum"):
        value = schema["enum"][0]
    if kind == "string":
        result["example"] = str(value) if value is not None else "固定样例"
    elif kind in {"integer", "number"}:
        result["example"] = value if isinstance(value, (int, float)) and not isinstance(value, bool) else max(schema.get("minimum", 1), 1)
    elif kind == "boolean":
        result["example"] = False
    return result


def _reply(data: Any, code: int = 200) -> dict[str, Any]:
    return {"code": code, "data": data, "simulated": True, "sideEffect": False}


def _listing(items: list[Any], total: int | None = None) -> dict[str, Any]:
    return {**_reply({"rows": items, "total": len(items) if total is None else total}), "total": len(items) if total is None else total}


def _missing() -> dict[str, Any]:
    return {**_reply(None, 404), "message": "未找到固定模拟对象。"}


def _service_id() -> str:
    value = os.environ.get("SOC_MOCK_SERVICE_ID", "").strip()
    if value not in SERVICE_PORTS:
        raise RuntimeError(f"SOC_MOCK_SERVICE_ID 无效：{value or '<empty>'}")
    return value


def _tool_name(key: str, service_id: str | None = None) -> str:
    prefix = f"{(service_id or _service_id()).replace('-', '_')}__"
    return key[len(prefix):] if key.startswith(prefix) else key


def _service_tools(service_id: str) -> list[tuple[str, dict[str, Any]]]:
    prefix = f"{service_id.replace('-', '_')}__"
    tools = {_tool_name(key, service_id): deepcopy(value) for key, value in SOC_TOOLS.items() if key.startswith(prefix)}
    for name in GENERIC_TOOLS.get(service_id, []):
        tools.setdefault(name, {"inputSchema": _schema({})})
    for name, schema in COMPOSITION_INPUTS.get(service_id, {}).items():
        tools[name] = {"inputSchema": deepcopy(schema)}
    for name, definition in tools.items():
        schema = _with_examples(definition.get("inputSchema", {}), service_id)
        if service_id == "ai-soc-ingest" and "body" in schema.get("properties", {}):
            schema["properties"]["body"]["example"] = {"deviceId": DEVICE["deviceId"], "configKind": "ACL", "operation": "ADD"}
        definition["inputSchema"] = schema
    return list(tools.items())


def _path_for(name: str, service_id: str | None = None) -> str:
    service = service_id or _service_id()
    paths = {
        "get_correlate_incident_by_incident_id": "/correlate/incident/{incidentId}",
        "get_correlate_reasoning_rules_by_rule_id": "/correlate/reasoning/rules/{ruleId}",
        "get_detect_alert_by_alert_id": "/detect/alert/{alertId}",
        "list_detect_whitelist": "/detect/whitelist/list",
        "search_event": "/event/search",
        "get_graph_enrich_topology_by_asset_id": "/graph/enrich/topology/{assetId}",
        "get_graph_identity_asset_accounts": "/graph/identity/asset/{assetId}/accounts",
        "get_graph_flow_host_pair_ports": "/graph/flow/host-pair/ports",
        "get_graph_lm_login_sequence": "/graph/lm/login-sequence",
        "get_graph_path_query": "/graph/path/query",
        "get_graph_compliance_rules": "/graph/compliance/rules",
        "get_reachability_path_by_ip": "/reachability/path/by-ip",
        "get_reachability_acl_hit": "/reachability/acl-hit",
        "get_reachability_route_candidates": "/reachability/route-candidates",
        "get_reachability_policy_flow_evidence": "/reachability/policy-flow-evidence",
        "get_graph_path_evidence": "/graph/path/evidence",
        "get_graph_resolve_ip_host": "/graph/resolve/ip-host",
        "search_graph_assets": "/graph/assets/search",
        "get_graph_composed": "/graph/composed",
        "get_graph_coverage": "/graph/coverage",
        "get_graph_node_detail": "/graph/node-detail",
        "get_ingest_devices_by_asset_by_asset_id": "/admin/ingest/devices/by-asset/{assetId}",
        "get_admin_baseline_report_latest": "/admin/ingest/baseline/report/latest",
        "get_admin_baseline_readiness": "/admin/ingest/baseline/readiness",
        "get_admin_ingest_devices_run_state": "/admin/ingest/devices/{deviceId}/run-state",
        "get_admin_ingest_devices_plugin_configs": "/admin/ingest/devices/{deviceId}/plugin-configs",
        "get_admin_ingest_devices_scan_templates": "/admin/ingest/devices/{deviceId}/scan-templates",
        "get_ingest_dispatch_dispatchable_devices": "/admin/ingest/dispatch/dispatchable-devices",
        "get_admin_dispatch_task_policy_configs": "/admin/dispatch/task/policy-configs",
        "get_admin_dispatch_task_input_fields": "/admin/dispatch/task/input-fields",
        "get_admin_dispatch_task_by_id": "/admin/dispatch/task/{id}",
        "preview_admin_dispatch_task": "/admin/dispatch/task/preview",
        "preview_internal_ingest_dispatch": "/internal/ingest/dispatch/preview",
        "create_admin_dispatch_task": "/admin/dispatch/task",
        "precheck_admin_dispatch_task": "/admin/dispatch/task/{id}/precheck",
        "submit_admin_dispatch_task": "/admin/dispatch/task/{id}/submit",
        "execute_admin_dispatch_task": "/admin/dispatch/task/{id}/execute",
        "rollback_admin_dispatch_task": "/admin/dispatch/task/{id}/rollback",
        "get_soc_asset_by_asset_id": "/soc/asset/{assetId}",
        "get_soc_asset_biz_systems": "/soc/asset/{assetId}/biz-systems",
        "get_soc_asset_importance": "/soc/asset/{assetId}/importance",
        "get_soc_asset_registration_children": "/soc/asset/{assetId}/registration-children",
        "get_soc_asset_vulnerabilities": "/soc/asset/{assetId}/vulnerabilities",
        "get_soc_asset_collection_capability": "/soc/asset/{assetId}/collection-capability",
        "get_soc_asset_online_transitions": "/soc/asset/{assetId}/online-transitions",
        "get_soc_asset_port_evidence": "/soc/asset/port-evidence",
        "list_soc_layer": "/soc/layer/list",
        "list_soc_asset": "/soc/asset/list",
        "get_soc_asset_source_identities_resolve": "/soc/asset/source-identities/resolve",
        "create_soc_asset_probe": "/soc/discovery/tasks/probe",
        "create_soc_discovery_identify": "/soc/discovery/tasks/identify",
        "create_soc_discovery_tasks": "/soc/discovery/tasks",
        "get_soc_discovery_tasks_by_task_id": "/soc/discovery/tasks/{taskId}",
        "get_soc_discovery_tasks_scope": "/soc/discovery/tasks/{taskId}/scope",
        "start_soc_discovery_tasks": "/soc/discovery/tasks/start",
        "create_soc_discovery_tasks_adopt": "/soc/discovery/tasks/adopt",
        "create_soc_asset": "/soc/asset",
        "get_resp_actions_device_agents": "/resp/actions/device-agents",
        "get_resp_action_defs": "/resp/action-defs",
        "get_resp_action_def": "/resp/action-defs/{actionKey}",
        "list_resp_action_executions": "/resp/actions/executions",
        "get_resp_action_execution": "/resp/actions/executions/{id}",
        "execute_resp_agent_actions": "/resp/agent/actions/execute",
        "get_resp_actions_by_workflow_tracking": "/resp/actions/by-workflow/{instanceId}/tracking",
        "recommend_resp_actions": "/resp/actions/recommend",
        "get_resp_actions_target_candidates": "/resp/actions/{actionKey}/target-candidates",
        "get_resp_agent_actions_executions": "/resp/agent/actions/executions",
        "list_detect_alert": "/detect/alert/list",
        "get_detect_alert_group_members": "/detect/alert/group-members",
        "list_framework_todos": "/framework/todos",
        "get_framework_todo": "/framework/todos/{todoId}",
        "get_framework_approval_status": "/framework/approvals/{approvalId}",
    }
    return paths.get(name, f"/mock/{service}/{name}")


def _method_for(name: str) -> str:
    return "post" if SAFE_OPERATION_WORDS.search(name) else "get"


def _parameter_schema(schema: dict[str, Any], path: str) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
    required = set(schema.get("required", [])) if isinstance(schema, dict) else set()
    body = properties.get("body") if "body" in properties else None
    parameters = []
    for name, value in properties.items():
        if name == "body":
            continue
        parameter = {
            "name": name,
            "in": "path" if "{" + name + "}" in path else "query",
            "required": name in required or "{" + name + "}" in path,
            "schema": value if isinstance(value, dict) else {"type": "string"},
        }
        if isinstance(value, dict) and value.get("type") == "object":
            parameter.update(style="form", explode=True)
        parameters.append(parameter)
    request_body = None
    if body is not None:
        request_body = {"required": "body" in required, "content": {"application/json": {"schema": body}}}
    return parameters, request_body


def _openapi(service_id: str, base_url: str, tools: list[tuple[str, dict[str, Any]]]) -> dict[str, Any]:
    paths: dict[str, Any] = {}
    for name, definition in tools:
        path = _path_for(name, service_id)
        parameters, body = _parameter_schema(definition.get("inputSchema", {}), path)
        operation: dict[str, Any] = {
            "operationId": name,
            "summary": f"{name} 本地模拟",
            "description": "仅返回固定的本地测试数据；不连接真实系统，不执行真实动作。",
            "parameters": parameters,
            "responses": {"200": {"description": "固定模拟响应", "content": {"application/json": {"schema": {"type": "object"}}}}},
        }
        if body is not None:
            operation["requestBody"] = body
        paths.setdefault(path, {})["post" if body is not None else _method_for(name)] = operation
    return {
        "openapi": "3.0.3",
        "info": {"title": f"{service_id} 本地安全模拟服务", "version": "0.1.0", "description": SERVICE_SUMMARIES[service_id]},
        "servers": [{"url": base_url.rstrip("/")}],
        "paths": paths,
    }


def _asset(arguments: dict[str, Any]) -> dict[str, Any] | None:
    identifier = arguments.get("assetId", (arguments.get("req") or {}).get("assetId"))
    return next((deepcopy(item) for item in ASSETS if identifier is not None and str(item["assetId"]) == str(identifier)), None)


def _asset_detail(asset: dict[str, Any]) -> dict[str, Any]:
    return {**asset, "assetType": "SERVER", "status": "online", "online": "online", "deptId": 1,
            "networkTier": "test", "lastSeenAt": OBSERVED_AT, "onlineBasis": "FIXED_TEST_DATA",
            "stateEvidence": {"signals": [{"source": "mock-observation", "observedAt": OBSERVED_AT, "validity": "VALID", "supportsOnline": True}]}}


def _fixed_result(service_id: str, operation: str, arguments: dict[str, Any]) -> dict[str, Any]:
    # 请求只能选择固定夹具；不将任意输入、配置正文或操作参数带回响应。
    aliases = {"list_resp_action_defs": "get_resp_action_defs", "list_resp_agent_actions_executions": "get_resp_agent_actions_executions",
               "list_admin_dispatch_dispatchable_devices": "get_ingest_dispatch_dispatchable_devices"}
    operation = aliases.get(operation, operation)
    asset = _asset(arguments)
    if "assetId" in arguments and asset is None:
        return _missing()
    if service_id == "ai-soc-master":
        if operation in {"get_soc_discovery_tasks_by_task_id", "get_soc_discovery_tasks_scope"}:
            if arguments.get("taskId") != "8001":
                return _missing()
            if operation == "get_soc_discovery_tasks_by_task_id":
                return _reply({"task": {"id": "8001", "taskId": "8001", "status": "done", "total": 0, "doneCount": 0,
                                        "discoveredCount": 0, "adoptedCount": 0, "pendingCount": 0, "unreachableCount": 0}, "findings": []})
            return _reply({"taskId": "8001", "stage": "preview", "includedRanges": "192.0.2.10,192.0.2.20", "excludedRanges": "",
                           "autoAdopt": False, "canStart": False, "requiresConfirmation": True, "previewHash": "mock-discovery-preview-8001"})
        if operation == "list_soc_asset":
            matches = [item for item in ASSETS if (not arguments.get("ip") or item["ip"] == arguments["ip"])
                       and (not arguments.get("hostname") or item["hostname"] == arguments["hostname"])
                       and (not arguments.get("keyword") or arguments["keyword"] in [item["hostname"], item["ip"]])]
            return _listing([_asset_detail(item) for item in matches] if arguments.get("pageNum", 1) == 1 else [], len(matches))
        if operation == "get_soc_asset_by_asset_id":
            return _reply(_asset_detail(asset)) if asset else _missing()
        if operation in {"get_soc_asset_registration_children", "get_soc_asset_vulnerabilities", "get_soc_asset_online_transitions", "get_soc_asset_biz_systems", "list_soc_layer"}:
            return _listing([])
        if operation == "get_soc_asset_collection_capability":
            return _reply({"assetId": asset["assetId"], "groups": []}) if asset else _missing()
        if operation == "get_soc_asset_port_evidence":
            return _reply({"status": "NO_RECORD", "recordedAt": None, "source": None, "service": None})
        if operation == "get_soc_asset_source_identities_resolve":
            return _listing([_asset_detail(item) for item in ASSETS if item["ip"] == arguments.get("ip")])
    if service_id == "ai-soc-ingest":
        if operation == "get_admin_baseline_report_latest":
            return _reply({"assetId": asset["assetId"], "templateId": "mock-baseline", "run": {"assetId": asset["assetId"], "templateId": "mock-baseline", "passFlag": "1"}}) if asset else _missing()
        if operation == "get_admin_baseline_readiness":
            return _reply({"assetId": asset["assetId"], "templateId": "mock-baseline", "templateScopeMatched": True,
                           "memberCount": 1, "applicableCount": 1, "coverageReason": "APPLICABLE_ITEMS_PRESENT",
                           "items": [{"itemId": "mock-item", "applicable": True, "applicabilityReason": "MATCHED"}]}) if asset else _missing()
        if operation == "get_ingest_devices_by_asset_by_asset_id":
            return _listing([DEVICE] if asset and asset["assetId"] == 9106 else [])
        if operation == "get_ingest_dispatch_dispatchable_devices":
            return _listing([DEVICE] if arguments.get("configKind") in {None, "ACL", "ROUTE"} else [])
        if operation in {"get_admin_dispatch_task_policy_configs", "get_admin_dispatch_task_input_fields", "get_admin_ingest_devices_scan_templates", "get_admin_ingest_devices_run_state", "get_admin_ingest_devices_plugin_configs"}:
            if arguments.get("deviceId") != DEVICE["deviceId"]:
                return _missing()
            if operation == "get_admin_dispatch_task_policy_configs":
                return _listing([{"value": "mock-policy", "label": "本地测试策略", "inputMode": "PARAMETERS"}])
            if operation == "get_admin_dispatch_task_input_fields":
                return _listing([{"fieldName": "note", "required": False, "type": "string"}])
            if operation == "get_admin_ingest_devices_scan_templates":
                return _listing([{"value": "mock-template", "label": "Basic Network Scan"}])
            return _reply({"deviceId": DEVICE["deviceId"], "status": "SIMULATED", "observedAt": OBSERVED_AT})
        if operation in {"preview_admin_dispatch_task", "preview_internal_ingest_dispatch"}:
            body = arguments.get("body") or {}
            if body.get("deviceId") != DEVICE["deviceId"]:
                return _missing()
            return _reply({"success": True, "online": True, "precheck": {"status": "READY", "blocked": False, "changeIntroducesHard": False}, "deviceId": DEVICE["deviceId"]})
        if operation == "create_admin_dispatch_task":
            return _reply({"id": "7001", "taskId": "7001", "status": "DRAFT"})
        if operation in {"get_admin_dispatch_task_by_id", "precheck_admin_dispatch_task", "submit_admin_dispatch_task", "execute_admin_dispatch_task", "rollback_admin_dispatch_task"}:
            if str(arguments.get("id")) != "7001":
                return _missing()
            if operation == "get_admin_dispatch_task_by_id":
                return _reply({"task": {"id": "7001", "status": "DRAFT"}, "items": []})
            if operation == "precheck_admin_dispatch_task":
                return _reply({"success": True, "blocked": False, "overallHasConflict": False, "riskAcceptanceRequired": False, "perDevice": []})
            return _reply({"accepted": True, "taskId": "7001", "status": "SIMULATED"})
    if service_id == "ai-soc-graph":
        if operation == "get_graph_compliance_rules":
            return _listing([{"id": "mock-required", "name": "本地测试路径", "enabled": True, "ruleType": "REQUIRED", "destPort": 443, "protocol": "tcp",
                              "sourceSelector": {"scope": "ASSETS", "cidrs": ["192.0.2.10/32"]}, "destSelector": {"scope": "ASSETS", "cidrs": ["192.0.2.20/32"]}}])
        if operation in {"get_graph_path_query", "get_reachability_path_by_ip", "get_reachability_acl_hit", "get_reachability_route_candidates", "get_reachability_policy_flow_evidence", "get_graph_path_evidence"}:
            source = next((item for item in ASSETS if arguments.get("srcIp") == item["ip"] or str(arguments.get("srcVid")) in {str(item["assetId"]), f"asset:{item['assetId']}"}), None)
            target = next((item for item in ASSETS if arguments.get("dstIp") == item["ip"] or str(arguments.get("dstVid")) in {str(item["assetId"]), f"asset:{item['assetId']}"}), None)
            if source is None or target is None:
                return _missing()
            if operation == "get_reachability_acl_hit":
                return _reply({"hops": [{"deviceId": "9201", "verdict": "PERMIT"}]})
            if operation == "get_reachability_route_candidates":
                return _reply({"status": "NO_RECORD", "candidates": [], "gaps": ["固定测试数据没有额外路由观测"]})
            if operation == "get_reachability_policy_flow_evidence":
                return _reply({"status": "NO_RECORD", "exact": [], "destination": []})
            if operation == "get_graph_path_evidence":
                return _reply({"status": "NO_RECORD", "sameSessionConfirmed": False, "candidatePolicies": [], "logQueryAttempts": 0, "probeWindowRequested": False, "trafficEvidence": {"gaps": ["固定测试数据没有会话观测"]}})
            return _reply({"reachable": True, "verdict": "REACHABLE", "natApplied": False, "path": ["9201"], "routeOnlyPath": ["9201"],
                           "diagnosis": {"sourceIp": source["ip"], "targetIp": target["ip"], "port": 443, "protocol": "tcp", "portEvaluated": arguments.get("port", 443) == 443 and arguments.get("protocol", "tcp") == "tcp", "verdict": "REACHABLE", "observedAt": OBSERVED_AT}})
        if operation in {"search_graph_assets", "get_graph_resolve_ip_host", "get_graph_node_detail"}:
            return _listing([_asset_detail(item) for item in ASSETS if arguments.get("q", arguments.get("ip", arguments.get("vid"))) in {item["hostname"], item["ip"], str(item["assetId"]), f"asset:{item['assetId']}"}])
    if service_id == "ai-soc-detect" and operation in {"list_detect_alert", "get_detect_alert_group_members"}:
        if asset is None:
            return _missing()
        if operation == "list_detect_alert":
            return _reply({"groups": [], "totalGroups": 0, "totalAlerts": 0, "truncated": False, "snapshotId": "mock-alerts-snapshot", "asOf": OBSERVED_AT, "nextCursor": None})
        return _reply({"members": [], "total": 0, "truncated": False, "snapshotId": "mock-alerts-snapshot", "nextCursor": None})
    if service_id == "ai-soc-response":
        if operation == "get_resp_action_defs":
            return _listing([ACTION])
        if operation in {"get_resp_action_def", "get_resp_actions_target_candidates"}:
            if arguments.get("actionKey") != ACTION["actionKey"]:
                return _missing()
            return _reply(ACTION) if operation == "get_resp_action_def" else _listing([DEVICE])
        if operation == "get_resp_actions_device_agents":
            return _listing([{"agentId": "mock-agent-01", "hostname": "mock-app", "ip": "192.0.2.10", "os": "mock"}]) if arguments.get("deviceId") == DEVICE["deviceId"] else _missing()
        if operation == "execute_resp_agent_actions":
            return _reply({"executionId": "mock-execution-01", "status": "SIMULATED"})
        if operation == "get_resp_agent_actions_executions":
            return _listing([{"executionId": "mock-execution-01", "status": "SIMULATED", "deviceEffectVerified": False}])
    if service_id == "ai-soc-event":
        return {"items": [], "total": 0, "aggregations": {}, "simulated": True, "sideEffect": False}
    return _listing([])


def _valid_arguments(value: Any, schema: dict[str, Any]) -> bool:
    expected = schema.get("type")
    if expected == "object":
        if not isinstance(value, dict) or any(key not in value for key in schema.get("required", [])):
            return False
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False and set(value) - set(properties):
            return False
        if any(not _valid_arguments(item, properties[key]) for key, item in value.items() if key in properties):
            return False
    elif expected == "string" and not isinstance(value, str):
        return False
    elif expected == "integer" and (not isinstance(value, int) or isinstance(value, bool)):
        return False
    elif expected == "boolean" and not isinstance(value, bool):
        return False
    elif expected == "array" and not isinstance(value, list):
        return False
    if "enum" in schema and value not in schema["enum"]:
        return False
    return "anyOf" not in schema or any(_valid_arguments(value, branch) and (not isinstance(value, dict) or all(key in value for key in branch.get("required", []))) for branch in schema["anyOf"])


async def _call(service_id: str, operation: str, arguments: dict[str, Any]) -> dict[str, Any]:
    definition = dict(_service_tools(service_id)).get(operation)
    if definition is None:
        return {**_missing(), "message": "未找到本地模拟工具。"}
    if not _valid_arguments(arguments, definition.get("inputSchema", {})):
        return {**_reply(None, 400), "message": "请求参数不符合固定工具合同。"}
    return _fixed_result(service_id, operation, arguments)


def _mcp_server(service_id: str, tools: list[tuple[str, dict[str, Any]]]) -> Server:
    catalog = {name: definition for name, definition in tools}

    async def list_tools(_ctx: ServerRequestContext, _params: types.PaginatedRequestParams | None) -> types.ListToolsResult:
        return types.ListToolsResult(tools=[types.Tool(name=name, description=f"{name} 本地模拟；无真实副作用。", inputSchema=definition.get("inputSchema", {"type": "object"})) for name, definition in catalog.items()])

    async def call_tool(_ctx: ServerRequestContext, params: types.CallToolRequestParams) -> types.CallToolResult:
        if params.name not in catalog:
            payload = {**_missing(), "message": "未找到本地模拟工具。"}
            return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(payload, ensure_ascii=False))], structuredContent=payload, isError=True)
        payload = await _call(service_id, params.name, params.arguments or {})
        return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(payload, ensure_ascii=False))], structuredContent=payload, isError=payload.get("code", 200) != 200)

    return Server(service_id, version="0.1.0", on_list_tools=list_tools, on_call_tool=call_tool)


def create_app(service_id: str | None = None) -> FastAPI:
    service_id = service_id or _service_id()
    port = SERVICE_PORTS[service_id]
    tools = _service_tools(service_id)
    server = _mcp_server(service_id, tools)
    routes = []
    for name, definition in tools:
        path = _path_for(name, service_id)
        pattern = re.sub(r"\\\{([A-Za-z][A-Za-z0-9_]*)\\\}", r"(?P<\1>[^/]+)", re.escape(path))
        method = "post" if "body" in definition.get("inputSchema", {}).get("properties", {}) else _method_for(name)
        routes.append((path.count("{"), -len(path), re.compile(pattern), method, name, definition))
    routes.sort(key=lambda route: route[:2])

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        async with AsyncExitStack() as stack:
            await stack.enter_async_context(server.session_manager.run())
            yield

    app = FastAPI(title=f"{service_id} 本地安全模拟服务", version="0.1.0", lifespan=lifespan)
    expected_key = os.environ.get("SOC_MOCK_API_KEY", "").strip()

    @app.middleware("http")
    async def local_auth(request: Request, call_next):
        local_path = request.url.path.removeprefix(request.scope.get("root_path", ""))
        if expected_key and local_path not in {"/health", "/v3/api-docs/mcp"} and request.headers.get("X-API-Key") != expected_key:
            return JSONResponse({"detail": "本地模拟凭据无效"}, status_code=401)
        return await call_next(request)

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": service_id, "port": port, "simulated": True}

    @app.get("/v3/api-docs/mcp", include_in_schema=False)
    async def spec(request: Request):
        base_url = request.base_url.replace(path=request.scope.get("root_path", "") or "/")
        return _openapi(service_id, str(base_url), tools)

    mcp_app = server.streamable_http_app(streamable_http_path="/", stateless_http=True, json_response=True,
                                         transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False))
    app.mount("/mcp", mcp_app)

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], include_in_schema=False)
    async def operation(request: Request, path: str):
        local_path = "/" + path
        match = next(((route, route[2].fullmatch(local_path)) for route in routes if route[2].fullmatch(local_path)), None)
        if match is None:
            return JSONResponse({**_missing(), "message": "未找到本地模拟路径。"}, status_code=404)
        route, path_match = match
        _, _, _, method, name, definition = route
        if request.method.lower() != method:
            return JSONResponse({**_reply(None, 405), "message": "请求方法不符合固定工具合同。"}, status_code=405)
        schema = definition.get("inputSchema", {})
        arguments: dict[str, Any] = {**dict(request.query_params), **path_match.groupdict()}
        try:
            req_schema = schema.get("properties", {}).get("req", {})
            if req_schema.get("type") == "object" and "req" not in arguments:
                nested = {field: arguments.pop(field) for field in req_schema.get("properties", {}) if field in arguments}
                if nested:
                    arguments["req"] = nested
            for field, value in list(arguments.items()):
                field_schema = schema.get("properties", {}).get(field, {})
                kind = field_schema.get("type")
                if kind == "object" and isinstance(value, dict):
                    for key, item in list(value.items()):
                        if field_schema.get("properties", {}).get(key, {}).get("type") in {"integer", "boolean"}:
                            value[key] = json.loads(item)
                    continue
                if kind in {"integer", "object", "array", "boolean"}:
                    arguments[field] = json.loads(value)
            if "body" in schema.get("properties", {}):
                content = await request.body()
                if content:
                    arguments["body"] = json.loads(content)
        except (ValueError, TypeError):
            return JSONResponse({**_reply(None, 400), "message": "请求参数不符合固定工具合同。"}, status_code=400)
        result = await _call(service_id, name, arguments)
        return JSONResponse(result, status_code=result.get("code", 200))

    return app


app = create_app(os.environ.get("SOC_MOCK_SERVICE_ID") or "ai-soc-framework")

