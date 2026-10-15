"""唯一工具目录；SOC 参数源自 019 Candidate 的已使用工具合同。"""
from __future__ import annotations


def obj(properties=None, required=()):
    return {"type": "object", "properties": properties or {},
            "required": list(required), "additionalProperties": False}


TEXT = {"type": "string", "minLength": 1, "maxLength": 512}
IDENTIFIER = {"type": "string", "pattern": r"^[A-Za-z0-9_.-]{1,128}$"}
INTEGER = {"type": "integer"}
ASSET = {"type": "integer", "minimum": 1}
OPERATION = obj({"operationId": IDENTIFIER}, ["operationId"])
BODY = {"type": "object"}
TOOL_INPUT_SCHEMAS = {}


def dsh_schema(value):
    """使用当前 DSH MCP 客户端可装载的 JSON Schema 子集。"""
    if isinstance(value, list):
        return [dsh_schema(item) for item in value]
    if not isinstance(value, dict):
        return value
    result = {key: dsh_schema(item) for key, item in value.items()
              if key not in {"minLength", "maxLength", "minimum", "maximum", "minItems", "maxItems", "pattern", "uniqueItems"}}
    if isinstance(result.get("type"), list):
        result["oneOf"] = [{"type": kind} for kind in result.pop("type")]
    if "type" not in result and ("const" in result or result.get("enum")):
        sample = result.get("const", result.get("enum", [None])[0])
        result["type"] = "string" if isinstance(sample, str) else "integer" if isinstance(sample, int) else "null"
    return result


DESCRIPTIONS = {
    "search_graph_assets": "按资产名称、主机名、IP 或标识搜索基础模拟资产，q 为检索文本。",
    "get_graph_resolve_ip_host": "将模拟 IP 解析为对应主机资产。",
    "get_soc_asset_by_asset_id": "按整数 assetId 查询基础模拟资产详情。",
    "list_soc_asset": "分页查询基础模拟资产清单，可按 IP 或 keyword 筛选。",
    "get_soc_asset_biz_systems": "查询模拟资产所属的测试业务系统。",
    "get_soc_asset_vulnerabilities": "查询模拟资产的基础检查结果，当前没有待处理项。",
    "get_ingest_devices_by_asset_by_asset_id": "查询模拟资产绑定的正常采集器。",
    "get_graph_node_detail": "查询模拟资产图节点；vid 接受资产数字标识或 asset: 前缀形式。",
    "get_graph_path_query": "按源与目的图节点标识查询基础模拟连通路径。",
    "get_reachability_path_by_ip": "按源与目的 IP 查询基础模拟连通路径。",
    "get_graph_flow_host_pair_ports": "查询指定模拟主机对的连接聚合，当前返回空连接明细。",
    "get_reachability_cross_signal": "查询模拟资产登记与观测数量的交叉摘要。",
    "get_graph_compliance_violations": "查询基础模拟检查的待处理项，当前为空。",
    "get_graph_coverage": "查询模拟资产采集覆盖数量与比例。",
    "get_event_by_id": "按 INC 事件标识查询例行运维检查测试事件。",
    "list_executable_inspections": "列出已发布的基础资产健康巡检模板及当前全部测试资产范围。",
    "start_inspection": "按目录中的 taskId 和 definitionVersion 发起异步模拟巡检，重试复用 requestId。",
    "get_inspection_result": "按 runId 查询巡检进度，完成后返回摘要、设备数量和可下载报告地址。",
    "prepare_policy_configuration": "准备主机到主机的基础模拟访问策略草案；请求放在 body，幂等键为 request_id。",
    "get_policy_configuration_status": "按 operationId 查询模拟策略阶段、冻结候选及草案状态。",
    "select_policy_configuration_candidate": "提交当前冻结候选的完整排序和摘要，准备可确认的模拟策略草案。",
    "get_policy_configuration_result": "按 operationId 读取模拟策略草案、完整预览及执行结果。",
    "confirm_policy_configuration": "仅供受信运行时绑定 candidate_digest 确认模拟草案，不操作真实设备。",
    "prepare_emergency_action": "为单个测试资产准备基础应急模拟草案，body 含原始意图、目标线索和已知参数。",
    "revise_emergency_action": "按操作号和 expected_version 修订尚未确认的模拟应急草案。",
    "get_emergency_action": "按 operationId 查询模拟应急草案及当前版本。",
    "list_emergency_actions": "列出当前 Mock 进程中已准备的模拟应急操作。",
    "get_emergency_action_result": "按 operationId 查询应急模拟结果，不重新准备或提交动作。",
    "cancel_emergency_action": "按操作号和 expected_version 取消未确认的模拟应急草案。",
    "save_persistence_result": "模拟保存报告并返回真实可下载的固定基础 HTML 样例；不回显上传内容。",
}


def tool(name, schema):
    TOOL_INPUT_SCHEMAS[name] = schema
    return {"name": name, "description": DESCRIPTIONS[name], "inputSchema": dsh_schema(schema)}


POLICY_INTENT = obj({
    "schema_version": {"const": "workbench-policy-intent/v1"},
    "policy_kind": {"const": "NETWORK_ACCESS"}, "operation": {"const": "ADD"},
    "source": obj({"selector_type": {"const": "IP"}, "value": TEXT}, ["selector_type", "value"]),
    "destination": obj({"selector_type": {"const": "IP"}, "value": TEXT}, ["selector_type", "value"]),
    "protocol": {"enum": ["TCP", "UDP"]},
    "destination_port": {"type": "integer", "minimum": 1, "maximum": 65535},
    "target_external_id": {"type": "null"}, "device_query": TEXT,
    "validity": BODY, "change_reason": TEXT,
}, ["schema_version", "policy_kind", "operation", "source", "destination", "protocol", "destination_port"])
PREPARE_POLICY = obj({"body": obj({
    "contract_version": {"const": "workbench-policy-configuration/v2"},
    "request_id": IDENTIFIER, "intent": POLICY_INTENT,
}, ["contract_version", "request_id", "intent"])}, ["body"])
EMERGENCY_BODY = {
    "request_id": IDENTIFIER, "intent": TEXT, "target_hint": TEXT, "action_key": TEXT,
    "params": obj({"src_ip": TEXT, "port": {"type": ["string", "integer"]}, "user": TEXT}),
}
EMERGENCY_CONFIRMATION_SCHEMA = obj({
    "request_id": IDENTIFIER, "expected_version": ASSET,
    "snapshot_digest": {"type": "string", "pattern": r"^sha256:[a-f0-9]{64}$"},
    "confirmation_event_ref": {"type": "string", "minLength": 1, "maxLength": 8192},
}, ["request_id", "expected_version", "snapshot_digest", "confirmation_event_ref"])

TOOL_GROUPS = {
    "sec-ops": [
        tool("search_graph_assets", obj({"q": TEXT, "limit": {"type": "integer", "minimum": 1, "maximum": 100}}, ["q"])),
        tool("get_graph_resolve_ip_host", obj({"ip": TEXT}, ["ip"])),
        tool("get_soc_asset_by_asset_id", obj({"assetId": ASSET}, ["assetId"])),
        tool("list_soc_asset", obj({"ip": TEXT, "keyword": TEXT, "pageNum": ASSET, "pageSize": ASSET})),
        tool("get_soc_asset_biz_systems", obj({"assetId": ASSET}, ["assetId"])),
        tool("get_soc_asset_vulnerabilities", obj({"assetId": ASSET}, ["assetId"])),
        tool("get_ingest_devices_by_asset_by_asset_id", obj({"assetId": ASSET}, ["assetId"])),
        tool("get_graph_node_detail", obj({"vid": TEXT}, ["vid"])),
        tool("get_graph_path_query", obj({"srcVid": TEXT, "dstVid": TEXT, "maxHops": ASSET}, ["srcVid", "dstVid"])),
        tool("get_reachability_path_by_ip", obj({"srcIp": TEXT, "dstIp": TEXT}, ["srcIp", "dstIp"])),
        tool("get_graph_flow_host_pair_ports", obj({"srcIp": TEXT, "dstIp": TEXT, "timeFrom": TEXT}, ["srcIp", "dstIp"])),
        tool("get_reachability_cross_signal", obj()),
        tool("get_graph_compliance_violations", obj()),
        tool("get_graph_coverage", obj()),
        tool("get_event_by_id", obj({"eventId": TEXT}, ["eventId"])),
    ],
    "inspection": [
        tool("list_executable_inspections", obj()),
        tool("start_inspection", obj({
            "taskId": IDENTIFIER, "definitionVersion": {"type": ["string", "integer"]}, "requestId": IDENTIFIER,
            "scope": obj({"type": {"const": "ASSET_IDS"},
                          "assetIds": {"type": "array", "minItems": 1, "items": IDENTIFIER}}, ["type", "assetIds"]),
        }, ["taskId", "definitionVersion", "requestId"])),
        tool("get_inspection_result", obj({"runId": IDENTIFIER}, ["runId"])),
    ],
    "policy-configuration": [
        tool("prepare_policy_configuration", PREPARE_POLICY),
        tool("get_policy_configuration_status", OPERATION),
        tool("select_policy_configuration_candidate", obj({"operationId": IDENTIFIER, "body": obj({
            "candidate_set_digest": TEXT,
            "ranked_candidate_ids": {"type": "array", "minItems": 1, "items": TEXT, "uniqueItems": True},
            "reason_codes": {"type": "array", "items": TEXT},
        }, ["candidate_set_digest", "ranked_candidate_ids", "reason_codes"])}, ["operationId", "body"])),
        tool("get_policy_configuration_result", OPERATION),
        tool("confirm_policy_configuration", obj({"operationId": IDENTIFIER, "body": obj({
            "request_id": IDENTIFIER, "candidate_digest": TEXT,
        }, ["request_id", "candidate_digest"])}, ["operationId", "body"])),
    ],
    "emergency-action": [
        tool("prepare_emergency_action", obj({"body": obj(EMERGENCY_BODY, ["request_id", "intent", "target_hint"])}, ["body"])),
        tool("revise_emergency_action", obj({"operationId": IDENTIFIER, "body": obj({
            **EMERGENCY_BODY, "expected_version": ASSET,
        }, ["request_id", "intent", "expected_version"])}, ["operationId", "body"])),
        tool("get_emergency_action", OPERATION),
        tool("list_emergency_actions", obj({"limit": {"type": "integer", "minimum": 1, "maximum": 100}, "cursor": TEXT})),
        tool("get_emergency_action_result", OPERATION),
        tool("cancel_emergency_action", obj({"operationId": IDENTIFIER, "body": obj({
            "request_id": IDENTIFIER, "expected_version": ASSET,
        }, ["request_id", "expected_version"])}, ["operationId", "body"])),
    ],
    "report": [tool("save_persistence_result", obj({
        "businessId": IDENTIFIER, "sourceModule": IDENTIFIER, "revision": ASSET,
        "resultType": {"const": "report"}, "contentType": {"const": "text/html"},
        "fileName": IDENTIFIER, "fileContentBase64": {"type": "string", "maxLength": 1500000},
    }, ["businessId", "sourceModule", "revision", "resultType", "contentType", "fileName", "fileContentBase64"]))],
}

# 以下仅保存当前固定代码实际调用的 19 项，不包含上游其他能力。
SOC_TOOLS = {'ai_soc_correlate__get_correlate_incident_by_incident_id': {'resource_id': 'cb220340-41b9-4b04-a521-c6f687095016',
                                                             'inputSchema': {'type': 'object',
                                                                             'properties': {'incidentId': {'type': 'string'}},
                                                                             'required': ['incidentId']}},
 'ai_soc_correlate__get_correlate_intel_check': {'resource_id': 'cb220340-41b9-4b04-a521-c6f687095016',
                                                 'inputSchema': {'type': 'object',
                                                                 'properties': {'value': {'type': 'string'},
                                                                                'disposition': {'type': 'string'}},
                                                                 'required': ['disposition', 'value']}},
 'ai_soc_correlate__get_correlate_reasoning_rules_by_rule_id': {'resource_id': 'cb220340-41b9-4b04-a521-c6f687095016',
                                                                'inputSchema': {'type': 'object',
                                                                                'properties': {'ruleId': {'type': 'integer',
                                                                                                          'format': 'int64'}},
                                                                                'required': ['ruleId']}},
 'ai_soc_correlate__get_correlate_threat_intel': {'resource_id': 'cb220340-41b9-4b04-a521-c6f687095016',
                                                  'inputSchema': {'type': 'object',
                                                                  'properties': {'iocType': {'type': 'string'},
                                                                                 'disposition': {'type': 'string'},
                                                                                 'iocValueLike': {'type': 'string'},
                                                                                 'pageNum': {'type': 'integer',
                                                                                             'format': 'int32',
                                                                                             'default': 1},
                                                                                 'pageSize': {'type': 'integer',
                                                                                              'format': 'int32',
                                                                                              'default': 20}}}},
 'ai_soc_correlate__create_correlate_incident_judgement_fail': {'resource_id': 'cb220340-41b9-4b04-a521-c6f687095016',
                                                                'inputSchema': {'type': 'object',
                                                                                'properties': {'judgementId': {'type': 'string'},
                                                                                               'body': {'type': 'object',
                                                                                                        'properties': {'runId': {'type': 'string'},
                                                                                                                       'errorType': {'type': 'string'},
                                                                                                                       'error': {'type': 'string'},
                                                                                                                       'resultJson': {},
                                                                                                                       'agentName': {'type': 'string'},
                                                                                                                       'agentVersion': {'type': 'string'},
                                                                                                                       'model': {'type': 'string'}},
                                                                                                        'required': ['error']}},
                                                                                'required': ['body',
                                                                                             'judgementId']}},
 'ai_soc_correlate__get_correlate_incident_judge_pending': {'resource_id': 'cb220340-41b9-4b04-a521-c6f687095016',
                                                            'inputSchema': {'type': 'object',
                                                                            'properties': {'pageNum': {'type': 'integer',
                                                                                                       'format': 'int32',
                                                                                                       'default': 1},
                                                                                           'pageSize': {'type': 'integer',
                                                                                                        'format': 'int32',
                                                                                                        'default': 20},
                                                                                           'previewPriority': {'type': 'boolean',
                                                                                                               'default': False}}}},
 'ai_soc_correlate__create_incident_judgement_claim': {'resource_id': 'cb220340-41b9-4b04-a521-c6f687095016',
                                                       'inputSchema': {'type': 'object',
                                                                       'properties': {'incidentId': {'type': 'string'}},
                                                                       'required': ['incidentId']}},
 'ai_soc_correlate__update_incident_judgement_result': {'resource_id': 'cb220340-41b9-4b04-a521-c6f687095016',
                                                        'inputSchema': {'type': 'object',
                                                                        'properties': {'judgementId': {'type': 'string'},
                                                                                       'body': {'type': 'object',
                                                                                                'properties': {'runId': {'type': 'string'},
                                                                                                               'route': {'type': 'string'},
                                                                                                               'llmInvoked': {'type': 'boolean'},
                                                                                                               'verdict': {'type': 'string'},
                                                                                                               'confidence': {'type': 'number'},
                                                                                                               'validationStatus': {'type': 'string'},
                                                                                                               'summary': {'type': 'string'},
                                                                                                               'reportHtml': {'type': 'string'},
                                                                                                               'resultJson': {},
                                                                                                               'schemaVersion': {'type': 'string'},
                                                                                                               'agentName': {'type': 'string'},
                                                                                                               'agentVersion': {'type': 'string'},
                                                                                                               'model': {'type': 'string'}},
                                                                                                'required': ['resultJson',
                                                                                                             'route',
                                                                                                             'runId',
                                                                                                             'summary',
                                                                                                             'validationStatus',
                                                                                                             'verdict']}},
                                                                        'required': ['body', 'judgementId']}},
 'ai_soc_detect__get_detect_alert_by_alert_id': {'resource_id': '92a84e41-d340-4fb9-af8a-f7c7d41b0b54',
                                                 'inputSchema': {'type': 'object',
                                                                 'properties': {'alertId': {'type': 'string'}},
                                                                 'required': ['alertId']}},
 'ai_soc_detect__list_detect_whitelist': {'resource_id': '92a84e41-d340-4fb9-af8a-f7c7d41b0b54',
                                          'inputSchema': {'type': 'object', 'properties': {}}},
 'ai_soc_event__search_event': {'resource_id': '763bd53e-f72b-4fbf-ab39-1245ae15dd14',
                                'inputSchema': {'type': 'object',
                                                'properties': {'body': {'type': 'object',
                                                                        'properties': {'indices': {'type': 'array',
                                                                                                   'items': {'type': 'string'}},
                                                                                       'timeRange': {'type': 'object',
                                                                                                     'properties': {'from': {'type': 'string',
                                                                                                                             'format': 'date-time'},
                                                                                                                    'to': {'type': 'string',
                                                                                                                           'format': 'date-time'}}},
                                                                                       'filters': {'type': 'array',
                                                                                                   'items': {'type': 'object',
                                                                                                             'properties': {'field': {'type': 'string'},
                                                                                                                            'op': {'type': 'string'},
                                                                                                                            'value': {},
                                                                                                                            'values': {'type': 'array',
                                                                                                                                       'items': {}}}}},
                                                                                       'luceneQuery': {'type': 'string'},
                                                                                       'timeField': {'type': 'string'},
                                                                                       'histogramInterval': {'type': 'string'},
                                                                                       'size': {'type': 'integer',
                                                                                                'format': 'int32'},
                                                                                       'from': {'type': 'integer',
                                                                                                'format': 'int32'},
                                                                                       'searchAfter': {'type': 'array',
                                                                                                       'items': {}},
                                                                                       'sort': {'type': 'array',
                                                                                                'items': {'type': 'object',
                                                                                                          'properties': {'field': {'type': 'string'},
                                                                                                                         'order': {'type': 'string'}}}}}}},
                                                'required': ['body']}},
 'ai_soc_graph__get_graph_enrich_topology_by_asset_id': {'resource_id': 'e1bae1f6-b54c-4e8a-a393-cac600fcef59',
                                                         'inputSchema': {'type': 'object',
                                                                         'properties': {'assetId': {'type': 'integer',
                                                                                                    'format': 'int64'}},
                                                                         'required': ['assetId']}},
 'ai_soc_graph__get_graph_flow_host_pair_ports': {'resource_id': 'e1bae1f6-b54c-4e8a-a393-cac600fcef59',
                                                  'inputSchema': {'type': 'object',
                                                                  'properties': {'srcIp': {'type': 'string'},
                                                                                 'dstIp': {'type': 'string'},
                                                                                 'timeFrom': {'type': 'string'}},
                                                                  'required': ['dstIp', 'srcIp']}},
 'ai_soc_graph__get_graph_identity_asset_accounts': {'resource_id': 'e1bae1f6-b54c-4e8a-a393-cac600fcef59',
                                                     'inputSchema': {'type': 'object',
                                                                     'properties': {'assetId': {'type': 'integer',
                                                                                                'format': 'int64'}},
                                                                     'required': ['assetId']}},
 'ai_soc_graph__get_graph_lm_login_sequence': {'resource_id': 'e1bae1f6-b54c-4e8a-a393-cac600fcef59',
                                               'inputSchema': {'type': 'object',
                                                               'properties': {'account': {'type': 'string'},
                                                                              'windowStart': {'type': 'integer',
                                                                                              'format': 'int64'},
                                                                              'windowEnd': {'type': 'integer',
                                                                                            'format': 'int64'}},
                                                               'required': ['account',
                                                                            'windowEnd',
                                                                            'windowStart']}},
 'ai_soc_ingest__get_ingest_devices_by_asset_by_asset_id': {'resource_id': '84183787-6570-42af-80d2-a33f70536dac',
                                                            'inputSchema': {'type': 'object',
                                                                            'properties': {'assetId': {'type': 'integer',
                                                                                                       'format': 'int64'}},
                                                                            'required': ['assetId']}},
 'ai_soc_master__get_soc_asset_biz_systems': {'resource_id': '01450128-fd2d-4aec-a5d1-0986683b3355',
                                              'inputSchema': {'type': 'object',
                                                              'properties': {'assetId': {'type': 'integer',
                                                                                         'format': 'int64'}},
                                                              'required': ['assetId']}},
 'ai_soc_master__get_soc_asset_by_asset_id': {'resource_id': '01450128-fd2d-4aec-a5d1-0986683b3355',
                                              'inputSchema': {'type': 'object',
                                                              'properties': {'assetId': {'type': 'integer',
                                                                                         'format': 'int64'}},
                                                              'required': ['assetId']}},
 'ai_soc_master__get_soc_asset_importance': {'resource_id': '01450128-fd2d-4aec-a5d1-0986683b3355',
                                             'inputSchema': {'type': 'object',
                                                             'properties': {'assetId': {'type': 'integer',
                                                                                        'format': 'int64'}},
                                                             'required': ['assetId']}}}
