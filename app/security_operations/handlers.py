"""工具、SOC HTTP 和报告下载共用的基础模拟行为。"""
from __future__ import annotations

from copy import deepcopy
import base64
import binascii
from html import escape
import re

from jsonschema import Draft202012Validator

from .catalog import POLICY_DECISION_SCHEMA, SOC_TOOLS, TOOL_GROUPS, TOOL_INPUT_SCHEMAS
from .emergency import confirm_emergency as _confirm_emergency, emergency_result as _emergency_result, invoke_emergency
from .policy import decide_policy as _decide_policy, invoke_policy
from .soc import context, incident, soc_data
from .state import ASSETS, HTML, INCIDENT_IDS, LOCK, STATE, MockError, asset, identifier, lookup, remember, replay, reset_state, validate_identifier


def validate(schema, args):
    if not isinstance(args, dict) or not Draft202012Validator(schema).is_valid(args):
        raise MockError(422, "模拟工具参数不符合输入合同")


def report_url(base_url, report_id):
    return base_url.rstrip("/") + "/reports/" + report_id + ".html"


def create_report(metadata):
    report_id = identifier("report_")
    fields = {"reportId": report_id, **metadata}
    STATE["reports"][report_id] = HTML.format(metadata="".join(
        f"<dt>{escape(key)}</dt><dd>{escape(str(value))}</dd>" for key, value in fields.items()))
    return report_id


def report_html(report_id):
    validate_identifier(report_id)
    with LOCK:
        return lookup("reports", report_id)


def sec_ops(name, args):
    if name in {"search_graph_assets", "list_soc_asset"}:
        query = args.get("q", args.get("ip", args.get("keyword", "")))
        rows = [deepcopy(row) for row in ASSETS if not query or any(query.lower() in str(row[key]).lower()
                                                                  for key in ("assetId", "name", "hostname", "ip"))]
        size = args.get("limit", args.get("pageSize", 20))
        page = args.get("pageNum", 1)
        if isinstance(size, bool) or size < 1 or size > 100 or page < 1:
            raise MockError(422, "模拟分页参数无效")
        return {"items": rows[(page - 1) * size:page * size], "total": len(rows)}
    if name == "get_graph_resolve_ip_host":
        return {"hosts": [asset(args["ip"])]}
    kinds = {"get_soc_asset_by_asset_id": "asset", "get_soc_asset_biz_systems": "business",
             "get_ingest_devices_by_asset_by_asset_id": "bindings"}
    if name in kinds:
        return context(kinds[name], args["assetId"])
    if name == "get_soc_asset_vulnerabilities":
        asset(args["assetId"])
        return {"items": [], "total": 0}
    if name == "get_graph_node_detail":
        return {"node": asset(args["vid"]), "edges": []}
    if name in {"get_graph_path_query", "get_reachability_path_by_ip"}:
        source = asset(args.get("srcIp", args.get("srcVid")))
        destination = asset(args.get("dstIp", args.get("dstVid")))
        return {"reachable": True, "paths": [{"nodes": [source, deepcopy(ASSETS[2]), destination],
                                               "status": "AVAILABLE", "simulated": True}]}
    if name == "get_graph_flow_host_pair_ports":
        asset(args["srcIp"])
        asset(args["dstIp"])
        return []
    if name == "get_reachability_cross_signal":
        return {"registered": len(ASSETS), "observed": len(ASSETS), "missing": 0, "items": []}
    if name == "get_graph_compliance_violations":
        return {"items": [], "total": 0}
    if name == "get_graph_coverage":
        return {"collected": len(ASSETS), "registered": len(ASSETS), "discovered": 0, "coveragePct": 100}
    if name == "get_event_by_id":
        return incident(args["eventId"])
    raise MockError(404, "未找到对应模拟工具")


TASK = {"taskId": "mock-health-inspection", "definitionVersion": 1, "name": "基础资产健康巡检",
        "description": "检查当前资产清单中的全部测试资产。", "scopeLabel": "当前全部测试资产",
        "inspectionItems": [{"id": "availability", "name": "资产在线状态"},
                            {"id": "collection", "name": "采集连接状态"}],
        "status": "PUBLISHED", "enabled": True}


def inspection(name, args, base_url):
    if name == "list_executable_inspections":
        return {"items": [deepcopy(TASK)], "total": 1}
    if name == "start_inspection":
        previous = replay("inspection.start", args["requestId"], args)
        if previous is not None:
            return previous
        if args["taskId"] != TASK["taskId"]:
            raise MockError(404, "未找到对应模拟巡检模板")
        if str(args["definitionVersion"]) != str(TASK["definitionVersion"]):
            raise MockError(409, "模拟巡检模板版本不一致")
        scoped = [asset(value) for value in args.get("scope", {}).get("assetIds", [])] if args.get("scope") else deepcopy(ASSETS)
        run_id = identifier("inspection_")
        result = {"runId": run_id, "requestId": args["requestId"], "taskId": TASK["taskId"],
                  "status": "RUNNING", "reportDownloadUrl": None, "simulated": True}
        STATE["inspection"][run_id] = {"result": result, "queries": 0, "asset_count": len(scoped),
                                       "scope": "指定测试资产" if args.get("scope") else TASK["scopeLabel"]}
        return remember("inspection.start", args["requestId"], args, result)
    record = lookup("inspection", args["runId"])
    record["queries"] += 1
    result = record["result"]
    if record["queries"] >= 2 and result["status"] == "RUNNING":
        metadata = {"kind": "inspection", "runId": result["runId"], "taskId": TASK["taskId"],
                    "definitionVersion": TASK["definitionVersion"], "assetCount": record["asset_count"]}
        report_id = create_report(metadata)
        result.update(status="COMPLETED", conclusionStatus="NORMAL", reportReady=True,
                      reportDownloadUrl=report_url(base_url, report_id), scopeLabel=record["scope"],
                      reportKind="basic_mock", originalContentStored=False, reportMetadata=metadata,
                      deviceCount=record["asset_count"], assetCount=record["asset_count"],
                      businessSummary="例行检查正常，测试资产与采集连接均在线。",
                      reportMarkdown="### 基础资产健康巡检\n\n测试资产在线，采集连接正常。仅提供基础模拟数据。",
                      items=[{"name": "资产在线状态", "status": "NORMAL", "count": record["asset_count"]},
                             {"name": "采集连接状态", "status": "NORMAL", "count": record["asset_count"]}])
    return deepcopy(result)


def save_report(args, base_url):
    try:
        content = base64.b64decode(args["fileContentBase64"], validate=True)
        if len(content) > 1048576:
            raise ValueError
    except (ValueError, binascii.Error):
        raise MockError(422, "模拟报告内容不是有效的限定大小 Base64") from None
    key = str(args["businessId"]) + ":" + str(args["revision"])
    previous = replay("report.save", key, args)
    if previous is not None:
        return previous
    metadata = {"kind": "unlinked"}
    # 报告请求本身没有 route；只从同一运行已接受的 SOC 回写读取基本身份。
    run_id = args["businessId"]
    if args["sourceModule"] == "threat-analysis" and re.fullmatch(
            r"run-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", run_id):
        records = [record for record in STATE["writebacks"].values() if record["result"]["runId"] == run_id]
        if len(records) > 1:
            raise MockError(409, "模拟报告运行身份不唯一")
        if records:
            record = records[0]
            incident_id, route = record["result"]["incidentId"], record.get("report_route")
            if (record["result"]["status"] != "COMPLETED" or incident_id not in INCIDENT_IDS
                    or route not in {"fast_classification", "five_source"}
                    or args["fileName"] != incident_id + "-" + run_id + ".html"):
                raise MockError(422, "模拟报告元数据未与已完成的本次运行一致")
            metadata = {"kind": "threat_analysis", "runId": run_id, "incidentId": incident_id, "route": route}
    report_id = create_report(metadata)
    result = {"id": report_id, "downloadUrl": report_url(base_url, report_id), "simulated": True,
              "reportKind": "basic_mock", "originalContentStored": False,
              "metadataStatus": "LINKED" if metadata["kind"] == "threat_analysis" else "UNLINKED",
              "reportMetadata": metadata}
    return remember("report.save", key, args, result)


def invoke(group, name, args, base_url):
    definition = next((tool for tool in TOOL_GROUPS.get(group, []) if tool["name"] == name), None)
    if definition is None:
        raise MockError(404, "未找到对应模拟工具")
    validate(TOOL_INPUT_SCHEMAS[name], args)
    with LOCK:
        if group == "sec-ops":
            data = sec_ops(name, args)
        elif group == "inspection":
            data = inspection(name, args, base_url)
        elif group == "policy-configuration":
            data = invoke_policy(name, args, base_url)
        elif group == "emergency-action":
            data = invoke_emergency(name, args, base_url)
        else:
            data = save_report(args, base_url)
        return {"code": "200" if group in {"policy-configuration", "emergency-action"} else 200,
                "message": "基础模拟数据", "data": data}


def invoke_soc(resource_id, tool_name, args, base_url):
    definition = SOC_TOOLS.get(tool_name)
    if definition is None or definition["resource_id"] != resource_id:
        raise MockError(404, "未找到对应模拟资源或工具")
    validate(definition["inputSchema"], args)
    for key in ("incidentId", "alertId", "judgementId"):
        if key in args:
            validate_identifier(args[key])
    if isinstance(args.get("body"), dict) and "runId" in args["body"]:
        validate_identifier(args["body"]["runId"])
    with LOCK:
        data = soc_data(tool_name, args)
        return {"status": "success", "status_code": 200, "result": {"code": 200, "data": data}}


def confirm_emergency(operation_id, body):
    with LOCK:
        return _confirm_emergency(operation_id, body)


def emergency_result(operation_id):
    with LOCK:
        return _emergency_result(operation_id)


def decide_policy(operation_id, body):
    validate_identifier(operation_id)
    validate(POLICY_DECISION_SCHEMA, body)
    with LOCK:
        return _decide_policy(operation_id, body)
