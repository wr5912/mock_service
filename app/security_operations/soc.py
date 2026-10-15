"""SOC 固定取证链的正常运维样例和研判状态模拟。"""
from copy import deepcopy
import re

from .state import ASSETS, INCIDENT_IDS, MockError, STATE, asset, digest, identifier, lookup


EVENT_TIME = "2026-10-15T01:00:00Z"


def incident(incident_id):
    if incident_id not in INCIDENT_IDS:
        raise MockError(404, "未找到对应模拟事件")
    index = INCIDENT_IDS.index(incident_id)
    row = ASSETS[index]
    return {"incidentId": incident_id, "id": incident_id, "title": "例行运维检查测试事件",
            "description": "测试资产例行检查产生的基础记录，设备状态正常。",
            "severity": "LOW", "status": "OPEN", "affectedAssetId": row["assetId"],
            "targetIp": row["ip"], "contributingAlertsJson": ["MOCK-ALERT-00000" + str(index + 1)],
            "firstSeenTime": EVENT_TIME, "lastSeenTime": EVENT_TIME,
            "ruleId": 1, "entitiesJson": [{"type": "ASSET", "assetId": row["assetId"]},
                                          {"type": "IP", "value": row["ip"]}]}


def alert(alert_id):
    ids = ["MOCK-ALERT-000001", "MOCK-ALERT-000002"]
    if alert_id not in ids:
        raise MockError(404, "未找到对应模拟告警")
    row = ASSETS[ids.index(alert_id)]
    return {"alert_id": alert_id, "id": alert_id, "title": "正常运维测试告警",
            "description": "例行健康检查的基础测试数据。", "severity": "LOW", "rule_id": 1,
            "affected_asset_id": row["assetId"], "affectedAssetId": row["assetId"],
            "created_at": EVENT_TIME, "alert_type": "HEALTH_CHECK", "destination_ip": row["ip"],
            "ocsf": {"activity_name": "例行健康检查", "class_name": "设备状态",
                     "metadata": {"original_time": EVENT_TIME, "product": {"name": "基础模拟服务"}},
                     "device": {"uid": str(row["assetId"]), "ip": row["ip"], "hostname": row["hostname"]}}}


def context(kind, value):
    row = asset(value)
    if kind == "asset":
        return row
    if kind == "importance":
        return {"assetId": row["assetId"], "importance": "NORMAL", "score": 1}
    if kind == "business":
        return [{"id": "mock-business", "name": "测试业务系统", "assetId": row["assetId"]}]
    if kind == "bindings":
        return [{"id": "mock-collector", "assetId": row["assetId"], "name": "测试采集器", "status": "ONLINE"}]
    if kind == "topology":
        return {"nodes": [row], "edges": [], "assetId": row["assetId"]}
    if kind == "accounts":
        return [{"account": "mock-operator", "assetId": row["assetId"]}]
    return []


def soc_data(tool_name, args):
    suffix = tool_name.split("__", 1)[1]
    if suffix == "get_correlate_incident_by_incident_id":
        return incident(args["incidentId"])
    if suffix == "get_detect_alert_by_alert_id":
        return alert(args["alertId"])
    if suffix == "list_detect_whitelist":
        return [{"whitelistId": "mock-whitelist-1", "type": "ASSET_ID", "value": "9106",
                 "enabled": True, "scopeRuleIds": [], "description": "正常测试资产"}]
    if suffix == "get_correlate_threat_intel":
        return {"rows": [], "total": 0}
    if suffix == "get_correlate_intel_check":
        return {"hit": False, "matched": False, "items": []}
    if suffix == "get_correlate_reasoning_rules_by_rule_id":
        if args["ruleId"] != 1:
            raise MockError(404, "未找到对应模拟规则")
        return {"id": 1, "name": "例行运维检查", "description": "核对测试资产的健康检查记录。"}
    kinds = {"get_soc_asset_by_asset_id": "asset", "get_soc_asset_importance": "importance",
             "get_soc_asset_biz_systems": "business", "get_ingest_devices_by_asset_by_asset_id": "bindings",
             "get_graph_enrich_topology_by_asset_id": "topology", "get_graph_identity_asset_accounts": "accounts"}
    if suffix in kinds:
        return context(kinds[suffix], args["assetId"])
    if suffix == "search_event":
        return {"hits": [], "total": 0}
    if suffix in {"get_graph_lm_login_sequence", "get_graph_flow_host_pair_ports"}:
        return []
    if suffix == "get_correlate_incident_judge_pending":
        if not 1 <= args.get("pageSize", 20) <= 100:
            raise MockError(422, "待研判分页大小须介于 1 与 100")
        rows = [{"incidentId": key, "title": "例行运维检查测试事件"}
                for key in INCIDENT_IDS if key not in STATE["claims"]]
        size = args.get("pageSize", 20)
        offset = (max(1, args.get("pageNum", 1)) - 1) * size
        return {"rows": rows[offset:offset + size], "total": len(rows)}
    if suffix == "create_incident_judgement_claim":
        incident_id = args["incidentId"]
        incident(incident_id)
        if incident_id in STATE["claims"]:
            raise MockError(409, "该模拟事件已认领")
        claim = {"incidentId": incident_id, "judgementId": identifier("judgement_"), "status": "CLAIMED"}
        STATE["claims"][incident_id] = claim
        return deepcopy(claim)
    if suffix in {"update_incident_judgement_result", "create_correlate_incident_judgement_fail"}:
        judgement_id = args["judgementId"]
        claim = next((value for value in STATE["claims"].values() if value["judgementId"] == judgement_id), None)
        if claim is None:
            raise MockError(404, "未找到对应模拟认领记录")
        body = args["body"]
        run_id = body.get("runId", "")
        if not isinstance(run_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", run_id):
            raise MockError(422, "模拟回写缺少有效运行标识")
        key = (judgement_id, run_id)
        fingerprint = digest({"tool": tool_name, "body": body})
        previous = STATE["writebacks"].get(key)
        if previous:
            if previous["digest"] != fingerprint:
                raise MockError(409, "同一模拟研判运行的结果不能覆盖")
            return {**deepcopy(previous["result"]), "replayed": True}
        if claim["status"] != "CLAIMED":
            raise MockError(409, "该模拟认领已完成回写")
        status = "COMPLETED" if suffix == "update_incident_judgement_result" else "FAILED"
        claim["status"] = status
        result = {"judgementId": judgement_id, "incidentId": claim["incidentId"], "runId": run_id,
                  "status": status, "replayed": False, "simulated": True}
        STATE["writebacks"][key] = {"digest": fingerprint, "result": result}
        return deepcopy(result)
    raise MockError(404, "未找到对应模拟工具")
