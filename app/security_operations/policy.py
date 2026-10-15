"""基础策略草案与模拟确认，不生成设备命令。"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address

from .catalog import POLICY_ENDPOINT_FIELDS
from .confirmation import validate_proof
from .state import ASSETS, MockError, STATE, asset, digest, identifier, lookup, remember, replay


def endpoint_candidates(query, side):
    query = query.strip().lower()
    exact = [row for row in ASSETS if query in (str(row["assetId"]), row["ip"], row["name"].lower(), row["hostname"])]
    rows = exact or [row for row in ASSETS if query in row["name"].lower() or query in row["hostname"]]
    if not rows:
        raise MockError(404, "未找到对应模拟端点")
    return [{"candidate_id": digest({"side": side, "asset_id": row["assetId"]}),
             "label": f'{row["name"]}（{row["ip"]}）', "name": row["name"], "ip": row["ip"]} for row in rows]


def endpoint_result(record, selected=None):
    body = record["body"]
    result = {"request_id": body["request_id"], "candidate_set_digest": record["candidate_set_digest"],
              "resolution_status": "SELECTION_REQUIRED", "simulated": True}
    for side in ("source", "destination"):
        candidates = record[side]
        result[side] = {"candidates": deepcopy(candidates)}
        if len(candidates) == 1:
            result[side]["selected_candidate_id"] = candidates[0]["candidate_id"]
    if selected is None and any(len(record[side]) != 1 for side in ("source", "destination")):
        result["result_markdown"] = "### 基础模拟端点选择\n\n请从当前冻结的测试资产中明确选择源和目的；尚未准备或执行策略。"
        return result
    selected = selected or {side: record[side][0]["candidate_id"] for side in ("source", "destination")}
    rows = {side: next(row for row in record[side] if row["candidate_id"] == selected[side]) for side in selected}
    proof = {"candidate_set_digest": result["candidate_set_digest"],
             **{f"selected_{side}_candidate_id": selected[side] for side in selected},
             **{f"{side}_query": rows[side]["ip"] for side in selected}}
    intent = {"schema_version": "workbench-policy-intent/v1", "policy_kind": "NETWORK_ACCESS",
              "operation": "ADD", "action": body["action"], "protocol": body["protocol"],
              "destination_port": body["destination_port"], "target_external_id": None,
              **{side: {"selector_type": "IP", "value": rows[side]["ip"]} for side in selected}}
    if body.get("device_query"):
        intent["device_query"] = body["device_query"]
    result.update(resolution_status="RESOLVED", prepare_body={
        "contract_version": "workbench-policy-configuration/v2", "request_id": body["request_id"],
        "intent": intent, "endpoint_resolution": proof,
    }, result_markdown=("### 需求理解\n\n"
        f'- **源**：{rows["source"]["label"]}\n- **目的**：{rows["destination"]["label"]}\n'
        f'- **协议与目的端口**：{body["protocol"]} {body["destination_port"]}\n'
        f'- **动作**：{"允许" if body["action"] == "ALLOW" else "限制"}基础模拟访问\n\n'
        "以上仅为测试资产的需求理解，尚未准备或执行策略。"))
    for side in selected:
        result[side]["selected_candidate_id"] = selected[side]
    return result


def resolve_endpoints(name, body):
    original = {key: body[key] for key in POLICY_ENDPOINT_FIELDS if key in body}
    key = body["request_id"]
    record = STATE["policy_endpoints"].get(key)
    if record is None:
        if name != "resolve_policy_endpoints":
            raise MockError(409, "必须先解析当前模拟端点")
        if body.get("device_query"):
            devices = endpoint_candidates(body["device_query"], "device")
            if len(devices) != 1 or asset(devices[0]["ip"])["type"] != "FIREWALL":
                raise MockError(422, "指定模拟设备不支持该配置")
        record = {"body": original, "source": endpoint_candidates(body["source_query"], "source"),
                  "destination": endpoint_candidates(body["destination_query"], "destination")}
        record["candidate_set_digest"] = digest(record)
        record["result"] = endpoint_result(record)
        STATE["policy_endpoints"][key] = record
    if digest(record["body"]) != digest(original):
        raise MockError(409, "同一端点请求标识不能用于不同参数")
    if name == "resolve_policy_endpoints":
        return deepcopy(record["result"])
    previous = replay("policy.endpoints.select", key, body)
    if previous is not None:
        return previous
    if (record["result"]["resolution_status"] != "SELECTION_REQUIRED"
            or body["candidate_set_digest"] != record["candidate_set_digest"]):
        raise MockError(409, "端点选择未绑定当前冻结候选")
    selected = {side: body[f"selected_{side}_candidate_id"] for side in ("source", "destination")}
    if any(selected[side] not in {row["candidate_id"] for row in record[side]} for side in selected):
        raise MockError(422, "端点选择必须属于当前冻结候选")
    record["result"] = endpoint_result(record, selected)
    return remember("policy.endpoints.select", key, body, record["result"])


def draft(operation):
    operation.update(operation_status="waiting_user", stage_code="awaiting_confirmation",
                     task_status="DRAFT", result_code="DRAFT_READY", confirmation_required=True,
                     can_decide=True,
                     confirmation_expires_at=(datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat())
    operation["candidate_digest"] = digest({"operation": operation["operation_id"],
                                            "intent": operation["intent"],
                                            "selected": operation.get("selected_candidate_id")})
    operation["result_markdown"] = (
        "### 基础模拟策略草案\n\n状态：DRAFT。\n\n"
        "配置预览：正常测试资产之间的访问配置，命令数组为空。\n\n"
        "```json\n{\"commands\": []}\n```\n\n"
        "仅更新 Mock 进程中的模拟状态，不下发设备配置。请在本会话单独发送“执行”。")


def decide_policy(operation_id, body):
    operation = lookup("policy", operation_id)
    request = {"operationId": operation_id, **body}
    previous = replay("policy.decision", body["request_id"], request)
    if previous is not None:
        return previous
    current_digest = operation.get("candidate_digest", operation["selection"]["candidate_set_digest"])
    if (operation["task_status"] not in {"RUNNING", "DRAFT"} or body["candidate_digest"] != current_digest
            or body["business_revision"] != operation["version"]):
        raise MockError(409, "决定未绑定当前有效模拟草案或候选版本")
    changed = body["decision"] == "REQUEST_CHANGES"
    operation.update(operation_status="cancelled", stage_code="terminal", task_status="CANCELLED",
                     result_code="POLICY_CHANGES_REQUESTED" if changed else "POLICY_REJECTED",
                     confirmation_required=False, can_decide=False,
                     result_markdown="当前模拟草案已关闭，请按修改后的条件重新准备。" if changed else "当前模拟配置已取消，未提交设备配置。")
    operation["selection"]["status"] = "CANCELLED"
    return remember("policy.decision", body["request_id"], request, operation)


def invoke_policy(name, args, base_url):
    if name in {"resolve_policy_endpoints", "choose_ambiguous_policy_endpoints"}:
        return resolve_endpoints(name, args["body"])
    if name == "prepare_policy_configuration":
        body = args["body"]
        previous = replay("policy.prepare", body["request_id"], body)
        if previous is not None:
            return previous
        if "endpoint_resolution" in body:
            resolution = STATE["policy_endpoints"].get(body["request_id"], {}).get("result", {})
            if resolution.get("resolution_status") != "RESOLVED" or resolution.get("prepare_body") != body:
                raise MockError(409, "准备参数未绑定当前已解析的模拟端点")
        intent = body["intent"]
        try:
            source = str(IPv4Address(intent["source"]["value"]))
            destination = str(IPv4Address(intent["destination"]["value"]))
        except ValueError:
            raise MockError(422, "策略源和目的必须是有效 IPv4 地址") from None
        asset(source)
        asset(destination)
        if intent.get("device_query"):
            devices = endpoint_candidates(intent["device_query"], "device")
            if len(devices) != 1:
                raise MockError(422, "指定模拟设备必须唯一")
            device = asset(devices[0]["ip"])
            if device["type"] != "FIREWALL":
                raise MockError(422, "指定模拟设备不支持该配置")
        safe_intent = {"source": source, "destination": destination, "action": intent.get("action", "ALLOW"),
                       "protocol": intent["protocol"], "destination_port": intent["destination_port"]}
        op_id = identifier("op_")
        candidates = [
            {"candidate_id": "candidate-primary", "device_id": "9200", "device_name": ASSETS[2]["name"],
             "label": "测试防火墙（主路径）", "device_query": "mock-firewall", "selectable": True,
             "path_order": 1, "traffic_direction": "FORWARD", "relative_position": "FIRST",
             "coverage": "COMPLETE", "reason_codes": ["path_order_tiebreak"]},
            {"candidate_id": "candidate-secondary", "device_id": "9200", "device_name": ASSETS[2]["name"],
             "label": "测试防火墙（备用路径）", "device_query": "mock-firewall", "selectable": True,
             "path_order": 2, "traffic_direction": "FORWARD", "relative_position": "LAST",
             "coverage": "COMPLETE", "reason_codes": ["path_order_tiebreak"]},
        ]
        operation = {"operation_id": op_id, "task_id": identifier("task_"), "version": 1,
                     "contract_version": "workbench-policy-configuration/v2", "intent": safe_intent,
                     "accepted": True, "duplicate": False, "simulated": True,
                     "operation_status": "running", "stage_code": "awaiting_candidate_selection",
                     "task_status": "RUNNING", "result_code": "CANDIDATE_SELECTION_REQUIRED",
                     "confirmation_required": False, "can_decide": False,
                     "selection": {"status": "PENDING", "candidate_set_digest": digest(candidates), "business_revision": 1,
                                   "candidates": candidates}}
        operation["candidate"] = {"candidates": deepcopy(candidates), "business_revision": 1,
                                  "candidate_set_digest": digest(candidates), "intent_digest": digest(safe_intent),
                                  "replacement_required": False}
        if intent.get("device_query"):
            operation["selected_candidate_id"] = "candidate-primary"
            operation["selection"]["status"] = "SELECTED"
            draft(operation)
        STATE["policy"][op_id] = operation
        return remember("policy.prepare", body["request_id"], body, operation)

    operation = lookup("policy", args["operationId"])
    if name in {"get_policy_configuration_status", "get_policy_configuration_result"}:
        return deepcopy(operation)
    body = args["body"]
    if name == "select_policy_configuration_candidate":
        selection = operation["selection"]
        expected = {row["candidate_id"] for row in selection["candidates"]}
        if selection["status"] != "PENDING":
            raise MockError(409, "当前模拟草案不等待候选排序")
        if body["candidate_set_digest"] != selection["candidate_set_digest"]:
            raise MockError(409, "候选摘要与当前模拟草案不一致")
        if set(body["ranked_candidate_ids"]) != expected or len(body["ranked_candidate_ids"]) != len(expected):
            raise MockError(422, "排序必须包含当前全部候选且不得重复")
        operation["selected_candidate_id"] = body["ranked_candidate_ids"][0]
        selection["status"] = "SELECTED"
        draft(operation)
        return deepcopy(operation)
    if name == "confirm_policy_configuration":
        request = {"operationId": args["operationId"], **body}
        previous = replay("policy.confirm", body["request_id"], request)
        if previous is not None:
            return previous
        if (operation.get("candidate_digest") != body["candidate_digest"] or operation["task_status"] != "DRAFT"
                or datetime.fromisoformat(operation["confirmation_expires_at"]) <= datetime.now(timezone.utc)):
            raise MockError(409, "确认未绑定当前有效模拟草案")
        if "proof" in body:
            validate_proof(body["proof"], operation, "candidate_digest", "strategy.apply")
        operation.update(operation_status="completed", stage_code="completed", task_status="SUCCEEDED",
                         result_code="SUCCESS", confirmation_required=False, can_decide=False,
                         failure_scope="NONE", confirmation={"accepted": True, "approval_receipt_id": identifier("receipt_")},
                         execution={"status": "SUCCEEDED", "simulated": True, "operation_status": "terminal",
                                    "task_status": "SUCCEEDED", "result_code": "SUCCESS"},
                         confirmation_proof_verified=False,
                         result_markdown="模拟配置已完成。仅更新 Mock 状态，没有下发真实设备配置。")
        return remember("policy.confirm", body["request_id"], request, operation)
    raise MockError(404, "未找到对应模拟工具")
