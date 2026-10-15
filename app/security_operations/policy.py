"""基础策略草案与模拟确认，不生成设备命令。"""
from copy import deepcopy
from ipaddress import IPv4Address

from .state import ASSETS, MockError, STATE, asset, digest, identifier, lookup, remember, replay


def draft(operation):
    operation.update(operation_status="waiting_user", stage_code="awaiting_confirmation",
                     task_status="DRAFT", result_code="DRAFT_READY", confirmation_required=True,
                     can_decide=True)
    operation["candidate_digest"] = digest({"operation": operation["operation_id"],
                                            "intent": operation["intent"],
                                            "selected": operation.get("selected_candidate_id")})
    operation["result_markdown"] = (
        "### 基础模拟策略草案\n\n状态：DRAFT。\n\n"
        "配置预览：正常测试资产之间的访问配置，命令数组为空。\n\n"
        "```json\n{\"commands\": []}\n```\n\n"
        "仅更新 Mock 进程中的模拟状态，不下发设备配置。请在本会话单独发送“执行”。")


def invoke_policy(name, args, base_url):
    if name == "prepare_policy_configuration":
        body = args["body"]
        previous = replay("policy.prepare", body["request_id"], body)
        if previous is not None:
            return previous
        intent = body["intent"]
        try:
            source = str(IPv4Address(intent["source"]["value"]))
            destination = str(IPv4Address(intent["destination"]["value"]))
        except ValueError:
            raise MockError(422, "策略源和目的必须是有效 IPv4 地址") from None
        asset(source)
        asset(destination)
        if intent.get("device_query"):
            device = asset(intent["device_query"])
            if device["type"] != "FIREWALL":
                raise MockError(422, "指定模拟设备不支持该配置")
        safe_intent = {"source": source, "destination": destination,
                       "protocol": intent["protocol"], "destination_port": intent["destination_port"]}
        op_id = identifier("op_")
        candidates = [
            {"candidate_id": "candidate-primary", "device_id": "9200", "device_name": ASSETS[2]["name"],
             "path_order": 1, "traffic_direction": "FORWARD", "relative_position": "FIRST",
             "coverage": "COMPLETE", "reason_codes": ["path_order_tiebreak"]},
            {"candidate_id": "candidate-secondary", "device_id": "9200", "device_name": ASSETS[2]["name"],
             "path_order": 2, "traffic_direction": "FORWARD", "relative_position": "LAST",
             "coverage": "COMPLETE", "reason_codes": ["path_order_tiebreak"]},
        ]
        operation = {"operation_id": op_id, "task_id": identifier("task_"),
                     "contract_version": "workbench-policy-configuration/v2", "intent": safe_intent,
                     "accepted": True, "duplicate": False, "simulated": True,
                     "operation_status": "running", "stage_code": "awaiting_candidate_selection",
                     "task_status": "RUNNING", "result_code": "CANDIDATE_SELECTION_REQUIRED",
                     "confirmation_required": False, "can_decide": False,
                     "selection": {"status": "PENDING", "candidate_set_digest": digest(candidates),
                                   "candidates": candidates}}
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
        if operation.get("candidate_digest") != body["candidate_digest"] or operation["task_status"] != "DRAFT":
            raise MockError(409, "确认未绑定当前有效模拟草案")
        operation.update(operation_status="completed", stage_code="completed", task_status="SUCCEEDED",
                         result_code="SIMULATION_COMPLETED", confirmation_required=False, can_decide=False,
                         failure_scope="NONE", confirmation={"accepted": True, "approval_receipt_id": identifier("receipt_")},
                         execution={"status": "SUCCEEDED", "simulated": True},
                         result_markdown="模拟配置已完成。仅更新 Mock 状态，没有下发真实设备配置。")
        return remember("policy.confirm", body["request_id"], request, operation)
    raise MockError(404, "未找到对应模拟工具")
