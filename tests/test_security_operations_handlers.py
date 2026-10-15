import base64
import json

import pytest

from app.security_operations.catalog import SOC_TOOLS, TOOL_GROUPS
from app.security_operations.handlers import (
    confirm_emergency, emergency_result, invoke, invoke_soc, report_html, reset_state,
)
from app.security_operations.state import INCIDENT_IDS, STATE, MockError


BASE = "http://mock.test"


@pytest.fixture(autouse=True)
def isolated_state():
    reset_state()
    yield
    reset_state()


def call(group, name, args=None):
    return invoke(group, name, args or {}, BASE)["data"]


def soc(name, args):
    definition = SOC_TOOLS[name]
    result = invoke_soc(definition["resource_id"], name, args, BASE)
    assert result["status"] == "success"
    assert result["result"]["code"] == 200
    return result["result"]["data"]


def policy_body(request_id="policy-1", device=None):
    intent = {
        "schema_version": "workbench-policy-intent/v1", "policy_kind": "NETWORK_ACCESS", "operation": "ADD",
        "source": {"selector_type": "IP", "value": "192.0.2.10"},
        "destination": {"selector_type": "IP", "value": "192.0.2.20"},
        "protocol": "TCP", "destination_port": 443, "target_external_id": None,
    }
    if device:
        intent["device_query"] = device
    return {"body": {"contract_version": "workbench-policy-configuration/v2", "request_id": request_id, "intent": intent}}


def prepare_emergency(request_id="emergency-1"):
    args = {"body": {"request_id": request_id, "intent": "隔离测试主机", "target_hint": "192.0.2.10"}}
    return args, call("emergency-action", "prepare_emergency_action", args)


def confirmation(operation, request_id="confirm-1"):
    payload = {"operation_id": operation["operation_id"], "version": operation["version"],
               "snapshot_digest": operation["snapshot_digest"], "decision": "CONFIRM"}
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return {"request_id": request_id, "expected_version": operation["version"],
            "snapshot_digest": operation["snapshot_digest"], "confirmation_event_ref": encoded + ".mock-proof"}


def test_catalog_counts_and_dsh_schema_subset():
    assert {key: len(value) for key, value in TOOL_GROUPS.items()} == {
        "sec-ops": 15, "inspection": 3, "policy-configuration": 7, "emergency-action": 6, "report": 1,
    }
    assert len(SOC_TOOLS) == 19

    def walk(value):
        if isinstance(value, dict):
            assert not isinstance(value.get("type"), list)
            if "const" in value or "enum" in value:
                assert "type" in value
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(TOOL_GROUPS)


@pytest.mark.parametrize("group,name,args,status", [
    ("unknown", "list_soc_asset", {}, 404), ("sec-ops", "unknown", {}, 404),
    ("sec-ops", "get_soc_asset_by_asset_id", {}, 422),
    ("sec-ops", "get_soc_asset_by_asset_id", {"assetId": "9106"}, 422),
    ("sec-ops", "get_soc_asset_by_asset_id", {"assetId": 9999}, 404),
    ("inspection", "get_inspection_result", {"runId": "missing"}, 404),
])
def test_unknown_and_invalid_calls(group, name, args, status):
    with pytest.raises(MockError) as failure:
        call(group, name, args)
    assert failure.value.status_code == status


def test_inspection_async_idempotence_and_real_report():
    task = call("inspection", "list_executable_inspections")["items"][0]
    args = {key: task[key] for key in ("taskId", "definitionVersion")}
    args["requestId"] = "inspection-1"
    started = call("inspection", "start_inspection", args)
    assert started["status"] == "RUNNING"
    assert call("inspection", "start_inspection", args)["runId"] == started["runId"]
    assert call("inspection", "get_inspection_result", {"runId": started["runId"]})["reportDownloadUrl"] is None
    completed = call("inspection", "get_inspection_result", {"runId": started["runId"]})
    assert completed["status"] == "COMPLETED"
    assert completed["assetCount"] == 3
    report_id = completed["reportDownloadUrl"].rsplit("/", 1)[1].removesuffix(".html")
    assert "基础模拟报告" in report_html(report_id)
    assert started["runId"] in report_html(report_id)
    assert completed["reportMetadata"] == {"kind": "inspection", "runId": started["runId"],
                                            "taskId": task["taskId"], "definitionVersion": 1, "assetCount": 3}
    assert completed["originalContentStored"] is False
    with pytest.raises(MockError) as failure:
        call("inspection", "start_inspection", {**args, "scope": {"type": "ASSET_IDS", "assetIds": ["9106"]}})
    assert failure.value.status_code == 409


def test_policy_selection_draft_binding_and_confirmation_replay():
    args = policy_body()
    prepared = call("policy-configuration", "prepare_policy_configuration", args)
    assert prepared == call("policy-configuration", "prepare_policy_configuration", args)
    operation_id = prepared["operation_id"]
    selection = prepared["selection"]
    draft = call("policy-configuration", "select_policy_configuration_candidate", {
        "operationId": operation_id, "body": {"candidate_set_digest": selection["candidate_set_digest"],
        "ranked_candidate_ids": [row["candidate_id"] for row in selection["candidates"]], "reason_codes": ["path_order_tiebreak"]},
    })
    assert draft["task_status"] == "DRAFT"
    assert "\"commands\": []" in draft["result_markdown"]
    wrong = {"operationId": operation_id, "body": {"request_id": "confirm-1", "candidate_digest": "sha256:wrong"}}
    with pytest.raises(MockError):
        call("policy-configuration", "confirm_policy_configuration", wrong)
    confirmed_args = {"operationId": operation_id, "body": {"request_id": "confirm-1", "candidate_digest": draft["candidate_digest"]}}
    confirmed = call("policy-configuration", "confirm_policy_configuration", confirmed_args)
    assert confirmed["confirmation"]["accepted"] is True
    assert confirmed["execution"]["simulated"] is True
    assert confirmed == call("policy-configuration", "confirm_policy_configuration", confirmed_args)
    assert invoke("policy-configuration", "get_policy_configuration_result", {"operationId": operation_id}, BASE)["code"] == "200"


def test_policy_rejects_unknown_device_and_same_key_new_intent():
    args = policy_body(device="mock-firewall")
    assert call("policy-configuration", "prepare_policy_configuration", args)["task_status"] == "DRAFT"
    args["body"]["intent"]["destination_port"] = 8443
    with pytest.raises(MockError) as failure:
        call("policy-configuration", "prepare_policy_configuration", args)
    assert failure.value.status_code == 409
    with pytest.raises(MockError):
        call("policy-configuration", "prepare_policy_configuration", policy_body("policy-2", "unknown"))


def test_emergency_revision_rejects_stale_confirmation_and_completes_bound_draft():
    args, first = prepare_emergency()
    assert call("emergency-action", "prepare_emergency_action", args) == first
    revised = call("emergency-action", "revise_emergency_action", {"operationId": first["operation_id"], "body": {
        "request_id": "revise-1", "expected_version": 1, "intent": "解除隔离测试主机"}})
    assert revised["version"] == 2
    assert revised["snapshot"]["action_key"] == "host-unisolate"
    with pytest.raises(MockError) as failure:
        confirm_emergency(first["operation_id"], confirmation(first))
    assert failure.value.status_code == 409
    body = confirmation(revised)
    confirmed = confirm_emergency(revised["operation_id"], body)
    assert confirmed["phase"] == "TERMINAL"
    assert confirmed["execution_status"] == "SUCCEEDED"
    assert confirm_emergency(revised["operation_id"], body) == confirmed
    assert emergency_result(revised["operation_id"])["snapshot_digest"] == revised["snapshot_digest"]


def test_emergency_cancel_and_bad_proof_are_not_execution():
    _, prepared = prepare_emergency()
    body = confirmation(prepared)
    body["confirmation_event_ref"] = "invalid"
    with pytest.raises(MockError):
        confirm_emergency(prepared["operation_id"], body)
    assert emergency_result(prepared["operation_id"])["execution_status"] == "NOT_SUBMITTED"
    args = {"operationId": prepared["operation_id"], "body": {"request_id": "cancel-1", "expected_version": 1}}
    cancelled = call("emergency-action", "cancel_emergency_action", args)
    assert cancelled["phase"] == "CANCELLED"
    assert cancelled == call("emergency-action", "cancel_emergency_action", args)
    with pytest.raises(MockError):
        confirm_emergency(prepared["operation_id"], confirmation(prepared))


def test_soc_claim_writeback_and_pending_share_identity():
    pending = "ai_soc_correlate__get_correlate_incident_judge_pending"
    assert soc(pending, {"pageNum": 1, "pageSize": 100})["total"] == 2
    claim = soc("ai_soc_correlate__create_incident_judgement_claim", {"incidentId": INCIDENT_IDS[0]})
    assert soc(pending, {})["total"] == 1
    with pytest.raises(MockError) as failure:
        soc("ai_soc_correlate__create_incident_judgement_claim", {"incidentId": INCIDENT_IDS[0]})
    assert failure.value.status_code == 409
    body = {"runId": "run_mock_1", "route": "fast_classification", "verdict": "误报",
            "validationStatus": "not_applicable_fast_classification", "summary": "正常测试记录", "resultJson": {}}
    args = {"judgementId": claim["judgementId"], "body": body}
    name = "ai_soc_correlate__update_incident_judgement_result"
    assert soc(name, args)["incidentId"] == INCIDENT_IDS[0]
    assert soc(name, args)["replayed"] is True
    with pytest.raises(MockError):
        soc(name, {**args, "body": {**body, "summary": "另一条正常记录"}})


def test_soc_rejects_mismatched_resource_and_unknown_event():
    name = "ai_soc_correlate__get_correlate_incident_by_incident_id"
    with pytest.raises(MockError):
        invoke_soc("wrong-resource", name, {"incidentId": INCIDENT_IDS[0]}, BASE)
    with pytest.raises(MockError):
        soc(name, {"incidentId": "INC-20261015-999999"})


def test_report_never_returns_caller_html_and_has_stable_id():
    marker = "UNTRUSTED_INPUT_MARKER"
    args = {"businessId": "mock-run", "sourceModule": "threat-analysis", "revision": 1,
            "resultType": "report", "contentType": "text/html", "fileName": "report.html",
            "fileContentBase64": base64.b64encode(marker.encode()).decode()}
    result = invoke("report", "save_persistence_result", args, BASE)
    assert result["code"] == 200
    assert result["data"]["originalContentStored"] is False
    assert result["data"]["metadataStatus"] == "UNLINKED"
    assert marker not in report_html(result["data"]["id"])
    assert result == invoke("report", "save_persistence_result", args, BASE)
    with pytest.raises(MockError):
        report_html("unknown")
    with pytest.raises(MockError):
        invoke("report", "save_persistence_result", {**args, "fileContentBase64": "not-base64"}, BASE)


def report_args(run_id, incident_id, text="基础上传正文不保留"):
    return {"businessId": run_id, "sourceModule": "threat-analysis", "revision": 1,
            "resultType": "report", "contentType": "text/html", "fileName": incident_id + "-" + run_id + ".html",
            "fileContentBase64": base64.b64encode(text.encode()).decode()}


def complete_report_run(run_id, incident_id, route, marker="基础上游文字"):
    claim = soc("ai_soc_correlate__create_incident_judgement_claim", {"incidentId": incident_id})
    body = {"runId": run_id, "route": route, "verdict": "误报", "validationStatus": "passed",
            "summary": marker, "reportHtml": marker,
            "resultJson": {"run_id": run_id, "incident_id": incident_id, "route": route, "detail": marker}}
    soc("ai_soc_correlate__update_incident_judgement_result", {"judgementId": claim["judgementId"], "body": body})


def test_threat_reports_bind_distinct_runs_without_storing_or_reflecting_upstream_content():
    marker = "BASIC_UPSTREAM_CONTENT_NOT_RETAINED"
    artifacts = []
    for index, route in enumerate(("fast_classification", "five_source"), 1):
        run_id = f"run-00000000-0000-4000-8000-{index:012d}"
        incident_id = INCIDENT_IDS[index - 1]
        complete_report_run(run_id, incident_id, route, marker)
        result = call("report", "save_persistence_result", report_args(run_id, incident_id, "<article>" + marker + "</article>"))
        assert result["metadataStatus"] == "LINKED"
        assert result["originalContentStored"] is False
        assert result["reportKind"] == "basic_mock"
        assert result["reportMetadata"] == {"kind": "threat_analysis", "runId": run_id, "incidentId": incident_id, "route": route}
        html = report_html(result["id"])
        assert all(value in html for value in (result["id"], run_id, incident_id, route))
        assert "上传的报告正文未保存" in html
        artifacts.append(html)
    assert artifacts[0] != artifacts[1]
    assert marker not in repr(STATE)


@pytest.mark.parametrize("mismatch", ["fileName", "route"])
def test_threat_report_rejects_unbound_filename_or_non_enum_route(mismatch):
    run_id = "run-00000000-0000-4000-8000-000000000001"
    complete_report_run(run_id, INCIDENT_IDS[0], "five_source" if mismatch == "fileName" else "BASIC_UNKNOWN_ROUTE")
    args = report_args(run_id, INCIDENT_IDS[1] if mismatch == "fileName" else INCIDENT_IDS[0])
    with pytest.raises(MockError) as failure:
        call("report", "save_persistence_result", args)
    assert failure.value.status_code == 422
    assert not STATE["reports"]
    assert "BASIC_UNKNOWN_ROUTE" not in repr(STATE)


def test_report_without_soc_writeback_or_valid_run_format_is_explicitly_unlinked():
    for run_id in ("run-00000000-0000-4000-8000-000000000001", "run-00000000-0000-3000-8000-000000000001"):
        result = call("report", "save_persistence_result", report_args(run_id, INCIDENT_IDS[0]))
        assert result["metadataStatus"] == "UNLINKED"
        assert result["originalContentStored"] is False
        assert result["reportMetadata"] == {"kind": "unlinked"}
        assert run_id not in report_html(result["id"])


@pytest.mark.parametrize("port", [-1, 0, 65536, True])
def test_policy_full_schema_retains_port_bounds(port):
    args = policy_body()
    args["body"]["intent"]["destination_port"] = port
    with pytest.raises(MockError) as failure:
        call("policy-configuration", "prepare_policy_configuration", args)
    assert failure.value.status_code == 422


def test_inspection_full_schema_rejects_empty_scope_before_creating_run():
    args = {"taskId": "mock-health-inspection", "definitionVersion": 1, "requestId": "inspection-1",
            "scope": {"type": "ASSET_IDS", "assetIds": []}}
    with pytest.raises(MockError) as failure:
        call("inspection", "start_inspection", args)
    assert failure.value.status_code == 422
    assert call("inspection", "start_inspection", {key: value for key, value in args.items() if key != "scope"})["status"] == "RUNNING"


@pytest.mark.parametrize("request_id", ["", "自然语言请求号", "<p>neutral-marker</p>", "x" * 129])
def test_request_ids_are_limited_identifiers_across_entrypoints(request_id):
    args = {"taskId": "mock-health-inspection", "definitionVersion": 1, "requestId": request_id}
    with pytest.raises(MockError) as failure:
        call("inspection", "start_inspection", args)
    assert failure.value.status_code == 422
    with pytest.raises(MockError):
        call("policy-configuration", "prepare_policy_configuration", policy_body(request_id))
    _, prepared = prepare_emergency()
    body = confirmation(prepared)
    body["request_id"] = request_id
    with pytest.raises(MockError):
        confirm_emergency(prepared["operation_id"], body)
    assert emergency_result(prepared["operation_id"])["execution_status"] == "NOT_SUBMITTED"


def test_emergency_version_bool_is_not_integer_in_body_or_proof():
    _, prepared = prepare_emergency()
    body = confirmation(prepared)
    body["expected_version"] = True
    with pytest.raises(MockError):
        confirm_emergency(prepared["operation_id"], body)
    body = confirmation(prepared)
    payload = {"operation_id": prepared["operation_id"], "version": True,
               "snapshot_digest": prepared["snapshot_digest"], "decision": "CONFIRM"}
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    body["confirmation_event_ref"] = encoded + ".mock-proof"
    with pytest.raises(MockError):
        confirm_emergency(prepared["operation_id"], body)
    assert emergency_result(prepared["operation_id"])["phase"] == "READY"
