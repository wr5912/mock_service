from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.threat_analysis_mock_data.main import app as standalone_app
from app.threat_intelligence import create_threat_intelligence_app


ROOT = Path(__file__).resolve().parents[1]
EMPTY_CONTENT_FIELDS = {"command_line", "cmd_line", "parent_command_line", "attack_story", "raw_content", "script", "payload"}
# 检查数据值，不把兼容字段名或请求分类当作模拟内容。
DISALLOWED_TOPICS = re.compile(
    r"powershell|cmd\.exe|wscript|cscript|rundll32|regsvr32|schtasks|psexec|"
    r"webshell|ransomware|shellcode|malicious|backdoor|勒索|横向移动|渗透|病毒|恶意代码|攻击链",
    re.IGNORECASE,
)


def assert_basic_content(value) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key in EMPTY_CONTENT_FIELDS:
                assert item in ("", None, [])
            if key == "threat_type":
                assert item == "none"
            if key in {"tactic", "technique"}:
                assert item == ""
            if key in {"ttps", "top_tactics"}:
                assert item == []
            assert_basic_content(item)
    elif isinstance(value, list):
        for item in value:
            assert_basic_content(item)
    elif isinstance(value, str):
        assert not DISALLOWED_TOPICS.search(value)


@pytest.mark.parametrize("target", [app, standalone_app], ids=["main", "standalone"])
def test_all_analysis_results_are_basic_and_match_listing(target) -> None:
    client = TestClient(target)
    response = client.get("/api/external/detection-findings", params={"limit": 200})
    assert response.status_code == 200
    findings = response.json()["data"]["items"]
    assert len(findings) == 6
    for finding in findings:
        result = client.get(f"/api/external/detection-findings/{finding['finding_id']}/analysis-result")
        assert result.status_code == 200
        data = result.json()["data"]
        assert data["finding"] == finding
        assert data["latest_result"]["verdict"] == "benign"
        assert data["latest_result"]["severity"] == "info"
        assert data["report"]["report"]["attack_story"] == ""
        assert data["report"]["report"]["recommended_actions"] == []
        assert_basic_content(data)
    limited = client.get("/api/external/detection-findings", params={"limit": 1})
    assert len(limited.json()["data"]["items"]) == 1
    assert client.get("/api/external/detection-findings/not-a-record/analysis-result").status_code == 404


@pytest.mark.parametrize("target", [app, standalone_app], ids=["main", "standalone"])
def test_analysis_validation_does_not_echo_input(target) -> None:
    response = TestClient(target).get(
        "/api/external/detection-findings", params={"limit": "neutral-validation-marker"}
    )
    assert response.status_code == 422
    assert "neutral-validation-marker" not in response.text


def test_all_current_json_sources_contain_only_basic_data() -> None:
    fixtures = list((ROOT / "app/threat_analysis_mock_data/data").rglob("*.json"))
    es_sources = list((ROOT / "mock_es_data_json").glob("*.json"))
    assert len(fixtures) == 7
    assert [path.name for path in es_sources] == ["basic_operations.json"]
    for path in fixtures + es_sources:
        assert_basic_content(json.loads(path.read_text(encoding="utf-8")))
    assert not (ROOT / "exports/sanitized.tar.gz").exists()


@pytest.mark.parametrize("seed", [0, 7, 999])
def test_all_standard_generators_return_basic_data(seed: int) -> None:
    client = TestClient(app)
    for route in ["assets", "alerts", "incidents", "vulnerabilities", "indicators", "events"]:
        response = client.get(f"/api/v1/{route}", params={"count": 200, "seed": seed})
        assert response.status_code == 200
        assert_basic_content(response.json())
    summary = client.get("/api/v1/dashboard/summary", params={"seed": seed}).json()
    assert summary["critical_alert_count"] == 0
    assert summary["vulnerable_asset_count"] == 0
    assert_basic_content(summary)


def test_public_schema_examples_contain_only_basic_data() -> None:
    schemas = [
        TestClient(app).get("/openapi.json").json(),
        TestClient(standalone_app).get("/openapi.json").json(),
        create_threat_intelligence_app().test_client().get("/swagger.json").get_json(),
    ]

    def inspect(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in {"example", "examples"}:
                    assert_basic_content(item)
                inspect(item)
        elif isinstance(value, list):
            for item in value:
                inspect(item)

    for schema in schemas:
        inspect(schema)
