from __future__ import annotations

import json

import httpx
import pytest

from scripts.es_models import process_creation
from scripts.import_sanitized_es_data import (
    DEFAULT_DATA_PATH,
    DEFAULT_DEST_ES_URL,
    build_bulk_body,
    build_parser,
    bulk_import,
    create_index,
    dest_es_url_from_env,
    import_sanitized_records,
    load_basic_records,
    load_model_modules,
    snake_case_index_body,
)


def test_dest_es_url_defaults_to_local_es(monkeypatch) -> None:
    monkeypatch.delenv("DEST_ES_URL", raising=False)

    assert dest_es_url_from_env() == DEFAULT_DEST_ES_URL == "http://127.0.0.1:59200"


def test_dest_es_url_allows_environment_override(monkeypatch) -> None:
    monkeypatch.setenv("DEST_ES_URL", "http://demo-es:9200")

    assert dest_es_url_from_env() == "http://demo-es:9200"


def test_basic_source_covers_current_index_models() -> None:
    records = load_basic_records()

    assert DEFAULT_DATA_PATH.name == "basic_operations.json"
    assert set(records) == set(load_model_modules())
    assert len(records) == 21
    assert all(len(rows) == 1 for rows in records.values())


def test_dry_run_does_not_open_network(monkeypatch) -> None:
    def fail_client(*args, **kwargs):
        pytest.fail("dry-run 不应创建网络客户端。")

    monkeypatch.setattr("scripts.import_sanitized_es_data.httpx.Client", fail_client)
    result = import_sanitized_records(build_parser().parse_args(["--dry-run"]))

    assert result["dry_run"] is True
    assert result["imported"] == 0
    assert result["created_indices"] == []
    assert sum(result["by_index"].values()) == 21


def test_archive_flags_are_no_longer_accepted() -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--archive", "unused-local-file"])


@pytest.mark.parametrize("size", ["0", "-1", "neutral-validation-marker"])
def test_batch_size_must_be_positive(size: str) -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--batch-size", size])


def test_snake_case_index_body_renames_mapping_fields() -> None:
    properties = snake_case_index_body(process_creation)["mappings"]["properties"]

    assert "host_ip" in properties
    assert "HostIp" not in properties
    assert "command_line" in properties["data"]["properties"]
    assert "CommandLine" not in properties["data"]["properties"]


def test_build_bulk_body_imports_basic_documents() -> None:
    body = build_bulk_body("es_process_creation", [{"host_ip": "192.0.2.10"}])
    lines = body.strip().splitlines()

    assert json.loads(lines[0]) == {"index": {"_index": "es_process_creation"}}
    assert json.loads(lines[1]) == {"host_ip": "192.0.2.10"}


def test_create_index_requires_replace_when_index_exists() -> None:
    calls = []

    def handler(request):
        calls.append(request.method)
        return httpx.Response(200)

    with httpx.Client(base_url="http://demo-es", transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(RuntimeError, match="Use --replace"):
            create_index(client, "es_process_creation", process_creation, replace=False)
    assert calls == ["HEAD"]


def test_create_index_with_replace_deletes_and_recreates() -> None:
    calls = []

    def handler(request):
        calls.append((request.method, request.url.path))
        if request.method == "PUT":
            assert json.loads(request.content)["mappings"]["properties"]["host_ip"]["type"] == "text"
        return httpx.Response(200)

    with httpx.Client(base_url="http://demo-es", transport=httpx.MockTransport(handler)) as client:
        assert create_index(client, "es_process_creation", process_creation, replace=True) is True
    assert [method for method, _ in calls] == ["HEAD", "DELETE", "PUT"]


def test_bulk_error_does_not_echo_upstream_content() -> None:
    def handler(request):
        return httpx.Response(200, json={"errors": True, "items": [{"index": {"error": "neutral-error-marker"}}]})

    with httpx.Client(base_url="http://demo-es", transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(RuntimeError) as error:
            bulk_import(client, "es_process_creation", [{"host_ip": "192.0.2.10"}])
    assert "neutral-error-marker" not in str(error.value)


def test_full_import_uses_only_current_basic_business_indices(monkeypatch) -> None:
    requests = []
    real_client = httpx.Client

    def handler(request):
        requests.append(request)
        if request.method == "HEAD":
            return httpx.Response(404)
        return httpx.Response(200, json={"errors": False})

    monkeypatch.setattr(
        "scripts.import_sanitized_es_data.httpx.Client",
        lambda **kwargs: real_client(**kwargs, transport=httpx.MockTransport(handler)),
    )
    result = import_sanitized_records(build_parser().parse_args([]))

    assert result["imported"] == 21
    assert len(result["created_indices"]) == 21
    assert not any(request.method == "DELETE" for request in requests)
    assert all(request.url.path.startswith(("/es_", "/_bulk")) for request in requests)
    assert len([request for request in requests if request.method == "POST"]) == 21
