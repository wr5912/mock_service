from __future__ import annotations

import json

from es_models import process_creation, threat_event
from scripts.export_es_data import build_range_query, to_epoch_millis
from scripts.import_es_json import (
    build_bulk_body,
    collect_indices,
    index_creation_body,
    iter_exported_records,
)


def test_build_range_query_uses_keyword_for_text_time_fields() -> None:
    query = build_range_query(process_creation, "2026-01-06", "2026-01-23")

    assert query == {
        "range": {
            "TimeStamp.keyword": {
                "gte": "2026-01-06",
                "lt": "2026-01-23",
            }
        }
    }


def test_build_range_query_converts_long_time_fields_to_epoch_millis() -> None:
    query = build_range_query(threat_event, "2026-01-06", "2026-01-23")

    assert query == {
        "range": {
            "timestamp": {
                "gte": to_epoch_millis("2026-01-06", "Asia/Shanghai"),
                "lt": to_epoch_millis("2026-01-23", "Asia/Shanghai"),
            }
        }
    }


def test_build_bulk_body_keeps_index_id_and_raw_source() -> None:
    body = build_bulk_body(
        [
            {
                "_index": "es_process_creation",
                "_id": "doc-1",
                "_source": {"HostID": "host-1", "Data": {"CommandLine": "cmd.exe"}},
            }
        ]
    )

    lines = body.strip().splitlines()
    assert json.loads(lines[0]) == {"index": {"_index": "es_process_creation", "_id": "doc-1"}}
    assert json.loads(lines[1]) == {"HostID": "host-1", "Data": {"CommandLine": "cmd.exe"}}


def test_iter_exported_records_reads_exporter_json_array(tmp_path) -> None:
    export_file = tmp_path / "export.json"
    export_file.write_text(
        '[\n'
        '{"_index": "es_process_creation", "_id": "1", "_source": {"HostID": "host-1"}},\n'
        '{"_index": "es_web_event", "_id": "2", "_source": {"HostID": "host-2"}}\n'
        ']\n',
        encoding="utf-8",
    )

    records = list(iter_exported_records(export_file))

    assert [record["_id"] for record in records] == ["1", "2"]
    assert collect_indices(export_file) == {"es_process_creation", "es_web_event"}


def test_index_creation_body_converts_typed_mapping_for_es7() -> None:
    body = index_creation_body(process_creation.INDEX_MAPPING)

    assert "_doc" not in body["mappings"]
    assert "properties" in body["mappings"]
    assert "Data" in body["mappings"]["properties"]
