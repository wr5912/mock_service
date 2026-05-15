from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
from collections.abc import Iterator
from datetime import date, datetime, time, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any
from zoneinfo import ZoneInfo

import httpx


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEFAULT_START_DATE = "2026-01-06"
DEFAULT_END_EXCLUSIVE_DATE = "2026-01-23"
DEFAULT_TIMEZONE = "Asia/Shanghai"


def load_mapping_modules() -> list[ModuleType]:
    model_dir = ROOT / "es_models"
    modules: list[ModuleType] = []
    for path in sorted(model_dir.glob("*.py")):
        if path.name.startswith("_"):
            continue
        module = importlib.import_module(f"es_models.{path.stem}")
        if hasattr(module, "INDEX_NAME") and hasattr(module, "INDEX_MAPPING"):
            modules.append(module)
    return modules


def get_field_spec(index_mapping: dict[str, Any], field_path: str) -> dict[str, Any] | None:
    properties = index_mapping.get("mappings", {}).get("_doc", {}).get("properties", {})
    current: dict[str, Any] | None = None
    for part in field_path.split("."):
        current = properties.get(part)
        if current is None:
            return None
        properties = current.get("properties", {})
    return current


def query_field_name(field_path: str, field_spec: dict[str, Any]) -> str:
    if field_spec.get("type") == "text" and "keyword" in field_spec.get("fields", {}):
        return f"{field_path}.keyword"
    return field_path


def parse_local_datetime(value: str, timezone_name: str) -> datetime:
    zone = ZoneInfo(timezone_name)
    if len(value) == 10:
        parsed_date = date.fromisoformat(value)
        return datetime.combine(parsed_date, time.min, tzinfo=zone)
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=zone)
    return parsed.astimezone(zone)


def to_epoch_millis(value: str, timezone_name: str) -> int:
    return int(parse_local_datetime(value, timezone_name).timestamp() * 1000)


def range_bounds(
    field_spec: dict[str, Any],
    start_date: str,
    end_exclusive_date: str,
    timezone_name: str,
) -> tuple[str | int, str | int]:
    if field_spec.get("type") == "long":
        return (
            to_epoch_millis(start_date, timezone_name),
            to_epoch_millis(end_exclusive_date, timezone_name),
        )
    return start_date, end_exclusive_date


def choose_time_field(module: ModuleType) -> tuple[str, dict[str, Any]] | None:
    for field_path in getattr(module, "TIME_FIELD_CANDIDATES", []):
        field_spec = get_field_spec(module.INDEX_MAPPING, field_path)
        if field_spec is not None:
            return field_path, field_spec
    return None


def build_range_query(
    module: ModuleType,
    start_date: str,
    end_exclusive_date: str,
    timezone_name: str = DEFAULT_TIMEZONE,
) -> dict[str, Any]:
    selected = choose_time_field(module)
    if selected is None:
        return {"match_all": {}}

    field_path, field_spec = selected
    gte, lt = range_bounds(field_spec, start_date, end_exclusive_date, timezone_name)
    return {
        "range": {
            query_field_name(field_path, field_spec): {
                "gte": gte,
                "lt": lt,
            }
        }
    }


def auth_from_env(prefix: str = "ES") -> tuple[str, str] | None:
    username = os.getenv(f"{prefix}_USERNAME")
    password = os.getenv(f"{prefix}_PASSWORD")
    if username and password:
        return username, password
    return None


def default_output_path(start_date: str, end_exclusive_date: str) -> Path:
    try:
        inclusive_end = date.fromisoformat(end_exclusive_date) - timedelta(days=1)
        end_label = inclusive_end.isoformat()
    except ValueError:
        end_label = end_exclusive_date.replace(":", "").replace("/", "-")
    return ROOT / "exports" / f"{start_date}_{end_label}.json"


def iter_index_hits(
    client: httpx.Client,
    module: ModuleType,
    start_date: str,
    end_exclusive_date: str,
    timezone_name: str,
    page_size: int,
    scroll: str,
) -> Iterator[dict[str, Any]]:
    body = {
        "size": page_size,
        "sort": ["_doc"],
        "query": build_range_query(module, start_date, end_exclusive_date, timezone_name),
    }
    response = client.post(f"/{module.INDEX_NAME}/_search", params={"scroll": scroll}, json=body)
    if response.status_code == 404:
        raise IndexNotFoundError(module.INDEX_NAME)
    response.raise_for_status()

    payload = response.json()
    scroll_id = payload.get("_scroll_id")
    try:
        while True:
            hits = payload.get("hits", {}).get("hits", [])
            if not hits:
                break
            yield from hits
            if not scroll_id:
                break
            response = client.post(
                "/_search/scroll",
                json={"scroll": scroll, "scroll_id": scroll_id},
            )
            response.raise_for_status()
            payload = response.json()
            scroll_id = payload.get("_scroll_id", scroll_id)
    finally:
        if scroll_id:
            client.request("DELETE", "/_search/scroll", json={"scroll_id": [scroll_id]})


def write_json_array(records: Iterator[dict[str, Any]], output_path: Path) -> int:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with output_path.open("w", encoding="utf-8") as fh:
        fh.write("[\n")
        for record in records:
            if count:
                fh.write(",\n")
            json.dump(record, fh, ensure_ascii=False)
            count += 1
        fh.write("\n]\n")
    return count


def export_records(args: argparse.Namespace) -> int:
    es_url = os.getenv("ES_URL")
    if not es_url:
        raise SystemExit("ES_URL is required, for example: ES_URL=http://remote-host:26084")

    modules = load_mapping_modules()
    if args.indices:
        selected = set(args.indices)
        modules = [module for module in modules if module.INDEX_NAME in selected]

    skipped: list[str] = []
    total_by_index: dict[str, int] = {}

    def records() -> Iterator[dict[str, Any]]:
        nonlocal skipped, total_by_index
        with httpx.Client(base_url=es_url.rstrip("/"), auth=auth_from_env(), timeout=args.timeout) as client:
            for module in modules:
                index_count = 0
                try:
                    for hit in iter_index_hits(
                        client=client,
                        module=module,
                        start_date=args.start_date,
                        end_exclusive_date=args.end_date,
                        timezone_name=args.timezone,
                        page_size=args.page_size,
                        scroll=args.scroll,
                    ):
                        index_count += 1
                        yield {
                            "_index": hit.get("_index", module.INDEX_NAME),
                            "_id": hit.get("_id"),
                            "_source": hit.get("_source", {}),
                        }
                except IndexNotFoundError:
                    if args.strict:
                        raise
                    skipped.append(module.INDEX_NAME)
                total_by_index[module.INDEX_NAME] = index_count

    output_path = Path(args.output) if args.output else default_output_path(args.start_date, args.end_date)
    total = write_json_array(records(), output_path)
    print(json.dumps({"output": str(output_path), "total": total, "by_index": total_by_index, "skipped": skipped}, ensure_ascii=False))
    return total


class IndexNotFoundError(RuntimeError):
    pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Export mapped Elasticsearch documents to a JSON array.")
    parser.add_argument("--start-date", default=DEFAULT_START_DATE, help="Inclusive start date or datetime.")
    parser.add_argument("--end-date", default=DEFAULT_END_EXCLUSIVE_DATE, help="Exclusive end date or datetime.")
    parser.add_argument("--timezone", default=DEFAULT_TIMEZONE, help="Timezone used when converting long timestamps.")
    parser.add_argument("--output", help="Output JSON file path. Defaults to exports/<start>_<end>.json.")
    parser.add_argument("--page-size", type=int, default=1000, help="Scroll page size.")
    parser.add_argument("--scroll", default="2m", help="Elasticsearch scroll keepalive.")
    parser.add_argument("--timeout", type=float, default=60.0, help="HTTP timeout in seconds.")
    parser.add_argument("--strict", action="store_true", help="Fail if any mapped index is missing.")
    parser.add_argument("--indices", nargs="*", help="Optional INDEX_NAME subset, for example es_process_creation.")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    export_records(args)


if __name__ == "__main__":
    main()
