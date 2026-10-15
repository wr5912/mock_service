from __future__ import annotations

import argparse
import importlib
import json
import logging
import os
import re
import sys
from collections.abc import Iterable, Iterator
from copy import deepcopy
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx
from pydantic import ValidationError


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

LOGGER = logging.getLogger("import_sanitized_es_data")
DEFAULT_DEST_ES_URL = "http://127.0.0.1:59200"
DEFAULT_DATA_PATH = ROOT / "mock_es_data_json" / "basic_operations.json"


def configure_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )


def load_model_modules() -> dict[str, ModuleType]:
    modules: dict[str, ModuleType] = {}
    for path in sorted((ROOT / "scripts" / "es_models").glob("*.py")):
        if path.name.startswith("_"):
            continue
        module = importlib.import_module(f"scripts.es_models.{path.stem}")
        if hasattr(module, "INDEX_NAME") and hasattr(module, "INDEX_MAPPING"):
            modules[module.INDEX_NAME] = module
    return modules


def auth_from_env(prefix: str = "DEST_ES") -> tuple[str, str] | None:
    username = os.getenv(f"{prefix}_USERNAME")
    password = os.getenv(f"{prefix}_PASSWORD")
    if username and password:
        return username, password
    return None


def dest_es_url_from_env() -> str:
    return os.getenv("DEST_ES_URL", DEFAULT_DEST_ES_URL)


def to_snake_case(value: str) -> str:
    cleaned = re.sub(r"[^0-9A-Za-z]+", "_", value).strip("_")
    cleaned = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", cleaned)
    cleaned = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", cleaned)
    cleaned = cleaned.lower()
    cleaned = cleaned.replace("ipv_6", "ipv6").replace("md_5", "md5")
    if not cleaned:
        return "field"
    if cleaned[0].isdigit():
        return f"field_{cleaned}"
    return cleaned


def load_basic_records() -> dict[str, list[dict[str, Any]]]:
    """只读取仓库内经过审查的唯一基本数据源，不读取归档或外部文件。"""

    try:
        data = json.loads(DEFAULT_DATA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit("无法读取本地基本模拟数据。") from exc
    modules = load_model_modules()
    if not isinstance(data, dict) or set(data) != set(modules):
        raise SystemExit("基本模拟数据的索引集合不符合当前模型。")
    for index_name, records in data.items():
        if not isinstance(records, list) or not records or not all(isinstance(row, dict) for row in records):
            raise SystemExit("基本模拟数据必须包含非空对象列表。")
        try:
            for record in records:
                modules[index_name].MODEL_CLASS.model_validate(record)
        except ValidationError as exc:
            raise SystemExit("基本模拟数据不符合索引模型。") from exc
    return data


def iter_batches(records: Iterable[dict[str, Any]], batch_size: int) -> Iterator[list[dict[str, Any]]]:
    batch: list[dict[str, Any]] = []
    for record in records:
        batch.append(record)
        if len(batch) >= batch_size:
            yield batch
            batch = []
    if batch:
        yield batch


def raw_to_python_field_map(module: ModuleType) -> dict[str, str]:
    return {raw_path: py_path.split(".")[-1] for py_path, raw_path in module.SOURCE_FIELD_MAP.items()}


def snake_case_properties(
    properties: dict[str, Any],
    raw_to_py: dict[str, str],
    raw_prefix: tuple[str, ...] = (),
) -> dict[str, Any]:
    converted: dict[str, Any] = {}
    for raw_name, spec in properties.items():
        raw_path = ".".join((*raw_prefix, raw_name))
        py_name = raw_to_py.get(raw_path, to_snake_case(raw_name))
        converted_spec = deepcopy(spec)
        nested = converted_spec.get("properties")
        if isinstance(nested, dict):
            converted_spec["properties"] = snake_case_properties(nested, raw_to_py, (*raw_prefix, raw_name))
        converted[py_name] = converted_spec
    return converted


def snake_case_index_body(module: ModuleType) -> dict[str, Any]:
    body = deepcopy(module.INDEX_MAPPING)
    mappings = body.get("mappings", {})
    if "_doc" in mappings:
        mappings = mappings["_doc"]
    properties = mappings.get("properties", {})
    mappings["properties"] = snake_case_properties(properties, raw_to_python_field_map(module))
    body["mappings"] = mappings
    return body


def create_index(client: httpx.Client, index_name: str, module: ModuleType, replace: bool) -> bool:
    response = client.head(f"/{index_name}")
    exists = response.status_code == 200
    if response.status_code not in {200, 404}:
        response.raise_for_status()
    if exists and not replace:
        raise RuntimeError(f"Index already exists: {index_name}. Use --replace to delete and recreate it.")
    if exists and replace:
        delete_response = client.delete(f"/{index_name}")
        delete_response.raise_for_status()
        LOGGER.warning("deleted existing index=%s", index_name)

    create_response = client.put(f"/{index_name}", json=snake_case_index_body(module))
    if create_response.status_code in {200, 201}:
        return True
    create_response.raise_for_status()
    return False


def build_bulk_body(index_name: str, records: Iterable[dict[str, Any]]) -> str:
    lines: list[str] = []
    for record in records:
        lines.append(json.dumps({"index": {"_index": index_name}}, ensure_ascii=False))
        lines.append(json.dumps(record, ensure_ascii=False))
    return "\n".join(lines) + "\n"


def bulk_import(client: httpx.Client, index_name: str, records: list[dict[str, Any]]) -> int:
    if not records:
        return 0
    response = client.post(
        "/_bulk",
        content=build_bulk_body(index_name, records).encode("utf-8"),
        headers={"Content-Type": "application/x-ndjson"},
    )
    response.raise_for_status()
    payload = response.json()
    if payload.get("errors"):
        raise RuntimeError(f"Bulk import failed for {index_name}.")
    return len(records)


def import_sanitized_records(args: argparse.Namespace) -> dict[str, Any]:
    """保留既有脚本入口；当前只导入基本数据，不再解压或下载历史档案。"""

    records_by_index = load_basic_records()
    summary = {
        "source": str(DEFAULT_DATA_PATH.relative_to(ROOT)),
        "imported": 0,
        "by_index": {name: len(records) for name, records in records_by_index.items()},
        "created_indices": [],
        "dry_run": args.dry_run,
    }
    if args.dry_run:
        print(json.dumps(summary, ensure_ascii=False))
        return summary

    modules = load_model_modules()
    with httpx.Client(base_url=dest_es_url_from_env().rstrip("/"), auth=auth_from_env(), timeout=args.timeout) as client:
        for index_name, records in records_by_index.items():
            if create_index(client, index_name, modules[index_name], args.replace):
                summary["created_indices"].append(index_name)
            for batch in iter_batches(records, args.batch_size):
                summary["imported"] += bulk_import(client, index_name, batch)
            LOGGER.info("done index=%s imported=%s", index_name, len(records))
    print(json.dumps(summary, ensure_ascii=False))
    return summary


def positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("必须为正整数。") from exc
    if number < 1:
        raise argparse.ArgumentTypeError("必须为正整数。")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="将仓库内基本模拟数据导入 Elasticsearch，不读取历史归档。")
    parser.add_argument("--batch-size", type=positive_int, default=1000, help="每批导入的记录数。")
    parser.add_argument("--timeout", type=float, default=60.0, help="HTTP 超时秒数。")
    parser.add_argument("--replace", action="store_true", help="删除并重建同名业务索引；默认不覆盖。")
    parser.add_argument("--dry-run", action="store_true", help="只检查本地数据并输出摘要，不访问 Elasticsearch。")
    parser.add_argument("--verbose", action="store_true", help="输出调试日志。")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    configure_logging(args.verbose)
    import_sanitized_records(args)


if __name__ == "__main__":
    main()
