from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def load_mapping_modules() -> dict[str, ModuleType]:
    model_dir = ROOT / "es_models"
    modules: dict[str, ModuleType] = {}
    for path in sorted(model_dir.glob("*.py")):
        if path.name.startswith("_"):
            continue
        module = importlib.import_module(f"es_models.{path.stem}")
        if hasattr(module, "INDEX_NAME") and hasattr(module, "INDEX_MAPPING"):
            modules[module.INDEX_NAME] = module
    return modules


def auth_from_env(prefix: str = "DEST_ES") -> tuple[str, str] | None:
    username = os.getenv(f"{prefix}_USERNAME")
    password = os.getenv(f"{prefix}_PASSWORD")
    if username and password:
        return username, password
    return None


def iter_exported_records(input_path: Path) -> Iterator[dict[str, Any]]:
    with input_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            stripped = line.strip()
            if not stripped or stripped in {"[", "]"}:
                continue
            if stripped.endswith(","):
                stripped = stripped[:-1]
            record = json.loads(stripped)
            if not isinstance(record, dict):
                raise SystemExit("Input file must contain JSON objects in the exported array.")
            yield record


def collect_indices(input_path: Path) -> set[str]:
    return {record["_index"] for record in iter_exported_records(input_path)}


def iter_batches(records: Iterable[dict[str, Any]], batch_size: int) -> Iterator[list[dict[str, Any]]]:
    batch: list[dict[str, Any]] = []
    for record in records:
        batch.append(record)
        if len(batch) >= batch_size:
            yield batch
            batch = []
    if batch:
        yield batch


def build_bulk_body(records: Iterable[dict[str, Any]]) -> str:
    lines: list[str] = []
    for record in records:
        action: dict[str, Any] = {"_index": record["_index"]}
        if record.get("_id") is not None:
            action["_id"] = record["_id"]
        lines.append(json.dumps({"index": action}, ensure_ascii=False))
        lines.append(json.dumps(record.get("_source", {}), ensure_ascii=False))
    return "\n".join(lines) + "\n"


def index_creation_body(index_mapping: dict[str, Any]) -> dict[str, Any]:
    mappings = index_mapping.get("mappings")
    if not isinstance(mappings, dict):
        return index_mapping

    typed_mapping = mappings.get("_doc")
    if not isinstance(typed_mapping, dict):
        return index_mapping

    body = dict(index_mapping)
    body["mappings"] = typed_mapping
    return body


def create_index_if_missing(
    client: httpx.Client,
    index_name: str,
    module_by_index: dict[str, ModuleType],
) -> bool:
    response = client.head(f"/{index_name}")
    if response.status_code == 200:
        return False
    if response.status_code != 404:
        response.raise_for_status()

    module = module_by_index.get(index_name)
    if module is None:
        return False

    response = client.put(f"/{index_name}", json=index_creation_body(module.INDEX_MAPPING))
    if response.status_code in {200, 201}:
        return True
    if response.status_code == 400 and "resource_already_exists_exception" in response.text:
        return False
    response.raise_for_status()
    return True


def bulk_import(client: httpx.Client, records: list[dict[str, Any]]) -> int:
    if not records:
        return 0
    body = build_bulk_body(records)
    response = client.post(
        "/_bulk",
        content=body.encode("utf-8"),
        headers={"Content-Type": "application/x-ndjson"},
    )
    response.raise_for_status()
    payload = response.json()
    if payload.get("errors"):
        first_error = next((item for item in payload.get("items", []) if item.get("index", {}).get("error")), None)
        raise RuntimeError(f"Bulk import failed: {first_error}")
    return len(records)


def import_records(args: argparse.Namespace) -> int:
    dest_es_url = os.getenv("DEST_ES_URL")
    if not dest_es_url:
        raise SystemExit("DEST_ES_URL is required, for example: DEST_ES_URL=http://new-es-host:9200")

    input_path = Path(args.input)

    module_by_index = load_mapping_modules()
    created_indices: set[str] = set()
    imported = 0

    with httpx.Client(base_url=dest_es_url.rstrip("/"), auth=auth_from_env(), timeout=args.timeout) as client:
        if args.create_indices:
            for index_name in sorted(collect_indices(input_path)):
                if create_index_if_missing(client, index_name, module_by_index):
                    created_indices.add(index_name)

        for batch in iter_batches(iter_exported_records(input_path), args.batch_size):
            imported += bulk_import(client, batch)

    print(json.dumps({"input": str(input_path), "imported": imported, "created_indices": sorted(created_indices)}, ensure_ascii=False))
    return imported


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Import an exported JSON array into Elasticsearch.")
    parser.add_argument("--input", required=True, help="JSON array exported by scripts/export_es_data.py.")
    parser.add_argument("--batch-size", type=int, default=1000, help="Bulk import batch size.")
    parser.add_argument("--timeout", type=float, default=60.0, help="HTTP timeout in seconds.")
    parser.add_argument(
        "--no-create-indices",
        dest="create_indices",
        action="store_false",
        help="Do not create missing indices from generated mappings.",
    )
    parser.set_defaults(create_indices=True)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    import_records(args)


if __name__ == "__main__":
    main()
