from __future__ import annotations

import argparse
import importlib
import json
import logging
import os
import re
import shutil
import sys
import tarfile
from collections.abc import Iterable, Iterator
from copy import deepcopy
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

LOGGER = logging.getLogger("import_sanitized_es_data")
DEFAULT_DEST_ES_URL = "http://127.0.0.1:59200"


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


def index_name_from_file(path: Path) -> str:
    return path.stem


def safe_tar_members(tar: tarfile.TarFile, extract_root: Path) -> list[tarfile.TarInfo]:
    root = extract_root.resolve()
    safe_members: list[tarfile.TarInfo] = []

    for member in tar.getmembers():
        member_path = Path(member.name)
        if (
            not member.name
            or not member_path.parts
            or member_path.is_absolute()
            or ".." in member_path.parts
            or member_path.parts[0] != "sanitized"
        ):
            raise SystemExit(f"Unsafe archive member path: {member.name}")
        if member.issym() or member.islnk():
            raise SystemExit(f"Archive links are not allowed: {member.name}")
        if not (member.isdir() or member.isfile()):
            raise SystemExit(f"Unsupported archive member type: {member.name}")

        target = (root / member.name).resolve()
        if target != root and root not in target.parents:
            raise SystemExit(f"Unsafe archive extraction target: {member.name}")
        safe_members.append(member)

    if not safe_members:
        raise SystemExit("Archive is empty.")
    return safe_members


def extract_tar_members(tar: tarfile.TarFile, members: list[tarfile.TarInfo], extract_root: Path) -> None:
    for member in members:
        target = extract_root / member.name
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
            continue

        target.parent.mkdir(parents=True, exist_ok=True)
        source = tar.extractfile(member)
        if source is None:
            raise SystemExit(f"Cannot read archive member: {member.name}")
        with source, target.open("wb") as output:
            shutil.copyfileobj(source, output)


def extract_sanitized_archive(archive_path: Path, extract_root: Path, overwrite: bool) -> Path:
    if not archive_path.exists():
        raise SystemExit(f"Archive does not exist: {archive_path}")
    if not archive_path.is_file():
        raise SystemExit(f"Archive path is not a file: {archive_path}")

    extract_dir = extract_root / "sanitized"
    if extract_dir.exists():
        if not extract_dir.is_dir():
            raise SystemExit(f"Extraction path exists and is not a directory: {extract_dir}")
        if not overwrite:
            raise SystemExit(f"Extraction directory already exists: {extract_dir}. Use --overwrite-extract to replace it.")
        shutil.rmtree(extract_dir)

    extract_root.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(archive_path, "r:gz") as tar:
            members = safe_tar_members(tar, extract_root)
            file_count = sum(1 for member in members if member.isfile())
            LOGGER.info("extract archive=%s extract_root=%s files=%s", archive_path, extract_root, file_count)
            extract_tar_members(tar, members, extract_root)
    except tarfile.TarError as exc:
        raise SystemExit(f"Invalid archive: {archive_path}: {exc}") from exc

    if not extract_dir.is_dir():
        raise SystemExit(f"Archive did not create expected directory: {extract_dir}")
    return extract_dir


def iter_sanitized_records(input_path: Path) -> Iterator[dict[str, Any]]:
    with input_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            stripped = line.strip()
            if not stripped or stripped in {"[", "]"}:
                continue
            if stripped.endswith(","):
                stripped = stripped[:-1]
            record = json.loads(stripped)
            if not isinstance(record, dict):
                raise SystemExit(f"{input_path} must contain JSON objects in an array.")
            yield record


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
        first_error = next((item for item in payload.get("items", []) if item.get("index", {}).get("error")), None)
        raise RuntimeError(f"Bulk import failed for {index_name}: {first_error}")
    return len(records)


def import_sanitized_records(args: argparse.Namespace) -> dict[str, Any]:
    dest_es_url = dest_es_url_from_env()

    archive_path = Path(args.archive)
    extract_root = Path(args.extract_root)
    input_dir = extract_sanitized_archive(archive_path, extract_root, args.overwrite_extract)
    files = sorted(input_dir.glob("*.json"))
    if not files:
        raise SystemExit(f"No sanitized JSON files found in extracted directory: {input_dir}")

    modules = load_model_modules()
    imported_by_index: dict[str, int] = {}
    created_indices: list[str] = []

    LOGGER.info(
        "start sanitized import archive=%s input_dir=%s files=%s replace=%s",
        archive_path,
        input_dir,
        len(files),
        args.replace,
    )
    with httpx.Client(base_url=dest_es_url.rstrip("/"), auth=auth_from_env(), timeout=args.timeout) as client:
        for input_path in files:
            index_name = index_name_from_file(input_path)
            module = modules.get(index_name)
            if module is None:
                raise SystemExit(f"No scripts/es_models module found for sanitized index file: {input_path}")

            if create_index(client, index_name, module, args.replace):
                created_indices.append(index_name)

            imported = 0
            for batch in iter_batches(iter_sanitized_records(input_path), args.batch_size):
                imported += bulk_import(client, index_name, batch)
                if args.log_every and imported % args.log_every == 0:
                    LOGGER.info("progress index=%s imported=%s", index_name, imported)
            imported_by_index[index_name] = imported
            LOGGER.info("done index=%s imported=%s", index_name, imported)

    summary = {
        "archive": str(archive_path),
        "extract_dir": str(input_dir),
        "imported": sum(imported_by_index.values()),
        "by_index": imported_by_index,
        "created_indices": created_indices,
    }
    print(json.dumps(summary, ensure_ascii=False))
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Extract exports/sanitized.tar.gz and import snake_case JSON arrays into Elasticsearch.")
    parser.add_argument("--archive", default="exports/sanitized.tar.gz", help="Sanitized data archive to extract before import.")
    parser.add_argument("--extract-root", default="exports", help="Directory where the archive will be extracted.")
    parser.add_argument("--overwrite-extract", action="store_true", help="Delete existing exports/sanitized before extracting.")
    parser.add_argument("--batch-size", type=int, default=1000, help="Bulk import batch size.")
    parser.add_argument("--timeout", type=float, default=60.0, help="HTTP timeout in seconds.")
    parser.add_argument("--replace", action="store_true", help="Delete and recreate target indices before import.")
    parser.add_argument("--log-every", type=int, default=10000, help="Print per-index progress every N documents. Use 0 to disable.")
    parser.add_argument("--verbose", action="store_true", help="Print debug logs to stderr.")
    parser.epilog = f"DEST_ES_URL defaults to {DEFAULT_DEST_ES_URL} and can be overridden for remote Elasticsearch."
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    configure_logging(args.verbose)
    import_sanitized_records(args)


if __name__ == "__main__":
    main()
