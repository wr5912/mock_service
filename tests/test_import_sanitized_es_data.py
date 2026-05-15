from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

from es_models import process_creation
from scripts.import_sanitized_es_data import (
    build_bulk_body,
    create_index,
    extract_sanitized_archive,
    index_name_from_file,
    safe_tar_members,
    snake_case_index_body,
)


class FakeResponse:
    def __init__(self, status_code: int, text: str = "") -> None:
        self.status_code = status_code
        self.text = text

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(self.text or f"HTTP {self.status_code}")


class FakeClient:
    def __init__(self, head_status: int = 200) -> None:
        self.head_status = head_status
        self.calls: list[tuple[str, str, object | None]] = []

    def head(self, path: str) -> FakeResponse:
        self.calls.append(("HEAD", path, None))
        return FakeResponse(self.head_status)

    def delete(self, path: str) -> FakeResponse:
        self.calls.append(("DELETE", path, None))
        return FakeResponse(200)

    def put(self, path: str, json=None) -> FakeResponse:
        self.calls.append(("PUT", path, json))
        return FakeResponse(200)


def test_index_name_comes_from_sanitized_file_name() -> None:
    assert index_name_from_file(Path("exports/sanitized/es_process_creation.json")) == "es_process_creation"


def make_archive(archive_path: Path, files: dict[str, str]) -> None:
    with tarfile.open(archive_path, "w:gz") as tar:
        for name, content in files.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))


def test_extract_sanitized_archive_creates_expected_directory(tmp_path: Path) -> None:
    archive_path = tmp_path / "sanitized.tar.gz"
    extract_root = tmp_path / "exports"
    make_archive(archive_path, {"sanitized/es_process_creation.json": '[{"host_ip": "192.168.1.2"}]'})

    extracted = extract_sanitized_archive(archive_path, extract_root, overwrite=False)

    assert extracted == extract_root / "sanitized"
    assert json.loads((extracted / "es_process_creation.json").read_text(encoding="utf-8")) == [
        {"host_ip": "192.168.1.2"}
    ]


def test_extract_sanitized_archive_requires_overwrite_for_existing_directory(tmp_path: Path) -> None:
    archive_path = tmp_path / "sanitized.tar.gz"
    extract_root = tmp_path / "exports"
    (extract_root / "sanitized").mkdir(parents=True)
    make_archive(archive_path, {"sanitized/es_process_creation.json": "[]"})

    try:
        extract_sanitized_archive(archive_path, extract_root, overwrite=False)
    except SystemExit as exc:
        assert "--overwrite-extract" in str(exc)
    else:
        raise AssertionError("Expected SystemExit")


def test_extract_sanitized_archive_overwrites_existing_directory(tmp_path: Path) -> None:
    archive_path = tmp_path / "sanitized.tar.gz"
    extract_root = tmp_path / "exports"
    old_file = extract_root / "sanitized" / "old.json"
    old_file.parent.mkdir(parents=True)
    old_file.write_text("[]", encoding="utf-8")
    make_archive(archive_path, {"sanitized/es_process_creation.json": "[]"})

    extracted = extract_sanitized_archive(archive_path, extract_root, overwrite=True)

    assert not old_file.exists()
    assert (extracted / "es_process_creation.json").exists()


def test_safe_tar_members_rejects_path_traversal(tmp_path: Path) -> None:
    archive_path = tmp_path / "sanitized.tar.gz"
    make_archive(archive_path, {"../evil.json": "[]"})

    with tarfile.open(archive_path, "r:gz") as tar:
        try:
            safe_tar_members(tar, tmp_path / "exports")
        except SystemExit as exc:
            assert "Unsafe archive member path" in str(exc)
        else:
            raise AssertionError("Expected SystemExit")


def test_snake_case_index_body_renames_mapping_fields() -> None:
    body = snake_case_index_body(process_creation)
    properties = body["mappings"]["properties"]

    assert "host_ip" in properties
    assert "HostIp" not in properties
    assert "data" in properties
    assert "command_line" in properties["data"]["properties"]
    assert "CommandLine" not in properties["data"]["properties"]


def test_build_bulk_body_imports_plain_snake_case_documents() -> None:
    body = build_bulk_body("es_process_creation", [{"host_ip": "192.168.1.2"}])
    lines = body.strip().splitlines()

    assert json.loads(lines[0]) == {"index": {"_index": "es_process_creation"}}
    assert json.loads(lines[1]) == {"host_ip": "192.168.1.2"}


def test_create_index_requires_replace_when_index_exists() -> None:
    client = FakeClient(head_status=200)

    try:
        create_index(client, "es_process_creation", process_creation, replace=False)
    except RuntimeError as exc:
        assert "Use --replace" in str(exc)
    else:
        raise AssertionError("Expected RuntimeError")

    assert client.calls == [("HEAD", "/es_process_creation", None)]


def test_create_index_with_replace_deletes_and_recreates() -> None:
    client = FakeClient(head_status=200)

    assert create_index(client, "es_process_creation", process_creation, replace=True) is True

    assert [method for method, _, _ in client.calls] == ["HEAD", "DELETE", "PUT"]
    put_body = client.calls[-1][2]
    assert put_body["mappings"]["properties"]["host_ip"]["type"] == "text"
