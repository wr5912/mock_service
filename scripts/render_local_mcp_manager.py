"""把平台 MCP 登记中的外部 IP 替换为本地地址，端口和路径保持不变。"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


def _replace(value: object, source_host: str, target_host: str) -> object:
    if isinstance(value, dict):
        return {key: _replace(item, source_host, target_host) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace(item, source_host, target_host) for item in value]
    if not isinstance(value, str) or not value.startswith(("http://", "https://")):
        return value
    parsed = urlsplit(value)
    if parsed.hostname != source_host:
        return value
    host = target_host
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme, host, parsed.path, parsed.query, parsed.fragment))


def render(source: Path, output: Path, source_host: str = "172.16.138.223", target_host: str = "127.0.0.1") -> None:
    document = json.loads(source.read_text())
    rendered = _replace(copy.deepcopy(document), source_host, target_host)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(rendered, ensure_ascii=False, indent=2) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="原始 mcp/manager.json")
    parser.add_argument("--output", type=Path, required=True, help="输出本地 manager.json，不覆盖原文件")
    parser.add_argument("--source-host", default="172.16.138.223")
    parser.add_argument("--target-host", default="127.0.0.1")
    args = parser.parse_args()
    render(args.source, args.output, args.source_host, args.target_host)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
