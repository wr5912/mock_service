"""仅在当前进程保留基础模拟状态。"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import json
import re
from threading import RLock
from uuid import uuid4


class MockError(Exception):
    def __init__(self, status_code, message):
        super().__init__(message)
        self.status_code = status_code
        self.message = message


LOCK = RLock()
STATE = {name: {} for name in ("inspection", "policy", "policy_endpoints", "emergency", "claims", "writebacks", "reports", "requests")}
ASSETS = [
    {"assetId": 9106, "id": 9106, "name": "测试应用服务器", "hostname": "mock-app", "ip": "192.0.2.10", "status": "ONLINE", "importance": "NORMAL", "type": "SERVER"},
    {"assetId": 9107, "id": 9107, "name": "测试数据库服务器", "hostname": "mock-db", "ip": "192.0.2.20", "status": "ONLINE", "importance": "NORMAL", "type": "SERVER"},
    {"assetId": 9200, "id": 9200, "name": "测试防火墙", "hostname": "mock-firewall", "ip": "192.0.2.1", "status": "ONLINE", "importance": "NORMAL", "type": "FIREWALL"},
]
INCIDENT_IDS = ("INC-20261015-000001", "INC-20261015-000002")
HTML = ('<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">'
        '<title>基础模拟报告</title></head><body><h1>基础模拟报告</h1>'
        '<p>测试资产在线，例行运维检查正常。这是固定基础数据，不涉及真实设备操作。</p></body></html>')


def now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def digest(value):
    return "sha256:" + sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def identifier(prefix):
    return prefix + uuid4().hex


def validate_identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", value):
        raise MockError(422, "模拟标识须为 1 至 128 位英文、数字、下划线、点或连字符")


def lookup(family, key):
    if key not in STATE[family]:
        raise MockError(404, "未找到对应模拟记录")
    return STATE[family][key]


def asset(value):
    text = str(value)
    for row in ASSETS:
        if text in (str(row["assetId"]), row["ip"], row["name"], row["hostname"], "asset:" + str(row["assetId"])):
            return deepcopy(row)
    raise MockError(404, "未找到对应模拟资产")


def replay(family, request_id, value):
    key = (family, request_id)
    previous = STATE["requests"].get(key)
    if previous:
        if previous["digest"] != digest(value):
            raise MockError(409, "同一请求标识不能用于不同参数")
        return deepcopy(previous["result"])
    return None


def remember(family, request_id, value, result):
    STATE["requests"][(family, request_id)] = {"digest": digest(value), "result": deepcopy(result)}
    return deepcopy(result)


def reset_state():
    with LOCK:
        for records in STATE.values():
            records.clear()
