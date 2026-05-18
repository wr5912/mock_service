from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

router = APIRouter(tags=["Threat Analysis Mock"])


def success_response(data: Any) -> dict[str, Any]:
    return {
        "status": "success",
        "data": data,
        "warnings": [],
        "request_id": "threat-analysis-mock",
    }


def read_json(path: Path) -> Any:
    if not path.exists():
        raise HTTPException(status_code=404, detail="mock data not found")
    return json.loads(path.read_text(encoding="utf-8"))


@router.get("/api/external/detection-findings")
def list_detection_findings(
    limit: int = Query(default=50, ge=1, le=200),
) -> dict[str, Any]:
    data = read_json(DATA_DIR / "detection-findings.json")
    items = data.get("items", [])
    return success_response({"items": items[:limit], "limit": limit})


@router.get("/api/external/detection-findings/{finding_id}/analysis-result")
def get_detection_finding_analysis_result(finding_id: str) -> dict[str, Any]:
    data = read_json(DATA_DIR / "analysis-results" / f"{finding_id}.json")
    return success_response(data)

