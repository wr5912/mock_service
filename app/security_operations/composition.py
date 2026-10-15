"""资产到告警组合使用的两个只读基础模拟接口。"""

from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Path, Request
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .soc import EVENT_TIME, alert, incident
from .state import INCIDENT_IDS, MockError, asset


class AssetResult(BaseModel):
    code: int
    data: dict[str, Any]


class AlertQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assetId: str = Field(pattern=r"^[1-9][0-9]{0,15}$", description="资产查询结果中的正整数标识，以字符串传入。")
    pageNum: int = Field(default=1, ge=1, description="页码，从 1 开始。")
    pageSize: int = Field(default=5, ge=1, le=20, description="首页最大返回分组数，与组合 limit 一致。")
    windowSeconds: int = Field(default=2592000, ge=1, le=2592000, description="固定模拟时间点之前的查询秒数，最大 30 天。")


class AlertGroups(BaseModel):
    groups: list[dict[str, Any]]
    totalGroups: int
    totalAlerts: int
    truncated: bool
    from_: str = Field(alias="from")
    to: str
    pageNum: int
    pageSize: int


class AlertsResult(BaseModel):
    code: int
    data: AlertGroups


def _asset(value: int | str) -> dict[str, Any]:
    try:
        return asset(value)
    except MockError:
        raise HTTPException(status_code=404, detail="未找到对应模拟资产") from None


router = APIRouter(tags=["组合只读模拟"])


@router.get(
    "/api/v1/security-operations/readonly/assets/{assetId}",
    operation_id="get_soc_asset_by_asset_id",
    response_model=AssetResult,
    summary="按标识查询基本模拟资产",
    description="只读取已有基本资产；未知标识返回 404，不创建资产或操作记录。",
)
def get_asset(assetId: Annotated[int, Path(ge=1)]) -> AssetResult:
    return AssetResult(code=200, data=_asset(assetId))


@router.get(
    "/api/v1/security-operations/readonly/alerts",
    operation_id="list_detect_alert",
    response_model=AlertsResult,
    summary="按资产查询基本模拟告警分组",
    description="仅返回该资产的基本运维告警。查询范围以固定模拟时间点为止，req 使用 form/explode 展开为查询参数。",
    openapi_extra={"parameters": [{
        "name": "req", "in": "query", "required": True, "style": "form", "explode": True,
        "schema": AlertQuery.model_json_schema(),
    }]},
)
def list_alerts(request: Request) -> AlertsResult:
    try:
        query = AlertQuery.model_validate(dict(request.query_params))
    except ValidationError:
        raise HTTPException(status_code=422, detail="告警查询参数无效") from None
    selected_asset = _asset(query.assetId)
    groups = []
    alert_ids = {alert_id for incident_id in INCIDENT_IDS for alert_id in incident(incident_id)["contributingAlertsJson"]}
    for alert_id in sorted(alert_ids):
        item = alert(alert_id)
        if item["affectedAssetId"] == selected_asset["assetId"]:
            groups.append({
                "groupId": "group-" + item["alert_id"], "assetId": selected_asset["assetId"],
                "title": item["title"], "severity": item["severity"], "alertCount": 1,
                "firstSeenTime": item["created_at"], "lastSeenTime": item["created_at"],
                "alerts": [item],
            })
    offset = (query.pageNum - 1) * query.pageSize
    end = datetime.fromisoformat(EVENT_TIME.replace("Z", "+00:00"))
    start = end - timedelta(seconds=query.windowSeconds)
    return AlertsResult(code=200, data=AlertGroups(
        groups=groups[offset:offset + query.pageSize], totalGroups=len(groups),
        totalAlerts=sum(row["alertCount"] for row in groups),
        truncated=offset + query.pageSize < len(groups),
        **{"from": start.isoformat().replace("+00:00", "Z")}, to=EVENT_TIME,
        pageNum=query.pageNum, pageSize=query.pageSize,
    ))


_readonly_routes = list(router.routes)


@router.get("/api/v1/security-operations/readonly/openapi.json", include_in_schema=False)
def readonly_openapi() -> dict[str, Any]:
    return get_openapi(
        title="资产相关告警只读查询模拟接口", version="0.1.0",
        description="仅含资产到基本告警分组组合实际调用的两个 GET 操作。",
        routes=_readonly_routes, servers=[{"url": "/"}],
    )
