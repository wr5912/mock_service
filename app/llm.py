import json
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import HTTPException, status
from pydantic import ValidationError

from app.config import Settings
from app.models import ThreatIntelligenceIndicator, ThreatIntelligenceRequest, ThreatIntelligenceResponse


async def generate_scenario(settings: Settings, topic: str, language: str) -> str:
    if not settings.deepseek_api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="未配置 DEEPSEEK_API_KEY，无法调用 DeepSeek 生成演练场景。",
        )

    prompt_language = "中文" if language == "zh" else "English"
    payload = {
        "model": settings.deepseek_model,
        "messages": [
            {
                "role": "system",
                "content": "你是网络安全运营中心的演练设计助手，输出结构清晰、可执行、无真实攻击指令的模拟场景。",
            },
            {
                "role": "user",
                "content": f"请用{prompt_language}生成一个 SOC 模拟数据演练场景，主题：{topic}。包含背景、关键告警、调查线索、处置目标和验收标准。",
            },
        ],
        "temperature": 0.7,
    }

    try:
        async with httpx.AsyncClient(base_url=settings.deepseek_base_url, timeout=30) as client:
            response = await client.post(
                "/chat/completions",
                headers={"Authorization": f"Bearer {settings.deepseek_api_key}"},
                json=payload,
            )
            response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"DeepSeek API 返回错误：HTTP {exc.response.status_code}",
        ) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="DeepSeek API 调用失败。") from exc

    data = response.json()
    try:
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="DeepSeek API 响应格式不符合预期。") from exc


async def generate_threat_intelligence(
    settings: Settings,
    request: ThreatIntelligenceRequest,
) -> ThreatIntelligenceResponse:
    if not settings.deepseek_api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="未配置 DEEPSEEK_API_KEY，无法调用 DeepSeek 生成威胁情报。",
        )

    prompt_language = "中文" if request.language == "zh" else "English"
    ioc_instruction = "包含 3-5 条模拟 IOC。" if request.include_iocs else "不要包含 IOC，indicators 返回空数组。"
    payload = {
        "model": settings.deepseek_model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "你是威胁情报分析师，只生成用于 SOC/SIEM/SOAR 联调和演示的模拟威胁情报。"
                    "不得提供真实攻击步骤、可执行利用代码或真实凭据。"
                    "只返回 JSON 对象，不要使用 Markdown。"
                ),
            },
            {
                "role": "user",
                "content": (
                    f"请用{prompt_language}生成一份模拟威胁情报，主题：{request.topic}。"
                    f"情报类型：{request.intelligence_type}。{ioc_instruction}"
                    "JSON 字段必须包含：title, summary, severity, confidence, threat_actor, ttps, "
                    "indicators, recommendations。"
                    "severity 只能是 critical, high, medium, low, info。"
                    "confidence 必须是 0 到 100 的整数。"
                    "indicators 每项包含 type, value, threat_type, confidence, description；"
                    "type 只能是 ip, domain, url, hash, email, cve。"
                    "IOC 必须使用保留地址、example 域名或明显模拟值。"
                ),
            },
        ],
        "temperature": 0.6,
        "response_format": {"type": "json_object"},
    }

    try:
        async with httpx.AsyncClient(base_url=settings.deepseek_base_url, timeout=30) as client:
            response = await client.post(
                "/chat/completions",
                headers={"Authorization": f"Bearer {settings.deepseek_api_key}"},
                json=payload,
            )
            response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"DeepSeek API 返回错误：HTTP {exc.response.status_code}",
        ) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="DeepSeek API 调用失败。") from exc

    data = response.json()
    try:
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="DeepSeek API 响应格式不符合预期。") from exc

    parsed = parse_llm_json(content)
    return build_threat_intelligence_response(settings.deepseek_model, request, parsed, content)


def parse_llm_json(content: str) -> dict[str, Any]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="DeepSeek API 未返回合法 JSON。") from exc
    if not isinstance(data, dict):
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="DeepSeek API JSON 响应必须是对象。")
    return data


def build_threat_intelligence_response(
    model: str,
    request: ThreatIntelligenceRequest,
    data: dict[str, Any],
    raw_content: str,
) -> ThreatIntelligenceResponse:
    indicators: list[ThreatIntelligenceIndicator] = []
    for item in data.get("indicators", []):
        if isinstance(item, dict):
            try:
                indicators.append(ThreatIntelligenceIndicator.model_validate(item))
            except ValidationError:
                continue

    severity = data.get("severity")
    if severity not in {"critical", "high", "medium", "low", "info"}:
        severity = "medium"

    confidence = data.get("confidence", 70)
    if not isinstance(confidence, int):
        confidence = 70
    confidence = max(0, min(100, confidence))

    ttps = [str(item) for item in data.get("ttps", []) if str(item).strip()]
    recommendations = [str(item) for item in data.get("recommendations", []) if str(item).strip()]

    return ThreatIntelligenceResponse(
        model=model,
        topic=request.topic,
        intelligence_type=request.intelligence_type,
        generated_at=datetime.now(timezone.utc),
        title=str(data.get("title") or f"{request.topic} 威胁情报"),
        summary=str(data.get("summary") or raw_content),
        severity=severity,
        confidence=confidence,
        threat_actor=str(data["threat_actor"]) if data.get("threat_actor") else None,
        ttps=ttps,
        indicators=indicators if request.include_iocs else [],
        recommendations=recommendations,
        raw_content=raw_content,
    )
