import httpx
from fastapi import HTTPException, status

from app.config import Settings


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
