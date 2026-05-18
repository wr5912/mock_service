from __future__ import annotations

from fastapi import FastAPI

try:
    from .router import router
except ImportError:
    from router import router

app = FastAPI(title="Threat Analysis Mock External API", version="0.1.0")
app.include_router(router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "threat-analysis-mock-data"}

