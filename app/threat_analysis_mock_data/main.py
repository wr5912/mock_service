from __future__ import annotations

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

try:
    from .router import router
except ImportError:
    from router import router

app = FastAPI(title="Threat Analysis Mock External API", version="0.1.0")
app.include_router(router)


@app.exception_handler(RequestValidationError)
async def validation_error(request, error: RequestValidationError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"detail": "请求参数校验失败。"})


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "threat-analysis-mock-data"}

