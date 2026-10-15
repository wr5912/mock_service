from __future__ import annotations

import asyncio
import os
from typing import Any, get_args

from flask import Flask, request
from flask_restx import Api, Namespace, Resource, fields
from pydantic import ValidationError
from werkzeug.exceptions import HTTPException

from app.config import get_settings
from app.llm import generate_threat_intelligence
from app.models import ThreatIntelligenceRequest, ThreatIntelligenceType


def create_threat_intelligence_app() -> Flask:
    app = Flask(__name__)
    app.config["RESTX_MASK_SWAGGER"] = False

    api = Api(
        app,
        version="1.0.0",
        title="模拟威胁情报服务 API",
        description="使用本地固定基本数据，提供资产与服务状态联调示例，不依赖外部模型。",
        doc="/docs",
        validate=False,
    )
    namespace = Namespace("威胁情报", path="/", description="模拟威胁情报生成接口。")

    request_model = namespace.model(
        "ThreatIntelligenceRequest",
        {
            "topic": fields.String(
                required=True,
                min_length=2,
                max_length=120,
                description="兼容主题参数，不回显，不用于生成内容。",
                example="基础资产状态",
            ),
            "intelligence_type": fields.String(
                required=False,
                enum=list(get_args(ThreatIntelligenceType)),
                default="situational",
                description="兼容分类参数，响应统一返回基本状态简报。",
            ),
            "language": fields.String(required=False, enum=["zh", "en"], default="zh", description="返回语言。"),
            "include_iocs": fields.Boolean(required=False, default=True, description="是否包含模拟 IOC。"),
        },
    )
    indicator_model = namespace.model(
        "ThreatIntelligenceIndicator",
        {
            "type": fields.String(
                required=True,
                enum=["ip", "domain", "url", "hash", "email", "cve"],
                description="IOC 类型。",
            ),
            "value": fields.String(required=True, description="模拟 IOC 值。", example="update-check.example"),
            "threat_type": fields.String(required=True, description="基本模拟值固定为 none。", example="none"),
            "confidence": fields.Integer(required=True, min=0, max=100, description="IOC 可信度。"),
            "description": fields.String(required=True, description="IOC 上下文说明。"),
        },
    )
    response_model = namespace.model(
        "ThreatIntelligenceResponse",
        {
            "model": fields.String(required=True, description="本地模拟实现标识。"),
            "topic": fields.String(required=True, description="固定的基本状态主题。"),
            "intelligence_type": fields.String(required=True, description="威胁情报类型。"),
            "generated_at": fields.DateTime(required=True, description="生成时间。"),
            "title": fields.String(required=True, description="威胁情报标题。"),
            "summary": fields.String(required=True, description="威胁情报摘要。"),
            "severity": fields.String(
                required=True,
                enum=["critical", "high", "medium", "low", "info"],
                description="模拟威胁严重性。",
            ),
            "confidence": fields.Integer(required=True, min=0, max=100, description="整体情报可信度。"),
            "threat_actor": fields.String(required=False, description="兼容字段，固定为 null。"),
            "ttps": fields.List(fields.String, required=True, description="兼容字段，固定为空列表。"),
            "indicators": fields.List(fields.Nested(indicator_model), required=True, description="模拟 IOC 列表。"),
            "recommendations": fields.List(fields.String, required=True, description="处置和检测建议。"),
            "raw_content": fields.String(required=True, description="兼容字段，固定为空字符串。"),
        },
    )

    @namespace.route("/generate")
    class ThreatIntelligenceResource(Resource):
        @namespace.expect(request_model, validate=False)
        @namespace.response(200, "生成成功。", response_model)
        @namespace.response(400, "请求参数校验失败。")
        def post(self) -> tuple[dict[str, Any], int]:
            try:
                payload = request.get_json(silent=True) or {}
                threat_request = ThreatIntelligenceRequest.model_validate(payload)
                result = asyncio.run(
                    generate_threat_intelligence(
                        settings=get_settings(),
                        request=threat_request,
                    )
                )
                return result.model_dump(mode="json"), 200
            except ValidationError:
                return {"message": "请求参数校验失败。"}, 400

    @api.errorhandler(HTTPException)
    @app.errorhandler(HTTPException)
    def http_error(error: HTTPException) -> tuple[dict[str, str], int]:
        return {"message": "请求无法处理。"}, error.code or 500

    api.add_namespace(namespace)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "threat-intelligence"}

    return app


app = create_threat_intelligence_app()


def main() -> None:
    host = os.getenv("THREAT_INTEL_HOST", "0.0.0.0")
    port = int(os.getenv("THREAT_INTEL_PORT", "53002"))
    app.run(host=host, port=port)


if __name__ == "__main__":
    main()
