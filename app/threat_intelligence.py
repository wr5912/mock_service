from __future__ import annotations

import asyncio
import os
from typing import Any

from fastapi import HTTPException as FastAPIHTTPException
from flask import Flask, request
from flask_restx import Api, Namespace, Resource, fields
from pydantic import ValidationError

from app.config import get_settings
from app.llm import generate_threat_intelligence
from app.models import ThreatIntelligenceRequest


def create_threat_intelligence_app() -> Flask:
    app = Flask(__name__)
    app.config["RESTX_MASK_SWAGGER"] = False

    api = Api(
        app,
        version="1.0.0",
        title="模拟威胁情报服务 API",
        description="使用 LLM 生成结构化模拟威胁情报，供安全运营系统联调和演示使用。",
        doc="/docs",
        validate=True,
    )
    namespace = Namespace("威胁情报", path="/", description="模拟威胁情报生成接口。")

    request_model = namespace.model(
        "ThreatIntelligenceRequest",
        {
            "topic": fields.String(
                required=True,
                min_length=2,
                max_length=120,
                description="威胁情报主题，可以是行业、攻击组织、IOC、漏洞或安全事件场景。",
                example="近期针对制造业的勒索软件活动",
            ),
            "intelligence_type": fields.String(
                required=False,
                enum=["ioc", "actor_profile", "campaign", "vulnerability", "malware", "situational"],
                default="situational",
                description="威胁情报类型。",
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
            "threat_type": fields.String(required=True, description="关联威胁类型。", example="c2"),
            "confidence": fields.Integer(required=True, min=0, max=100, description="IOC 可信度。"),
            "description": fields.String(required=True, description="IOC 上下文说明。"),
        },
    )
    response_model = namespace.model(
        "ThreatIntelligenceResponse",
        {
            "model": fields.String(required=True, description="生成内容使用的 LLM 模型。"),
            "topic": fields.String(required=True, description="请求中的威胁情报主题。"),
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
            "threat_actor": fields.String(required=False, description="模拟攻击组织或威胁主体。"),
            "ttps": fields.List(fields.String, required=True, description="MITRE ATT&CK 技术或战术列表。"),
            "indicators": fields.List(fields.Nested(indicator_model), required=True, description="模拟 IOC 列表。"),
            "recommendations": fields.List(fields.String, required=True, description="处置和检测建议。"),
            "raw_content": fields.String(required=True, description="LLM 返回的原始内容。"),
        },
    )

    @namespace.route("/generate")
    class ThreatIntelligenceResource(Resource):
        @namespace.expect(request_model, validate=True)
        @namespace.response(200, "生成成功。", response_model)
        @namespace.response(400, "请求参数校验失败。")
        @namespace.response(503, "未配置 DEEPSEEK_API_KEY。")
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
            except ValidationError as exc:
                return {"message": "请求参数校验失败。", "errors": exc.errors()}, 400
            except FastAPIHTTPException as exc:
                return {"message": exc.detail}, exc.status_code

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
