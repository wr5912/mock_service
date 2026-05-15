# 项目覆盖说明

本文件用于补充或覆盖 `AGENTS.md` 中的团队通用规则。

## 项目上下文

- 项目名称：网络安全运营模拟数据 API 服务
- 项目目标：为 SOC、SIEM、SOAR、EDR、漏洞管理、威胁情报和安全运营看板提供常用模拟数据接口。
- 关键用户：安全运营产品开发、前端联调、演示环境维护和测试人员。
- 当前阶段：FastAPI 初始服务、API 文档、本地 Elasticsearch 与 Kibana 容器建设。

## 代码结构

- 前端目录：不涉及。
- 后端目录：`app/`
- 共享契约目录：OpenAPI 由 FastAPI 自动生成，访问 `/openapi.json`。
- 配置目录：当前使用环境变量、`.env.example` 和 `docker/.env.example`。
- 测试目录：`tests/`

## 常用命令

```bash
# 安装依赖
uv venv .venv
uv pip install --python .venv/bin/python -e ".[test]"

# 本地开发
.venv/bin/uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# 测试
.venv/bin/pytest

# 启动 Elasticsearch
cd docker && docker compose up -d elasticsearch

# 启动 Kibana
cd docker && docker compose up -d kibana

# 构建
不涉及
```

## 项目特有规则

- API Key 只能通过环境变量读取，禁止写入代码、README 示例真实值或测试文件。
- DeepSeek 相关接口必须在未配置 `DEEPSEEK_API_KEY` 时优雅返回错误，不影响本地模拟数据接口。
- API 文档必须包含清晰的中文 summary、description、参数边界和响应模型。
- Elasticsearch 与 Kibana 只作为本地开发和联调容器，默认关闭安全认证，不用于生产环境。

## 验证要求

- 最小验证：`.venv/bin/pytest`
- 发布前验证：测试通过，人工访问 `/docs` 或 `/openapi.json` 检查 API 文档；如改动 Docker，运行 `docker compose config`。
- 无法运行验证时的替代检查：说明原因，并至少检查 FastAPI 路由、Pydantic 模型和 README 示例是否一致。

## Docker 约束

- Docker 卷挂载路径：`docker/volume/elasticsearch/data`
- 端口映射：`59200 -> 9200`，`59300 -> 9300`，`55601 -> 5601`
- 国内源例外：不涉及。

## 已知风险与例外

- `/api/v1/ai/scenarios` 依赖外部 DeepSeek API；离线或未配置 API Key 时会返回 `503`。
- Elasticsearch 和 Kibana 镜像使用 Elastic 官方镜像仓库，版本均为 `7.14.0`。
