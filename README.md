# 基本运营模拟服务

本项目为安全运营产品联调提供本地基本数据，以及 `security-operations-expert` 所需的 HTTP API 和 MCP 服务。所有业务动作只更新模拟状态，不访问真实业务系统；无需模型或 API Key 生成数据。

模拟内容仅包括示例资产、正常登录、基础连接、测试告警、配置状态和演示工单。进程内业务状态在服务重启后重置。

## 启动

```bash
uv venv .venv
uv pip install --python .venv/bin/python -e ".[test]"
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 53001
```

- HTTP 文档：<http://127.0.0.1:53001/docs>
- 全部 API 规范：<http://127.0.0.1:53001/openapi.json>
- 智能体业务 API 规范：<http://127.0.0.1:53001/api/v1/security-operations/openapi.json>
- 平台资产关联告警编排规范：<http://127.0.0.1:53001/api/v1/security-operations/readonly/openapi.json>
- 健康检查：<http://127.0.0.1:53001/health>

保留的独立基本简报服务：

```bash
.venv/bin/python -m app.threat_intelligence
```

默认端口 `53002`，提供 `POST /generate`、`GET /health`、`GET /swagger.json` 和 `/docs`。通过进程环境变量 `THREAT_INTEL_HOST`、`THREAT_INTEL_PORT` 配置监听地址与端口，变量示例见 `.env.example`；该启动入口不自动加载 `.env`。两个服务均在对应终端按 `Ctrl+C` 停止。

完整 API/MCP 清单、MCP 管理界面配置、平台组合编排接入、固定后端环境变量及验证边界见 [security-operations-expert 接入说明](docs/security-operations-expert接入.md)。

## 基础 HTTP 数据

主服务提供资产、测试告警、事件单、组件状态、示例指标、常规日志、看板和本地基本场景；完整路径以 `/docs` 为准。列表支持 `count=1..200` 和 `seed`：

```bash
curl 'http://127.0.0.1:53001/api/v1/assets?count=3&seed=7'
curl 'http://127.0.0.1:53001/api/v1/dashboard/summary?seed=7'
```

原 `/api/v1/ai/scenarios` 与 `/generate` 入口保留，本地返回确定性的基本运营内容，不回显任意请求主题。原始兼容字段可为空，不提供攻击步骤、载荷、可执行命令或样本。

## Elasticsearch 与 Kibana

```bash
cp docker/.env.example docker/.env
cd docker
docker compose up -d elasticsearch kibana
```

Elasticsearch 为 <http://127.0.0.1:59200>，Kibana 为 <http://127.0.0.1:55601>；仅供本地联调。ES 数据卷为 `docker/volume/elasticsearch/data`，不清理或覆盖系统索引。

基本数据源和导入方法见 [ES 基本数据说明](mock_es_data_json/README.md)。旧数据归档已停止使用，无需 `git lfs pull`。

在 `docker/` 执行 `docker compose down` 停止容器，不删除数据卷。

## 验证

```bash
.venv/bin/pytest -q
```

接口合同、MCP 协议、基本数据约束和状态流程由测试覆盖。智能体业务验证须使用隔离实例、真实模型和实际工具回执；工具发现或 HTTP 成功不能代替业务闭环。
