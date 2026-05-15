# 网络安全运营模拟数据 API

这是一个基于 Python 3 和 FastAPI 的模拟数据服务，用于给 SOC、SIEM、SOAR、EDR、漏洞管理、威胁情报和安全运营看板等系统提供联调与演示数据。

服务默认不依赖外部网络。只有 `/api/v1/ai/scenarios` 会在配置 `DEEPSEEK_API_KEY` 后调用 DeepSeek 生成演练文本。

## 快速启动

```bash
uv venv .venv
uv pip install -e ".[test]"
.venv/bin/uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

启动后访问：

- Swagger UI：<http://127.0.0.1:8000/docs>
- ReDoc：<http://127.0.0.1:8000/redoc>
- OpenAPI JSON：<http://127.0.0.1:8000/openapi.json>
- 健康检查：<http://127.0.0.1:8000/health>

## 环境变量

复制 `.env.example` 为 `.env`，按需填写：

```bash
DEEPSEEK_API_KEY=
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-chat
```

不要把真实 API Key 写入代码或提交到 Git。

## Elasticsearch 与 Kibana 容器

项目提供 Elasticsearch `7.14.0` 单节点容器和 Kibana `7.14.0`，用于本地联调搜索、索引、日志类数据和可视化查询场景。

首次启动前复制 Docker 环境变量模板：

```bash
cp docker/.env.example docker/.env
```

启动 ES：

```bash
cd docker
docker compose up -d elasticsearch
```

启动 Kibana：

```bash
cd docker
docker compose up -d kibana
```

访问与验证：

- Elasticsearch HTTP 地址：<http://127.0.0.1:59200>
- Elasticsearch Transport 端口：`59300`
- Kibana 地址：<http://127.0.0.1:55601>
- Elasticsearch 健康检查：

```bash
curl "http://127.0.0.1:59200/_cluster/health?pretty"
```

- Kibana 健康检查：

```bash
curl "http://127.0.0.1:55601/api/status"
```

如已导入 `mock_es_data_json` 中的 OCSF 攻击链数据，可在 Kibana 中创建 Data View：

```bash
curl -X POST "http://127.0.0.1:55601/api/index_patterns/index_pattern" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d '{"index_pattern":{"title":"ocsf-attack-chain-*","timeFieldName":"time"}}'
```

创建后可在 Kibana 的 Discover 中选择 `ocsf-attack-chain-*` 查看数据。

停止 ES 与 Kibana：

```bash
cd docker
docker compose down
```

Elasticsearch 数据持久化目录为 `docker/volume/elasticsearch/data`。该目录只用于本地容器数据，不提交到 Git。

## API 清单

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/health` | 服务健康检查 |
| `GET` | `/api/v1/assets` | 生成资产列表 |
| `GET` | `/api/v1/alerts` | 生成安全告警列表 |
| `GET` | `/api/v1/incidents` | 生成安全事件单 |
| `GET` | `/api/v1/vulnerabilities` | 生成漏洞列表 |
| `GET` | `/api/v1/indicators` | 生成威胁情报 IOC |
| `GET` | `/api/v1/events` | 生成原始安全日志 |
| `GET` | `/api/v1/dashboard/summary` | 生成 SOC 看板汇总 |
| `POST` | `/api/v1/ai/scenarios` | 调用 DeepSeek 生成安全运营演练场景 |

所有列表接口都支持：

- `count`：返回记录数，范围 `1-200`。
- `seed`：随机种子。传入相同 `seed` 可得到稳定模拟数据，便于测试和截图复现。

## 请求示例

生成 3 条稳定告警：

```bash
curl "http://127.0.0.1:8000/api/v1/alerts?count=3&seed=7"
```

生成 SOC 看板汇总：

```bash
curl "http://127.0.0.1:8000/api/v1/dashboard/summary?seed=7"
```

调用 DeepSeek 生成演练场景：

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/ai/scenarios" \
  -H "Content-Type: application/json" \
  -d '{"topic":"勒索软件告警调查","language":"zh"}'
```

如果未配置 `DEEPSEEK_API_KEY`，该接口会返回 `503`，其他模拟数据接口不受影响。

## 数据对象

当前服务覆盖网络安全运营中最常用的数据对象：

- 资产：主机名、IP、负责人、业务域、资产类型、风险分、标签。
- 告警：标题、严重性、状态、来源、关联资产、MITRE ATT&CK 战术和技术。
- 事件单：标题、严重性、处置状态、处理人、关联告警、受影响资产。
- 漏洞：CVE、CVSS、组件、修复版本、暴露面和描述。
- IOC：IP、域名、URL、哈希、邮箱、威胁类型、置信度和发现时间。
- 原始事件：认证、网络、终端、云和应用日志。
- 看板汇总：告警数、严重告警数、未关闭事件数、存在漏洞资产数和高频战术。

## 测试

```bash
.venv/bin/pytest
```
