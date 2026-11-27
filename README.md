# 基本运营模拟服务

本项目为安全运营产品联调提供本地基本数据，以及 `security-operations-expert` 所需的 HTTP API 和 MCP 服务。所有业务动作只更新模拟状态，不访问真实业务系统；无需模型或 API Key 生成数据。

模拟内容仅包括示例资产、正常登录、基础连接、测试告警、配置状态和演示工单。进程内业务状态在服务重启后重置。

## 启动

```bash
uv venv .venv
uv pip install --python .venv/bin/python -e ".[test]"
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 53001
```

需要留存后台日志时，通过项目内脚本启动，标准输出和错误输出写入本仓库 `.local/logs/`，不要重定向到 `/tmp` 等项目外路径：

```bash
scripts/run_local.sh mock-53001 .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 53001
```

脚本会进入项目根目录并创建仅当前用户可写的日志；`.local/` 已加入 Git 忽略。直接在终端启动时，日志留在终端，不生成项目外的日志文件。

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

独立服务需要留存日志时，也通过同一脚本包裹上述启动命令，并按实际监听端口命名日志文件。

完整 API/MCP 清单、MCP 管理界面配置、平台组合编排接入、固定后端环境变量及验证边界见 [security-operations-expert 接入说明](docs/security-operations-expert接入.md)。

## 8 个 SOC MCP 服务的本地模拟

启动脚本会在 `127.0.0.1` 使用原端口启动 8 个独立模拟服务：

```bash
scripts/run_soc_mcp_mocks.sh
```

| 服务 | 本地地址 |
| --- | --- |
| `ai-soc-framework` | `http://127.0.0.1:18080` |
| `ai-soc-ingest` | `http://127.0.0.1:18081` |
| `ai-soc-response` | `http://127.0.0.1:18083` |
| `ai-soc-detect` | `http://127.0.0.1:18084` |
| `ai-soc-correlate` | `http://127.0.0.1:18085` |
| `ai-soc-master` | `http://127.0.0.1:18087` |
| `ai-soc-graph` | `http://127.0.0.1:18088` |
| `ai-soc-event` | `http://127.0.0.1:8083` |

每个服务提供 `/health`、`/v3/api-docs/mcp` 和 `/mcp/`。响应只包含固定本地测试数据，标记为 `simulated=true`、`sideEffect=false`；不访问真实系统、不执行真实动作、不生成攻击、渗透、恶意代码或攻击载荷内容。OpenAPI 地址使用当前请求的主机、端口和挂载前缀。

平台数据仓库中的原始 `mcp/manager.json` 不会被覆盖。需要本地联调时，只替换目标 IP，端口和路径保持不变：

```bash
.venv/bin/python scripts/render_local_mcp_manager.py \
  --source /path/to/harness-engineering-platform-data/mcp/manager.json \
  --output /path/to/local-data/mcp/manager.json
```

停止 8 个服务：

```bash
scripts/stop_soc_mcp_mocks.sh
```

停止入口仅终止启动记录所对应、仍监听目标端口的同一 SOC 进程；无法确认归属时提醒并保留记录。

Docker 容器需要访问时，将宿主 `docker0` 已配置的私有 IPv4 传给 `scripts/run_soc_mcp_mocks.sh --host 172.17.0.1`，停止该组使用 `scripts/stop_soc_mcp_mocks.sh --host 172.17.0.1`。无参命令操作回环组。

## MCP 管理页的 Host 服务

在 Mock 仓根目录运行 `scripts/run_host_mock.sh`。脚本复用 `.venv`，通过 OpenSSL 生成本机证书，并在 `tmux` 的 `host-mock` 会话中启动 HTTPS 服务。MCP 管理页已登记 `https://127.0.0.1:8443/app/v2/api-docs` 时，在 `host` 服务器点击「连接测试」，进入调试页后点击「发现工具与资源」即可调用。

| 工具 | 模拟接口 |
| --- | --- |
| `sendHmCmdUsingPOST` | `POST /app/ai/sendHmCmd` |
| `sendHmPolicyUsingPOST` | `POST /app/ai/sendHmPolicy` |

两个接口均接收 JSON，通过 MCP 调用时将请求对象放在 `body`。模拟服务只检查 `Authorization` 请求头是否存在。有效请求返回 `accepted: true`、`simulated: true`、`sideEffect: false` 的固定回执。健康检查地址为 `https://127.0.0.1:8443/health`，日志位于 `.local/logs/host-mock.log`。停止服务使用 `tmux kill-session -t '=host-mock'`。

如果平台仍记录上一次的连接失败，在 hep-lab 根目录刷新 `host` 的合同状态。

```bash
source ./tools/hep-env.sh --inherit
./harness-engineering-platform/platform/hep mcp probe host
```

## 网关与 MCP 闭环验收接口

默认关闭控制接口。仅在独立的本地验收实例中以 `MOCK_CONTROL_ENABLED=true` 启动；不要在现有共享演示服务上启用。控制接口不校验管理员身份，调用者可以调整测试凭据、风险和故障，因此只供受控联调环境使用。Docker 卷不涉及。

```bash
MOCK_CONTROL_ENABLED=true .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 53101 --no-access-log
```

以 `POST /api/v1/control/fixtures` 的 `{ "testRunId": "gateway-acceptance" }` 创建独立状态，默认两个稳定主体 `subject-a`、`subject-b` 均无风险限制。响应 `credentials` 仅在创建或轮换时返回测试凭据；服务只存其摘要，不写入请求账本。重复的 `testRunId` 返回 409，不覆盖历史记录。进程重启后 fixture 和账本重置。

| 接口 | 当前用途 |
| --- | --- |
| `POST /api/v1/control/identity/authenticate` | 接收 `{credential}`，返回 `authenticated`、`subjectId`、`credentialId`、`expiresAt`；未知、撤销或过期拒绝 |
| `POST /api/v1/control/identity/trust` | 接收 `{subjectId,credentialId}`，返回 `valid`、`subjectId`、`expiresAt`；轮换后旧标识不再可信 |
| `POST /api/v1/control/fixtures/{testRunId}/credentials/{subjectId}` | `{action: "rotate" \| "revoke" \| "expire"}`；轮换主体身份不变 |
| `PUT /api/v1/control/fixtures/{testRunId}/risk` | `{subjectId,agentId?,sessionId?,deniedOperations,expiresInSeconds?}`；可单独收紧某 Agent，限制可用 `*`、`write`、`publish`、`read` 或真实操作名，空数组只解除所选范围限制 |
| `POST /api/v1/control/risk/evaluate` | `{testRunId,subjectId,sessionId?,operation,phase,input?,scope?,sourceDigest?,operationBinding?}`；`operation` 保持动作名，`phase` 为 `input`、`execute` 或 `report`，返回明确范围、版本、有效期和约束 |
| `GET /api/v1/control/fixtures/{testRunId}/requests` | 读取目标收到的真实请求、参数摘要、提交与结束时间，不保存任意输入或正文 |
| `POST /api/v1/control/fixtures/{testRunId}/faults` | `{operation,mode,seconds?}`，一次性 `delay`、`block` 或 `committed-timeout`，最长 30 秒 |
| `POST /api/v1/control/fixtures/{testRunId}/faults/{faultId}/release` | 释放阻塞，继续同一个调用 |

业务 HTTP 和 MCP 请求携带 `X-Test-Run-Id` 选择 fixture，并可用 `X-Control-Subject-Id: subject-a` 或 `subject-b` 标注账本主体。两个 Header 只选择模拟状态和测试标签，**不是授权证明**；身份验证、资源归属及防护决定必须由真实平台完成。报告下载也须带相同 `X-Test-Run-Id`，不带或跨 fixture 下载返回 404。原本不带测试 Header 的业务接口保持原有行为和进程内状态。

风险请求的可选 `scope` 是平台已解析的 `{workspaceId,agentId,instanceId,runtimeGeneration,subjectId,sessionId?,serverId?}`，`sourceDigest` 是实际来源摘要；有具体工具或资源时，还可携带 `operationBinding: {serverId,operationId,target,method,kind}`。重复的主体、Session、服务和动作必须一致，否则返回不回显输入的 422。响应只回显明确提供的 Agent 范围，不回显来源摘要、实际操作目标或任意正文，也不把这些字段或 Header 当作认证证明；Agent 的 HMAC 认证与信任由真实平台完成，上表的 identity 接口只模拟接入用户认证与信任。

fixture 风险按 `(agentId,subjectId,sessionId)` 隔离保存。省略 `agentId` 保留原有主体／Session 规则并对匹配的 Agent 生效；指定 `agentId` 的规则只影响该 Agent，同一用户的其他 Agent 不继承。评估合并兼容规则与当前 Agent 规则，旧版仅包含主体／Session 的请求仍可用，但不会推测 Agent 归属。

同一明确评估范围的风险等级、约束或依据变化时，响应版本单调递增，或使用已由手动 fixture 更新推进的更高版本；标记输入恢复为干净输入也产生新事实版本。重复评估相同含义、只刷新有效期时不增加版本。服务仅保存最近含义摘要和版号，不保存风险请求正文或实际操作目标。

原有 SOC HTTP、只读资产告警查询、全部 MCP 工具、报告发布与下载以及 MCP Resource 读取记录目标账本。`phase` 从 `started` 进入 `committed` 再到 `finished`，时间戳说明实际阶段；提交后响应超时的结果为 `committed-response-unknown`，不能据此自动重发。拒绝尚未到达外部目标的请求，账本中应为零条。延迟和阻塞发生在处理器执行之前，提交后超时只影响响应，不回滚模拟副作用。

报告账本记录解码后正文的 SHA-256 摘要和固定测试标记。现有报告下载仍只提供基本元数据，不返回上传正文；因此必须检查发布请求是否到达目标及其 `reportBodyHash`，不能用下载文件中没有敏感标记来证明首次发布受保护。任意正文、原始参数和凭据不进入账本。

固定无害检测标记为 `MOCK_CONTROL_DENY_INPUT`（输入阶段限制全部操作）、`MOCK_CONTROL_DENY_WRITE`（执行阶段限制写入）、`MOCK_CONTROL_SENSITIVE_REPORT`（报告阶段限制发布）。它们只验证外部检测接入，不代表通用攻击识别。启用后 `/mcp/sec-ops/` 另提供可读取的固定资源 `mock-control://soc/asset-summary`，其他分组不增加资源。

本模拟服务不实现定时器或后台调度。首期验收只能声明经受管网关发起的即时任务检测、防护和恢复；定时任务的到时授权、撤权暂停及恢复仍须由平台和 Runtime 单独补齐并验证，不能从本测试结果推导。

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
