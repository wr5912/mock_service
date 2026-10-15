# security-operations-expert 模拟接入

服务用于保持智能体 Harness 原样的文本业务联调。当前目标来源为 `EXP-security-operations-expert-019-rc442472a242a`；Agent 清单中的 EXP-008 与运行实例不同。本服务提供基础模拟结果，不代表真实 SOC 数据或实际设备执行。

下文以 `http://127.0.0.1:53001` 为 Mock 基址。客户端与服务分处主机时替换为客户端可访问的主机地址；容器内 `127.0.0.1` 只有在使用 host network 时才指向宿主服务。

## API 清单

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | `/health` | 健康状态 |
| GET | `/api/v1/assets` | 基本资产 |
| GET | `/api/v1/alerts` | 测试告警 |
| GET | `/api/v1/incidents` | 演示事件单 |
| GET | `/api/v1/vulnerabilities` | 基础组件状态 |
| GET | `/api/v1/indicators` | 基本示例指标 |
| GET | `/api/v1/events` | 常规日志 |
| GET | `/api/v1/dashboard/summary` | 基本汇总 |
| POST | `/api/v1/ai/scenarios` | 本地固定运维场景 |
| GET | `/api/external/detection-findings` | 测试发现列表 |
| GET | `/api/external/detection-findings/{finding_id}/analysis-result` | 基本分析结果 |
| POST | `/api/v1/mcp-resources/{resourceId}/tools/{fullToolName}/invoke` | 下表 19 项 SOC 操作，使用冻结的资源 UUID |
| POST | `/api/v1/emergency-actions/{operationId}/confirmations` | 模拟受信确认 |
| GET | `/api/v1/emergency-actions/{operationId}/result` | 查询模拟确认结果 |
| GET | `/reports/{report_id}.html` | 下载已创建的基本 HTML 报告 |
| GET | `/api/v1/security-operations/openapi.json` | 由实际业务路由派生的接入规范 |

主服务另有 `/openapi.json`、`/docs`、`/docs/oauth2-redirect`、`/redoc`。独立 `app.threat_analysis_mock_data.main:app` 复用发现接口；53002 独立服务提供 `POST /generate`、`GET /health`、`/swagger.json` 和 `/docs`。

SOC 操作请求是 `{"arguments": {...}}`，响应是 `{"status":"success","status_code":200,"result":{"code":200,"data":...}}`。

| 资源 | 完整操作名 |
|---|---|
| `ai_soc_correlate` | `ai_soc_correlate__get_correlate_incident_by_incident_id`、`ai_soc_correlate__get_correlate_incident_judge_pending`、`ai_soc_correlate__get_correlate_reasoning_rules_by_rule_id`、`ai_soc_correlate__get_correlate_threat_intel`、`ai_soc_correlate__get_correlate_intel_check`、`ai_soc_correlate__create_incident_judgement_claim`、`ai_soc_correlate__update_incident_judgement_result`、`ai_soc_correlate__create_correlate_incident_judgement_fail` |
| `ai_soc_detect` | `ai_soc_detect__get_detect_alert_by_alert_id`、`ai_soc_detect__list_detect_whitelist` |
| `ai_soc_event` | `ai_soc_event__search_event` |
| `ai_soc_master` | `ai_soc_master__get_soc_asset_by_asset_id`、`ai_soc_master__get_soc_asset_importance`、`ai_soc_master__get_soc_asset_biz_systems` |
| `ai_soc_ingest` | `ai_soc_ingest__get_ingest_devices_by_asset_by_asset_id` |
| `ai_soc_graph` | `ai_soc_graph__get_graph_enrich_topology_by_asset_id`、`ai_soc_graph__get_graph_identity_asset_accounts`、`ai_soc_graph__get_graph_lm_login_sequence`、`ai_soc_graph__get_graph_flow_host_pair_ports` |

各操作的实际路径、参数与响应见业务 OpenAPI；不从工具名推测真实上游 REST 路径。

## MCP 清单

传输使用 Streamable HTTP，地址保留尾斜杠。每组只发现本组工具，共 30 个。下面是协议原始工具名，DSH 自动添加 `mcp__<serverName>__` 前缀。

| serverName 与路径 | 原始工具名 |
|---|---|
| `sec-ops`，`/mcp/sec-ops/` | `search_graph_assets`、`get_graph_resolve_ip_host`、`get_soc_asset_by_asset_id`、`list_soc_asset`、`get_soc_asset_biz_systems`、`get_soc_asset_vulnerabilities`、`get_ingest_devices_by_asset_by_asset_id`、`get_graph_node_detail`、`get_graph_path_query`、`get_reachability_path_by_ip`、`get_graph_flow_host_pair_ports`、`get_reachability_cross_signal`、`get_graph_compliance_violations`、`get_graph_coverage`、`get_event_by_id` |
| `inspection`，`/mcp/inspection/` | `list_executable_inspections`、`start_inspection`、`get_inspection_result` |
| `policy-configuration`，`/mcp/policy-configuration/` | `prepare_policy_configuration`、`get_policy_configuration_status`、`select_policy_configuration_candidate`、`get_policy_configuration_result`、`confirm_policy_configuration` |
| `emergency-action`，`/mcp/emergency-action/` | `prepare_emergency_action`、`revise_emergency_action`、`get_emergency_action`、`list_emergency_actions`、`get_emergency_action_result`、`cancel_emergency_action` |
| `report`，`/mcp/report/` | `save_persistence_result` |

`confirm_policy_configuration` 只供受信确认器，MCP 管理界面中将策略服务设为“仅选定工具”，选择其余四项；`report` 由后端独立调用。策略业务回执中的 `code` 是字符串 `"200"`，SOC Gateway 和报告回执中的 `code` 是数字 `200`。

## 集成步骤

1. 按根 README 启动 Mock 服务。
2. 打开现有 `security-operations-expert-eval` 实例，保持标准镜像和只读装载的 EXP-019 Harness 原样。
3. 在该实例的 MCP 配置管理界面逐一编辑四个模型服务，选择“现成 MCP 连接”，保持上表 serverName，填写对应 Mock URL，清除旧上游 Header，启用并保存。
4. 切换到“工具与资源”，选择各服务执行发现，核对工具数、名称和参数。报告连接启用，但模型开放方式设为“仅选定工具”且留空；报告工具单独通过分组提供。
5. 新建 OpenAPI 连接 `soc-mock`，填写 `http://127.0.0.1:53001/api/v1/security-operations/openapi.json`，无需凭据。保存并发现 19 个操作；该诊断连接保持停用，研判后端仍走固定 Gateway。桥接生成的工具请求为 `{"body":{"arguments":{...}}}`。
6. 在“工具与资源分组”选择需要开放的工具，保存后刷新回读。当前分组见下文；分组通过界面的统一访问 Token 鉴权，Token 不写入文档。
7. 新建 Session 验证业务。界面发现使用已保存配置，不等于实际工具调用成功。

优先通过 MCP 管理插件配置连接和分组。当前 Harness 的研判 Gateway、研判报告存储、策略及应急受信确认器直接读取环境，不读取该插件的连接配置；只有这些入口使用以下运行环境变量。只在容器中的临时 shell 执行 `export` 不会改变 DSH 主进程：

| 环境变量 | 模拟配置 |
|---|---|
| `SOC_MCP_BASE_URL` | Mock 基址 |
| `REPORT_MCP_URL` | Mock 基址 + `/mcp/report/` |
| `POLICY_CONFIGURATION_MCP_URL` | Mock 基址 + `/mcp/policy-configuration/` |
| `SEC_OPS_MCP_TOKEN` | 独立测试值 |
| `EMERGENCY_WORKBENCH_URL` | Mock 基址 |
| `EMERGENCY_WORKBENCH_TOKEN` | 独立测试值 |
| `EMERGENCY_CONFIRMATION_PRIVATE_KEY_B64` | 隔离验证用 PEM 私钥的 Base64，Runtime 需要用其签名 |
| `EMERGENCY_CONFIRMATION_ACTOR_ID` | 独立测试身份 |
| `AI_WORKBENCH_EMERGENCY_TENANT_ID` | 独立测试标识 |
| `AI_WORKBENCH_EMERGENCY_WORKSPACE_ID` | 独立测试标识 |

模型仍使用现有 `LOCAL_LLM_BASE_URL`、`LOCAL_LLM_API_KEY` 等受控来源；不要把真实凭据写入本说明、普通日志或验收材料。报告内容由基本数据生成，不原样发布提交的 HTML。

## 验证边界

Mock 只处理已声明对象和基础模拟状态，不连接真实设备，不执行配置命令。业务状态在重启后重置，重启前创建的运行或下载地址随后可能不存在。

当前 Harness 的 SOC 参数来自冻结目录；部分标准 MCP 上游无法连接，完整 inputSchema 未取得。对应 Mock 合同以调用代码、Skill 和原样智能体实际调用验证，不声称逐字段复刻真实上游。

当前语音接口还包括 `POST /v1/audio/transcriptions`、`POST /tts/stream/cancellable`、`POST /tts/cancel/{generationId}` 和 `WS /v1/asr/stream`；模型接口为 `POST /v1/chat/completions`。它们本次不模拟。DSH 的 delegate、schedule、研判内部工具和管理接口继续使用原实现。

## 本次验证与使用

2026-10-15 已完成 94 项自动化测试及隔离实例实机验证。MCP 界面完成六个连接的保存、刷新回读和发现，五组 MCP 共 30 个工具，SOC OpenAPI 发现 19 个操作；[配置记录](evidence/ui-configuration-20261015.json)与[发现记录](evidence/ui-discovery-20261015.json)保留实际结果。

| 业务 | 实际结果与证据 |
|---|---|
| 巡检 | 完成并下载报告；[原始 Session](evidence/inspection-session-66175ec3-41cf-4ba7-aa79-9d2a74dc3369.json) |
| 浏览器续查 | 在原 Session 输入续查请求，仍只有一次发起、三次结果查询，下载地址不变；[浏览器记录](evidence/browser-business-20261015.json)、[页面](evidence/browser-business-20261015.png) |
| 故障排查 | 子智能体查询资产和路径，返回模拟可达结果并保留空数据限制；[Session](evidence/fault-session-e51204c1-02a1-4f25-8500-e9acde667140.json) |
| 策略 | 草案、受信确认、最终结果查询通过；[Session](evidence/policy-session-712b1ac4-6b82-4d17-a188-be3cf7b6994b.json) |
| 应急 | 草案、受信确认、最终查询通过；另测修订与取消；[确认 Session](evidence/emergency-session-1a3431ab-7e69-4b80-a059-ae154b184fe8.json)、[修订取消 Session](evidence/emergency-revise-cancel-session-f94e0c01-e615-400b-9f5d-1d549be52547.json) |
| 事件研判 | 名单快速路径与完整路径均完成结果回写、报告保存和下载；[快速路径](evidence/threat-fast-session-7a28409f-a86d-40af-8cd6-2c9b2432f687.json)、[完整路径](evidence/threat-full-session-401a5c14-7cae-4213-9c5c-4abf45870637.json) |
| 周期巡检 | 30 秒间隔按现有能力拒绝；改为 60 秒后实际到期、完成一次巡检并删除任务；[到期与清理记录](evidence/schedule-fired-completed-cleaned-20261015.json) |
| 自动研判 | 标准 120 秒受信心跳实际调用待研判批次工具，空队列返回 0 条，随后删除任务；[心跳记录](evidence/threat-auto-fired-20261015.json)、[清理记录](evidence/threat-auto-cleaned-20261015.json)。非空队列的自动处理未在本次心跳验证。 |
| ES 导入 | 创建此前不存在的 21 个业务索引，各导入一条基本记录，读取结果与审查后的源文件一致，未覆盖系统索引；[导入核对](evidence/es-basic-import-20261015.json) |

首次隔离验证使用 `security-operations-expert-mock`，与原实例共用标准镜像，使用独立 HOME 和只读 Candidate；[身份核对](evidence/runtime-identity-20261015.json)。当次验证未改动原实例与 Harness 资产。该验证实例随后按用户要求停止并删除，HOME 卷保留；[删除回执](evidence/mock-instance-deleted-20261015.json)。

原默认 `local-qwen` 连接超时，失败记录保留；上述成功 Session 使用既有 `deepseek-official/deepseek-flash`（界面显示 `DeepSeek-V41-Flash`）。打开新的业务 Session 时也应在模型选择器选择这一已验证模型，默认模型配置保持原样。策略及应急后续轮次曾被原 Guard 要求重新加载 Skill，模型恢复后完成，未修改 Guard 放行规则。

本机文件监听资源不足曾使隔离实例的 HMR 启动失败，进而阻止主对话 WebSocket 就绪。仅在该实例 HOME 的 `profiles/web/cordis.patch.yml` 禁用原生 `hmr` 开发热重载并重启后，已验证真实浏览器双向帧、Session 列表、历史结果和续查；未修改宿主限制或业务插件源码。

Mock 应急确认核对载荷与草案绑定，不验证生产签名；回执保留 `confirmation_proof_verified: false`。这不影响本次基础状态模拟，但不能视为真实审批或签名验收。

可直接体验：

- “请执行一次基础资产健康巡检，查询到完成结果并提供报告下载链接。”
- “请排查 192.0.2.10 到 192.0.2.20 的访问是否可达，只查询证据。”
- “请研判基本运维测试事件 INC-20261015-000001。”（快速路径）或 `INC-20261015-000002`（完整路径）。本次已认领完成，重新演示该事件的研判需重启 Mock 清空状态，已有报告链接也随之失效。

## 当前实例接入

当前使用平台已有的 `security-operations-expert-eval`，入口 <http://10.0.160.32:3081/assistant/>。连接和分组通过该实例 MCP 配置管理界面保存；Mock 地址使用 `http://10.0.160.32:53001`，使返回的报告地址也可在局域网访问。固定后端所需环境按上表补充，实例名称、端口、HOME 卷、标准镜像及只读 Harness 来源保持一致；[运行核对](evidence/eval-runtime-integration-20261015.json)。

| 分组 ID | 工具数 | 分组路径 |
|---|---:|---|
| `sec-ops` | 15 | `/assistant/mcp/groups/sec-ops` |
| `inspection` | 3 | `/assistant/mcp/groups/inspection` |
| `policy-configuration` | 4 | `/assistant/mcp/groups/policy-configuration` |
| `emergency-action` | 6 | `/assistant/mcp/groups/emergency-action` |
| `report` | 1 | `/assistant/mcp/groups/report` |
| `inspection-readonly`（原有分组） | 2 | `/assistant/mcp/groups/inspection-readonly` |

以上路径的主机和端口使用当前实例入口，通过 `Authorization: Bearer <统一访问 Token>` 调用。策略组不包含受信确认工具；报告服务器启用且模型工具选择为空，因此分组可提供报告保存，模型侧仍为原来的 28 个 MCP 工具。SOC OpenAPI 连接继续作为停用诊断来源，其 19 个操作供发现检查；研判实际调用固定 Gateway。所有组的 resources 和 resourceTemplates 均为空。

[浏览器配置](evidence/eval-ui-configuration-20261015.json)、[逐服务发现](evidence/eval-ui-discovery-20261015.json)及[分组保存与回读](evidence/eval-ui-groups-20261015.json)分别保留结果。6 个分组均完成真实协议初始化、发现及基本调用，缺少 Bearer 均返回 401，报告保存及下载成功；[分组协议检查](evidence/eval-group-protocol-20261015.json)。真实新 Session 已完成[巡检与局域网报告](evidence/eval-lan-inspection-session-6db23391-eae9-4153-95b2-535bb44db7dd.json)、[故障查询](evidence/eval-fault-session-cb6f2007-bd35-43e3-a481-58978b1fd20f.json)、[策略受信确认](evidence/eval-policy-session-6204c591-605c-42f8-a072-e61233911632.json)和[应急受信确认](evidence/eval-emergency-session-e2750051-2ac4-4a1c-a1de-38883c291a36.json)。[浏览器业务检查](evidence/eval-browser-business-20261015.json)确认会话历史、双向 WebSocket 与局域网报告下载。策略及应急的末轮查询曾被 Guard 要求先加载本轮 Skill，模型恢复后完成，原错误保留。

本轮另以实例原有客户端完成 SOC 事件读取、待研判查询和基本报告保存下载；[后端检查](evidence/eval-soc-backend-20261015.json)。该检查未重新认领已完成事件，不能代替本实例新的一次完整研判；首次隔离实例的完整研判证据仍见前文。

实例重建后曾出现 WebSocket 重连；仅在该实例 HOME 禁用原生开发 HMR 后恢复界面保存和刷新。当前容器没有提供可确认 ENOSPC 的日志，不将首次隔离实例的日志原因直接用于本次归因。模型继续使用既有 `deepseek-official/deepseek-flash`；新会话请选择 `DeepSeek-V41-Flash`。

普通 `docker restart security-operations-expert-eval` 保留容器已有环境。平台“重启”及 `dsh-dev up --replace` 会重建容器，必须再次提供上表运行环境；现有实例登记只保存变量名，不自动恢复变量值。原配置和必要启动环境已在本机私有目录备份，凭据未写入本文或证据。

停止当前实例使用原仓库 `dsh-dev down security-operations-expert-eval`；主 Mock 和独立简报服务在启动终端按 `Ctrl+C` 停止。Mock 服务重启后不保留模拟业务状态。
