# Threat Analysis 基本状态模拟接口

该模块只提供本地基本资产与服务状态数据，不依赖外部模型、数据库或其他项目代码。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/external/detection-findings?limit=50` | 返回基本状态记录列表，limit 范围 1–200 |
| GET | `/api/external/detection-findings/{finding_id}/analysis-result` | 返回列表中对应记录的基本分析结构 |

主服务已经注册该 router，可直接随 `app.main:app` 使用。也可在项目根目录独立启动：

```bash
.venv/bin/uvicorn app.threat_analysis_mock_data.main:app --host 0.0.0.0 --port 53001
```

独立入口同样提供 `/health`、`/docs` 和 `/openapi.json`。

`data/detection-findings.json` 保存六条记录；`data/analysis-results/` 保存相同稳定 ID 的结果。内容均为基本模拟值：进程为演示服务、级别为 info、结论为 benign，相关技术与原始模型内容留空，不表示真实运行证据。
