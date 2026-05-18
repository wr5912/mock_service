# threat-analysis-mock-data

自包含的 Threat Analysis 外部查询接口 mock 数据包。

提供接口：

```text
GET /api/external/detection-findings
GET /api/external/detection-findings/{finding_id}/analysis-result
```

## 独立启动

把整个目录复制到任意位置后，在该目录内运行：

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

## 挂到现有 FastAPI 应用

把整个目录复制到 `/home/admin/projects/mock_service/app/threat_analysis_mock_data` 后，在现有 FastAPI `app/main.py` 中加入：

```python
from app.threat_analysis_mock_data.router import router as threat_analysis_router

app.include_router(threat_analysis_router)
```

如果目录名保持 `threat-analysis-mock-data`，Python 不能直接用常规 import 导入带连字符的包名；建议复制时改名为 `threat_analysis_mock_data`。

## 数据说明

- `data/detection-findings.json`：finding 列表。
- `data/analysis-results/{finding_id}.json`：单条 finding 的聚合分析结果。

所有数据均为本地 JSON 文件，不依赖数据库、Neo4j、Elasticsearch 或 threat-analysis 项目代码。
