# Elasticsearch 基本模拟数据

`basic_operations.json` 是当前 ES 模拟记录的唯一可编辑来源，包含 21 个既有索引各一条基本资产或服务状态数据。地址使用保留 IP 与 example 域名，命令行字段为空，不对应真实事件或真实安全问题。

先检查本地数据，不访问 ES：

```bash
.venv/bin/python scripts/import_sanitized_es_data.py --dry-run
```

启动本地 ES 后导入：

```bash
.venv/bin/python scripts/import_sanitized_es_data.py
```

默认目标为 `http://127.0.0.1:59200`，可用 `DEST_ES_URL` 指定联调地址；认证需要时使用 `DEST_ES_USERNAME` 和 `DEST_ES_PASSWORD` 环境变量。默认遇到同名索引停止，不覆盖数据；只有显式传入 `--replace` 才删除并重建同名业务索引。脚本只操作本文件列出的业务索引，不操作系统索引。

脚本文件名沿用既有入口，但不再下载、解压或导入历史档案。旧来源定位见 [历史数据包说明](../exports/README.md)。
