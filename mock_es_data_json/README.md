## Elasticsearch 导入指南

### 1. 创建索引

```bash
curl -X PUT "http://localhost:9200/ocsf-attack-chain-2026.05.14" \
  -H "Content-Type: application/json" \
  -d '{
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0
    },
    "mappings": {
      "dynamic": true,
      "properties": {
        "time": { "type": "date", "format": "epoch_millis" },
        "start_time": { "type": "date", "format": "epoch_millis" },
        "end_time": { "type": "date", "format": "epoch_millis" },
        "metadata.logged_time": { "type": "date", "format": "epoch_millis" },
        "class_uid": { "type": "integer" },
        "category_uid": { "type": "integer" },
        "activity_id": { "type": "integer" },
        "type_uid": { "type": "long" },
        "severity_id": { "type": "integer" },
        "status_id": { "type": "integer" }
      }
    }
  }'
```

### 2. 使用 Bulk API 导入

```bash
curl -X POST "http://localhost:9200/_bulk" \
  -H "Content-Type: application/x-ndjson" \
  --data-binary @ocsf_attack_chain_bulk.ndjson
```

### 3. 验证导入数量

```bash
curl "http://localhost:9200/ocsf-attack-chain-2026.05.14/_count?pretty"
```

预期返回：

```json
{
  "count": 15
}
```

### 4. 创建 Kibana Data View

启动 Kibana 后创建 Data View，索引匹配 `ocsf-attack-chain-*`，时间字段使用 `time`：

```bash
curl -X POST "http://localhost:5601/api/index_patterns/index_pattern" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d '{"index_pattern":{"title":"ocsf-attack-chain-*","timeFieldName":"time"}}'
```

本项目 Docker 默认将 Kibana 映射到宿主机 `55601`，从宿主机访问时使用：

```bash
curl -X POST "http://127.0.0.1:55601/api/index_patterns/index_pattern" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d '{"index_pattern":{"title":"ocsf-attack-chain-*","timeFieldName":"time"}}'
```

### 5. 查询攻击链

按受害 PC 查询：

```bash
curl "http://localhost:9200/ocsf-attack-chain-2026.05.14/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "term": {
        "device.name.keyword": "WS-FIN-023"
      }
    },
    "sort": [
      { "time": "asc" }
    ]
  }'
```

按攻击链关联 ID 查询：

```bash
curl "http://localhost:9200/ocsf-attack-chain-2026.05.14/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "term": {
        "metadata.correlation_uid.keyword": "corr-attack-chain-20260514-WS-FIN-023"
      }
    }
  }'
```

### 6. 关键一致性说明

这份数据中统一使用：

```json
{
  "victim_device": {
    "name": "WS-FIN-023",
    "hostname": "WS-FIN-023.acme.local",
    "ip": "10.10.20.25",
    "mac": "00:50:56:AA:20:25",
    "uid": "asset:acme:ws-fin-023"
  }
}
```

横向移动目标固定为：

```json
[
  {
    "name": "DC-01",
    "ip": "10.10.10.5",
    "mac": "00:50:56:AA:10:05"
  },
  {
    "name": "FS-01",
    "ip": "10.10.30.20",
    "mac": "00:50:56:AA:30:20"
  }
]
```

攻击者与 C2 固定为：

```json
{
  "external_attacker_ip": "203.0.113.45",
  "c2_ip": "198.51.100.77",
  "c2_domain": "cdn-update.example.net"
}
```

[1]: https://github.com/ocsf/ocsf-schema "GitHub - ocsf/ocsf-schema: OCSF Schema · GitHub"
