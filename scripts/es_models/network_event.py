from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


INDEX_NAME = "es_network_event"
INDEX_MAPPING = {
  "mappings": {
    "_doc": {
      "properties": {
        "Data": {
          "properties": {
            "Msg": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "ProcessID": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "Type": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            }
          }
        },
        "DataSubType": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "DataType": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "HostID": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "HostIp": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "HostMAC": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "PID_ID": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "TimeStamp": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        }
      }
    }
  }
}
TIME_FIELD_CANDIDATES = [
  "TimeStamp"
]
SOURCE_FIELD_MAP = {
  "data": "Data",
  "data.msg": "Data.Msg",
  "data.process_id": "Data.ProcessID",
  "data.type": "Data.Type",
  "data_sub_type": "DataSubType",
  "data_type": "DataType",
  "host_id": "HostID",
  "host_ip": "HostIp",
  "host_mac": "HostMAC",
  "pid_id": "PID_ID",
  "time_stamp": "TimeStamp"
}


class NetworkEventData(BaseModel):
    model_config = ConfigDict(extra="allow")

    msg: str | None = Field(
        default=None,
        description="事件消息内容，来源于 ES 字段 Data.Msg，ES 类型 text。",
    )
    process_id: str | None = Field(
        default=None,
        description="进程 ID，来源于 ES 字段 Data.ProcessID，ES 类型 text。",
    )
    type: str | None = Field(
        default=None,
        description="事件类型，来源于 ES 字段 Data.Type，ES 类型 text。",
    )

class NetworkEventRecord(BaseModel):
    model_config = ConfigDict(extra="allow")

    data: NetworkEventData | None = Field(
        default=None,
        description="事件原始扩展数据对象，来源于 ES 字段 Data，ES 类型 object。",
    )
    data_sub_type: str | None = Field(
        default=None,
        description="事件数据子类型，来源于 ES 字段 DataSubType，ES 类型 text。",
    )
    data_type: str | None = Field(
        default=None,
        description="事件数据类型，来源于 ES 字段 DataType，ES 类型 text。",
    )
    host_id: str | None = Field(
        default=None,
        description="终端或主机唯一标识，来源于 ES 字段 HostID，ES 类型 text。",
    )
    host_ip: str | None = Field(
        default=None,
        description="终端或主机 IP 地址，来源于 ES 字段 HostIp，ES 类型 text。",
    )
    host_mac: str | None = Field(
        default=None,
        description="终端或主机 MAC 地址，来源于 ES 字段 HostMAC，ES 类型 text。",
    )
    pid_id: str | None = Field(
        default=None,
        description="进程全局关联标识，来源于 ES 字段 PID_ID，ES 类型 text。",
    )
    time_stamp: str | None = Field(
        default=None,
        description="事件采集或发生时间戳，来源于 ES 字段 TimeStamp，ES 类型 text。",
    )


MODEL_CLASS = NetworkEventRecord
