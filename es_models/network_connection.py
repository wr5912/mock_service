from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


INDEX_NAME = "es_network_connection"
INDEX_MAPPING = {
  "mappings": {
    "_doc": {
      "properties": {
        "Data": {
          "properties": {
            "DestinationIp": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "DestinationIsIpv6": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "DestinationPort": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "Image": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "Initiated": {
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
            "Protocol": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "RecvLen": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "SendLen": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "SourceIp": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "SourceIsIpv6": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "SourcePort": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "Time": {
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
        "PPID_ID": {
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
  "TimeStamp",
  "Data.Time"
]
SOURCE_FIELD_MAP = {
  "data": "Data",
  "data.destination_ip": "Data.DestinationIp",
  "data.destination_is_ipv6": "Data.DestinationIsIpv6",
  "data.destination_port": "Data.DestinationPort",
  "data.image": "Data.Image",
  "data.initiated": "Data.Initiated",
  "data.process_id": "Data.ProcessID",
  "data.protocol": "Data.Protocol",
  "data.recv_len": "Data.RecvLen",
  "data.send_len": "Data.SendLen",
  "data.source_ip": "Data.SourceIp",
  "data.source_is_ipv6": "Data.SourceIsIpv6",
  "data.source_port": "Data.SourcePort",
  "data.time": "Data.Time",
  "data.type": "Data.Type",
  "data_sub_type": "DataSubType",
  "data_type": "DataType",
  "host_id": "HostID",
  "host_ip": "HostIp",
  "host_mac": "HostMAC",
  "pid_id": "PID_ID",
  "ppid_id": "PPID_ID",
  "time_stamp": "TimeStamp"
}


class NetworkConnectionData(BaseModel):
    model_config = ConfigDict(extra="allow")

    destination_ip: str | None = Field(
        default=None,
        description="目的 IP 地址，来源于 ES 字段 Data.DestinationIp，ES 类型 text。",
    )
    destination_is_ipv6: str | None = Field(
        default=None,
        description="目的地址是否为 IPv6，来源于 ES 字段 Data.DestinationIsIpv6，ES 类型 text。",
    )
    destination_port: str | None = Field(
        default=None,
        description="目的端口，来源于 ES 字段 Data.DestinationPort，ES 类型 text。",
    )
    image: str | None = Field(
        default=None,
        description="进程镜像路径或可执行文件路径，来源于 ES 字段 Data.Image，ES 类型 text。",
    )
    initiated: str | None = Field(
        default=None,
        description="连接是否由本机主动发起，来源于 ES 字段 Data.Initiated，ES 类型 text。",
    )
    process_id: str | None = Field(
        default=None,
        description="进程 ID，来源于 ES 字段 Data.ProcessID，ES 类型 text。",
    )
    protocol: str | None = Field(
        default=None,
        description="网络协议，来源于 ES 字段 Data.Protocol，ES 类型 text。",
    )
    recv_len: str | None = Field(
        default=None,
        description="接收字节数或接收长度，来源于 ES 字段 Data.RecvLen，ES 类型 text。",
    )
    send_len: str | None = Field(
        default=None,
        description="发送字节数或发送长度，来源于 ES 字段 Data.SendLen，ES 类型 text。",
    )
    source_ip: str | None = Field(
        default=None,
        description="源 IP 地址，来源于 ES 字段 Data.SourceIp，ES 类型 text。",
    )
    source_is_ipv6: str | None = Field(
        default=None,
        description="源地址是否为 IPv6，来源于 ES 字段 Data.SourceIsIpv6，ES 类型 text。",
    )
    source_port: str | None = Field(
        default=None,
        description="源端口，来源于 ES 字段 Data.SourcePort，ES 类型 text。",
    )
    time: str | None = Field(
        default=None,
        description="事件内部时间，来源于 ES 字段 Data.Time，ES 类型 text。",
    )
    type: str | None = Field(
        default=None,
        description="事件类型，来源于 ES 字段 Data.Type，ES 类型 text。",
    )

class NetworkConnectionRecord(BaseModel):
    model_config = ConfigDict(extra="allow")

    data: NetworkConnectionData | None = Field(
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
    ppid_id: str | None = Field(
        default=None,
        description="父进程全局关联标识，来源于 ES 字段 PPID_ID，ES 类型 text。",
    )
    time_stamp: str | None = Field(
        default=None,
        description="事件采集或发生时间戳，来源于 ES 字段 TimeStamp，ES 类型 text。",
    )


MODEL_CLASS = NetworkConnectionRecord
