from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


INDEX_NAME = "es_web_event"
INDEX_MAPPING = {
  "mappings": {
    "_doc": {
      "properties": {
        "Data": {
          "properties": {
            "Hashes": {
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
            "IsBlack": {
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
            "User": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "c-ip": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "cs-cookie": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "cs-method": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "cs-referer": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "cs-uri-query": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "cs-user-agent": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "cs-version": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "s-ip": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "s-port": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "sc-status": {
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
  "TimeStamp"
]
SOURCE_FIELD_MAP = {
  "data": "Data",
  "data.hashes": "Data.Hashes",
  "data.image": "Data.Image",
  "data.is_black": "Data.IsBlack",
  "data.process_id": "Data.ProcessID",
  "data.user": "Data.User",
  "data.c_ip": "Data.c-ip",
  "data.cs_cookie": "Data.cs-cookie",
  "data.cs_method": "Data.cs-method",
  "data.cs_referer": "Data.cs-referer",
  "data.cs_uri_query": "Data.cs-uri-query",
  "data.cs_user_agent": "Data.cs-user-agent",
  "data.cs_version": "Data.cs-version",
  "data.s_ip": "Data.s-ip",
  "data.s_port": "Data.s-port",
  "data.sc_status": "Data.sc-status",
  "data_sub_type": "DataSubType",
  "data_type": "DataType",
  "host_id": "HostID",
  "host_ip": "HostIp",
  "host_mac": "HostMAC",
  "pid_id": "PID_ID",
  "ppid_id": "PPID_ID",
  "time_stamp": "TimeStamp"
}


class WebEventData(BaseModel):
    model_config = ConfigDict(extra="allow")

    hashes: str | None = Field(
        default=None,
        description="文件或进程哈希值集合，来源于 ES 字段 Data.Hashes，ES 类型 text。",
    )
    image: str | None = Field(
        default=None,
        description="进程镜像路径或可执行文件路径，来源于 ES 字段 Data.Image，ES 类型 text。",
    )
    is_black: str | None = Field(
        default=None,
        description="是否命中黑名单或恶意判定，来源于 ES 字段 Data.IsBlack，ES 类型 text。",
    )
    process_id: str | None = Field(
        default=None,
        description="进程 ID，来源于 ES 字段 Data.ProcessID，ES 类型 text。",
    )
    user: str | None = Field(
        default=None,
        description="执行进程或访问资源的用户，来源于 ES 字段 Data.User，ES 类型 text。",
    )
    c_ip: str | None = Field(
        default=None,
        description="客户端 IP 地址，来源于 ES 字段 Data.c-ip，ES 类型 text。",
    )
    cs_cookie: str | None = Field(
        default=None,
        description="HTTP 请求 Cookie，来源于 ES 字段 Data.cs-cookie，ES 类型 text。",
    )
    cs_method: str | None = Field(
        default=None,
        description="HTTP 请求方法，来源于 ES 字段 Data.cs-method，ES 类型 text。",
    )
    cs_referer: str | None = Field(
        default=None,
        description="HTTP Referer 来源，来源于 ES 字段 Data.cs-referer，ES 类型 text。",
    )
    cs_uri_query: str | None = Field(
        default=None,
        description="HTTP 请求 URI 查询参数，来源于 ES 字段 Data.cs-uri-query，ES 类型 text。",
    )
    cs_user_agent: str | None = Field(
        default=None,
        description="HTTP User-Agent，来源于 ES 字段 Data.cs-user-agent，ES 类型 text。",
    )
    cs_version: str | None = Field(
        default=None,
        description="HTTP 协议版本，来源于 ES 字段 Data.cs-version，ES 类型 text。",
    )
    s_ip: str | None = Field(
        default=None,
        description="服务端 IP 地址，来源于 ES 字段 Data.s-ip，ES 类型 text。",
    )
    s_port: str | None = Field(
        default=None,
        description="服务端端口，来源于 ES 字段 Data.s-port，ES 类型 text。",
    )
    sc_status: str | None = Field(
        default=None,
        description="HTTP 响应状态码，来源于 ES 字段 Data.sc-status，ES 类型 text。",
    )

class WebEventRecord(BaseModel):
    model_config = ConfigDict(extra="allow")

    data: WebEventData | None = Field(
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


MODEL_CLASS = WebEventRecord
