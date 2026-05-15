from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


INDEX_NAME = "es_api_event"
INDEX_MAPPING = {
  "mappings": {
    "_doc": {
      "properties": {
        "Data": {
          "properties": {
            "Image": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "InnerType": {
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
            "SignedSrcImg": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "SignedStartModule": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "SourceCommandLine": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "SourceImage": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "SourceParentImage": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "StartAddress": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "StartFunction": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "StartModule": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "TargetImage": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "TargetParentProcessId": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "TargetProcessID": {
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
            },
            "dangerTid": {
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
  "data.image": "Data.Image",
  "data.inner_type": "Data.InnerType",
  "data.process_id": "Data.ProcessID",
  "data.signed_src_img": "Data.SignedSrcImg",
  "data.signed_start_module": "Data.SignedStartModule",
  "data.source_command_line": "Data.SourceCommandLine",
  "data.source_image": "Data.SourceImage",
  "data.source_parent_image": "Data.SourceParentImage",
  "data.start_address": "Data.StartAddress",
  "data.start_function": "Data.StartFunction",
  "data.start_module": "Data.StartModule",
  "data.target_image": "Data.TargetImage",
  "data.target_parent_process_id": "Data.TargetParentProcessId",
  "data.target_process_id": "Data.TargetProcessID",
  "data.time": "Data.Time",
  "data.type": "Data.Type",
  "data.danger_tid": "Data.dangerTid",
  "data_sub_type": "DataSubType",
  "data_type": "DataType",
  "host_id": "HostID",
  "host_ip": "HostIp",
  "host_mac": "HostMAC",
  "pid_id": "PID_ID",
  "ppid_id": "PPID_ID",
  "time_stamp": "TimeStamp"
}


class ApiEventData(BaseModel):
    model_config = ConfigDict(extra="allow")

    image: str | None = Field(
        default=None,
        description="进程镜像路径或可执行文件路径，来源于 ES 字段 Data.Image，ES 类型 text。",
    )
    inner_type: str | None = Field(
        default=None,
        description="API 或内部事件类型，来源于 ES 字段 Data.InnerType，ES 类型 text。",
    )
    process_id: str | None = Field(
        default=None,
        description="进程 ID，来源于 ES 字段 Data.ProcessID，ES 类型 text。",
    )
    signed_src_img: str | None = Field(
        default=None,
        description="源进程镜像签名状态，来源于 ES 字段 Data.SignedSrcImg，ES 类型 text。",
    )
    signed_start_module: str | None = Field(
        default=None,
        description="启动模块签名状态，来源于 ES 字段 Data.SignedStartModule，ES 类型 text。",
    )
    source_command_line: str | None = Field(
        default=None,
        description="源进程命令行参数，来源于 ES 字段 Data.SourceCommandLine，ES 类型 text。",
    )
    source_image: str | None = Field(
        default=None,
        description="源进程镜像路径，来源于 ES 字段 Data.SourceImage，ES 类型 text。",
    )
    source_parent_image: str | None = Field(
        default=None,
        description="源父进程镜像路径，来源于 ES 字段 Data.SourceParentImage，ES 类型 text。",
    )
    start_address: str | None = Field(
        default=None,
        description="远程线程或模块启动地址，来源于 ES 字段 Data.StartAddress，ES 类型 text。",
    )
    start_function: str | None = Field(
        default=None,
        description="远程线程或模块启动函数，来源于 ES 字段 Data.StartFunction，ES 类型 text。",
    )
    start_module: str | None = Field(
        default=None,
        description="远程线程或 API 相关启动模块，来源于 ES 字段 Data.StartModule，ES 类型 text。",
    )
    target_image: str | None = Field(
        default=None,
        description="目标进程镜像路径，来源于 ES 字段 Data.TargetImage，ES 类型 text。",
    )
    target_parent_process_id: str | None = Field(
        default=None,
        description="目标父进程 ID，来源于 ES 字段 Data.TargetParentProcessId，ES 类型 text。",
    )
    target_process_id: str | None = Field(
        default=None,
        description="目标进程 ID，来源于 ES 字段 Data.TargetProcessID，ES 类型 text。",
    )
    time: str | None = Field(
        default=None,
        description="事件内部时间，来源于 ES 字段 Data.Time，ES 类型 text。",
    )
    type: str | None = Field(
        default=None,
        description="事件类型，来源于 ES 字段 Data.Type，ES 类型 text。",
    )
    danger_tid: str | None = Field(
        default=None,
        description="高危线程 ID，来源于 ES 字段 Data.dangerTid，ES 类型 text。",
    )

class ApiEventRecord(BaseModel):
    model_config = ConfigDict(extra="allow")

    data: ApiEventData | None = Field(
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


MODEL_CLASS = ApiEventRecord
