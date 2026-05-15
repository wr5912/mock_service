from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


INDEX_NAME = "es_file_access"
INDEX_MAPPING = {
  "mappings": {
    "_doc": {
      "properties": {
        "Data": {
          "properties": {
            "CommandLine": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
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
            "ParentCommandLine": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "ParentImage": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "ParentProcessID": {
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
            "TargetFilename": {
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
  "data.command_line": "Data.CommandLine",
  "data.hashes": "Data.Hashes",
  "data.image": "Data.Image",
  "data.is_black": "Data.IsBlack",
  "data.parent_command_line": "Data.ParentCommandLine",
  "data.parent_image": "Data.ParentImage",
  "data.parent_process_id": "Data.ParentProcessID",
  "data.process_id": "Data.ProcessID",
  "data.target_filename": "Data.TargetFilename",
  "data.user": "Data.User",
  "data_sub_type": "DataSubType",
  "data_type": "DataType",
  "host_id": "HostID",
  "host_ip": "HostIp",
  "host_mac": "HostMAC",
  "pid_id": "PID_ID",
  "ppid_id": "PPID_ID",
  "time_stamp": "TimeStamp"
}


class FileAccessData(BaseModel):
    model_config = ConfigDict(extra="allow")

    command_line: str | None = Field(
        default=None,
        description="进程命令行参数，来源于 ES 字段 Data.CommandLine，ES 类型 text。",
    )
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
    parent_command_line: str | None = Field(
        default=None,
        description="父进程命令行参数，来源于 ES 字段 Data.ParentCommandLine，ES 类型 text。",
    )
    parent_image: str | None = Field(
        default=None,
        description="父进程镜像路径，来源于 ES 字段 Data.ParentImage，ES 类型 text。",
    )
    parent_process_id: str | None = Field(
        default=None,
        description="父进程 ID，来源于 ES 字段 Data.ParentProcessID，ES 类型 text。",
    )
    process_id: str | None = Field(
        default=None,
        description="进程 ID，来源于 ES 字段 Data.ProcessID，ES 类型 text。",
    )
    target_filename: str | None = Field(
        default=None,
        description="目标文件路径或文件名，来源于 ES 字段 Data.TargetFilename，ES 类型 text。",
    )
    user: str | None = Field(
        default=None,
        description="执行进程或访问资源的用户，来源于 ES 字段 Data.User，ES 类型 text。",
    )

class FileAccessRecord(BaseModel):
    model_config = ConfigDict(extra="allow")

    data: FileAccessData | None = Field(
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


MODEL_CLASS = FileAccessRecord
