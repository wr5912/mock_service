from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


INDEX_NAME = "es_threat_event"
INDEX_MAPPING = {
  "mappings": {
    "_doc": {
      "properties": {
        "DataSubType": {
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
        "IOAs": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "IOCs": {
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
        "accessDomain": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "accessIp": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "attackItemModels": {
          "properties": {
            "id": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "type": {
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
        "clientId": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "clientIndentity": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "companyId": {
          "type": "long"
        },
        "computerName": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "confidence": {
          "type": "long"
        },
        "createTime": {
          "type": "long"
        },
        "dealResult": {
          "type": "long"
        },
        "description": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "eventSource": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "extradesc": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "extradescEn": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "fileName": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "hasDeal": {
          "type": "boolean"
        },
        "hmAlertTime": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "ip": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "keyEvent": {
          "type": "boolean"
        },
        "osType": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "processIndentity": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "processMD5": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "processName": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "ruleId": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "ruleVersion": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "timestamp": {
          "type": "long"
        },
        "trigger": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "userName": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "versionName": {
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
  "timestamp",
  "createTime",
  "hmAlertTime"
]
SOURCE_FIELD_MAP = {
  "data_sub_type": "DataSubType",
  "host_mac": "HostMAC",
  "ioas": "IOAs",
  "iocs": "IOCs",
  "pid_id": "PID_ID",
  "access_domain": "accessDomain",
  "access_ip": "accessIp",
  "attack_item_models": "attackItemModels",
  "attack_item_models.id": "attackItemModels.id",
  "attack_item_models.type": "attackItemModels.type",
  "client_id": "clientId",
  "client_identity": "clientIndentity",
  "company_id": "companyId",
  "computer_name": "computerName",
  "confidence": "confidence",
  "create_time": "createTime",
  "deal_result": "dealResult",
  "description": "description",
  "event_source": "eventSource",
  "extra_desc": "extradesc",
  "extra_desc_en": "extradescEn",
  "file_name": "fileName",
  "has_deal": "hasDeal",
  "hm_alert_time": "hmAlertTime",
  "ip": "ip",
  "key_event": "keyEvent",
  "os_type": "osType",
  "process_identity": "processIndentity",
  "process_md5": "processMD5",
  "process_name": "processName",
  "rule_id": "ruleId",
  "rule_version": "ruleVersion",
  "timestamp": "timestamp",
  "trigger": "trigger",
  "user_name": "userName",
  "version_name": "versionName"
}


class ThreatEventAttackItemModels(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str | None = Field(
        default=None,
        description="攻击项或对象 ID，来源于 ES 字段 attackItemModels.id，ES 类型 text。",
    )
    type: str | None = Field(
        default=None,
        description="攻击项或对象类型，来源于 ES 字段 attackItemModels.type，ES 类型 text。",
    )

class ThreatEventRecord(BaseModel):
    model_config = ConfigDict(extra="allow")

    data_sub_type: str | None = Field(
        default=None,
        description="事件数据子类型，来源于 ES 字段 DataSubType，ES 类型 text。",
    )
    host_mac: str | None = Field(
        default=None,
        description="终端或主机 MAC 地址，来源于 ES 字段 HostMAC，ES 类型 text。",
    )
    ioas: str | None = Field(
        default=None,
        description="攻击行为指标集合，来源于 ES 字段 IOAs，ES 类型 text。",
    )
    iocs: str | None = Field(
        default=None,
        description="威胁情报指标集合，来源于 ES 字段 IOCs，ES 类型 text。",
    )
    pid_id: str | None = Field(
        default=None,
        description="进程全局关联标识，来源于 ES 字段 PID_ID，ES 类型 text。",
    )
    access_domain: str | None = Field(
        default=None,
        description="访问域名，来源于 ES 字段 accessDomain，ES 类型 text。",
    )
    access_ip: str | None = Field(
        default=None,
        description="访问 IP 地址，来源于 ES 字段 accessIp，ES 类型 text。",
    )
    attack_item_models: ThreatEventAttackItemModels | None = Field(
        default=None,
        description="攻击项模型对象，来源于 ES 字段 attackItemModels，ES 类型 object。",
    )
    client_id: str | None = Field(
        default=None,
        description="客户端 ID，来源于 ES 字段 clientId，ES 类型 text。",
    )
    client_identity: str | None = Field(
        default=None,
        description="客户端身份标识，来源于 ES 字段 clientIndentity，ES 类型 text。",
    )
    company_id: int | None = Field(
        default=None,
        description="租户或公司 ID，来源于 ES 字段 companyId，ES 类型 long。",
    )
    computer_name: str | None = Field(
        default=None,
        description="终端计算机名称，来源于 ES 字段 computerName，ES 类型 text。",
    )
    confidence: int | None = Field(
        default=None,
        description="威胁置信度，来源于 ES 字段 confidence，ES 类型 long。",
    )
    create_time: int | None = Field(
        default=None,
        description="告警创建时间戳，来源于 ES 字段 createTime，ES 类型 long。",
    )
    deal_result: int | None = Field(
        default=None,
        description="处置结果编码，来源于 ES 字段 dealResult，ES 类型 long。",
    )
    description: str | None = Field(
        default=None,
        description="威胁或告警描述，来源于 ES 字段 description，ES 类型 text。",
    )
    event_source: str | None = Field(
        default=None,
        description="事件来源系统，来源于 ES 字段 eventSource，ES 类型 text。",
    )
    extra_desc: str | None = Field(
        default=None,
        description="中文扩展描述，来源于 ES 字段 extradesc，ES 类型 text。",
    )
    extra_desc_en: str | None = Field(
        default=None,
        description="英文扩展描述，来源于 ES 字段 extradescEn，ES 类型 text。",
    )
    file_name: str | None = Field(
        default=None,
        description="关联文件名称，来源于 ES 字段 fileName，ES 类型 text。",
    )
    has_deal: bool | None = Field(
        default=None,
        description="是否已处置，来源于 ES 字段 hasDeal，ES 类型 boolean。",
    )
    hm_alert_time: str | None = Field(
        default=None,
        description="告警展示时间，来源于 ES 字段 hmAlertTime，ES 类型 text。",
    )
    ip: str | None = Field(
        default=None,
        description="终端或受害主机 IP 地址，来源于 ES 字段 ip，ES 类型 text。",
    )
    key_event: bool | None = Field(
        default=None,
        description="是否为关键事件，来源于 ES 字段 keyEvent，ES 类型 boolean。",
    )
    os_type: str | None = Field(
        default=None,
        description="操作系统类型，来源于 ES 字段 osType，ES 类型 text。",
    )
    process_identity: str | None = Field(
        default=None,
        description="进程身份标识，来源于 ES 字段 processIndentity，ES 类型 text。",
    )
    process_md5: str | None = Field(
        default=None,
        description="进程文件 MD5，来源于 ES 字段 processMD5，ES 类型 text。",
    )
    process_name: str | None = Field(
        default=None,
        description="进程名称，来源于 ES 字段 processName，ES 类型 text。",
    )
    rule_id: str | None = Field(
        default=None,
        description="检测规则 ID，来源于 ES 字段 ruleId，ES 类型 text。",
    )
    rule_version: str | None = Field(
        default=None,
        description="检测规则版本，来源于 ES 字段 ruleVersion，ES 类型 text。",
    )
    timestamp: int | None = Field(
        default=None,
        description="事件时间戳，来源于 ES 字段 timestamp，ES 类型 long。",
    )
    trigger: str | None = Field(
        default=None,
        description="触发条件或触发内容，来源于 ES 字段 trigger，ES 类型 text。",
    )
    user_name: str | None = Field(
        default=None,
        description="用户名，来源于 ES 字段 userName，ES 类型 text。",
    )
    version_name: str | None = Field(
        default=None,
        description="客户端版本名称，来源于 ES 字段 versionName，ES 类型 text。",
    )


MODEL_CLASS = ThreatEventRecord
