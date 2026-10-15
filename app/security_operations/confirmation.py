"""模拟确认只校验载荷绑定，不验证 RSA 签名或真实审批身份。"""
import base64
import binascii
import json
import time

from .state import MockError


def validate_proof(proof, operation, digest_field, purpose, legacy=False):
    try:
        encoded, signature = proof.split(".")
        payload = json.loads(base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True))
        if (not signature or not isinstance(payload, dict)
                or isinstance(payload.get("version"), bool) or not isinstance(payload.get("version"), int)
                or payload["operation_id"] != operation["operation_id"]
                or payload["version"] != operation["version"]
                or payload[digest_field] != operation[digest_field]
                or payload["decision"] != "CONFIRM"):
            raise ValueError
        if not legacy:
            if not base64.b64decode(signature + "=" * (-len(signature) % 4), altchars=b"-_", validate=True):
                raise ValueError
            issued, expires = payload.get("issued_at"), payload.get("expires_at")
            if (payload.get("purpose") != purpose or payload.get("audience") != "operation-confirmation-v1"
                    or payload.get("event_type") != "UserPromptSubmit"
                    or any(isinstance(value, bool) or not isinstance(value, int) for value in (issued, expires))
                    or not issued <= time.time() + 30 or not time.time() < expires <= issued + 120):
                raise ValueError
    except (ValueError, TypeError, AttributeError, KeyError, binascii.Error, UnicodeDecodeError):
        raise MockError(422, "模拟确认载荷与当前草案不一致或已过期") from None
