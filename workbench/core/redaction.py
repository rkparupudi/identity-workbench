"""Masking of secrets and personal data before text reaches a model or a log.

`redact_text` works on free text. `redact_obj` walks a decoded structure, drops
keys that hold secrets outright, and applies `redact_text` to every string.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

# Keys whose values are secrets whatever they contain.
SECRET_KEYS = {
    "signature", "signaturevalue", "signature_value", "x509certificate", "certificate",
    "client_secret", "clientsecret", "password", "passwd", "secret", "access_token",
    "refresh_token", "id_token", "assertion", "authorization", "cookie", "set-cookie",
    "api_key", "apikey", "private_key", "code", "samlresponse", "samlrequest", "token",
    "digestvalue", "ciphervalue",
}

_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
_KEY_VALUE = re.compile(
    r"(?i)\b(client_secret|password|passwd|pwd|secret|api[_-]?key|access_token|"
    r"refresh_token|id_token|code|assertion|SAMLResponse|SAMLRequest|token)"
    r"(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s&,;\"']+)"
)
_LONG_BLOB = re.compile(r"\b[A-Za-z0-9+/_-]{40,}={0,2}")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PEM = re.compile(r"-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----", re.S)


def _tag(kind: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:6]
    return f"<{kind}:{digest}>"


def redact_text(text: str, mask_emails: bool = True) -> str:
    """Replace tokens, secrets, long opaque blobs and (optionally) emails with tags.

    Tags carry a short hash, so the same value maps to the same tag and a reader
    can still tell 'these two fields were equal' without seeing the value.
    """
    if not text:
        return text
    text = _PEM.sub(lambda m: _tag("pem", m.group(0)), text)
    text = _JWT.sub(lambda m: _tag("jwt", m.group(0)), text)
    text = _BEARER.sub(lambda m: f"{m.group(1)} {_tag('credential', m.group(0))}", text)
    text = _KEY_VALUE.sub(lambda m: f"{m.group(1)}{m.group(2)}{_tag('secret', m.group(3))}", text)
    text = _LONG_BLOB.sub(lambda m: _tag("blob", m.group(0)), text)
    if mask_emails:
        text = _EMAIL.sub(lambda m: _tag("email", m.group(0).lower()), text)
    return text


def redact_obj(obj: Any, mask_emails: bool = True) -> Any:
    """Deep copy of `obj` that is safe to send to a model."""
    if isinstance(obj, dict):
        out = {}
        for key, value in obj.items():
            if str(key).lower().replace("-", "_") in SECRET_KEYS or str(key).lower() in SECRET_KEYS:
                out[key] = "<removed>" if value else value
            else:
                out[key] = redact_obj(value, mask_emails)
        return out
    if isinstance(obj, (list, tuple)):
        return [redact_obj(item, mask_emails) for item in obj]
    if isinstance(obj, str):
        return redact_text(obj, mask_emails)
    return obj


def mask_shape(value: str) -> str:
    """Keep the shape of a value but none of its content: 'Asha.Rao@x.com' -> 'Xxxx.Xxx@x.xxx'.

    Used to show a model what a column *looks like* when suggesting a mapping.
    """
    out = []
    for ch in value[:40]:
        if ch.isdigit():
            out.append("9")
        elif ch.isalpha():
            out.append("X" if ch.isupper() else "x")
        else:
            out.append(ch)
    return "".join(out)
