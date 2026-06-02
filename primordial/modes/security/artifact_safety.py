from __future__ import annotations

from typing import Any
import re

from primordial.adapters.caido_redaction import redact_request_path
from primordial.core.sensitive_text import redact_sensitive_text


SENSITIVE_KEY_RE = re.compile(
    r"(?i)(api[_-]?key|access[_-]?key|secret|password|passwd|pwd|token|authorization|webhook|credential|phrase)"
)
AUTH_HEADER_RE = re.compile(r"(?im)^(authorization\s*:\s*).+$")


def safe_artifact_payload(payload: Any, *, artifact_kind: str = "tool_output") -> Any:
    return _safe_value(payload, key=artifact_kind)


def _safe_value(value: Any, *, key: str = "") -> Any:
    if isinstance(value, dict):
        return {str(item_key): _safe_value(item, key=str(item_key)) for item_key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_safe_value(item, key=key) for item in value]
    if isinstance(value, bytes):
        return _safe_text(value.decode("utf-8", "replace"), key=key)
    if isinstance(value, str):
        return _safe_text(value, key=key)
    return value


def _safe_text(value: str, *, key: str = "") -> str:
    if SENSITIVE_KEY_RE.search(key):
        return "[redacted]" if value else ""
    text = AUTH_HEADER_RE.sub(r"\1[redacted]", redact_sensitive_text(str(value)))
    if "?" in text and text.startswith("/"):
        return redact_request_path(text)
    return text
