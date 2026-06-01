from __future__ import annotations

import re
from copy import deepcopy
from typing import Any


SENSITIVE_RAW_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "access_token",
    "refresh_token",
    "session_id",
    "uuid",
}


def redact_json(value: dict[str, Any] | list[Any] | None) -> dict[str, Any] | list[Any] | None:
    if value is None:
        return None
    return redact_json_value(deepcopy(value))


def redact_json_value(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            if str(key).lower() in SENSITIVE_RAW_KEYS:
                redacted[key] = "[redacted]"
            else:
                redacted[key] = redact_json_value(item)
        return redacted
    if isinstance(value, list):
        return [redact_json_value(item) for item in value]
    return value


def redact_text(value: str) -> str:
    redacted = value
    redacted = re.sub(r"(Bearer\s+)[A-Za-z0-9._~+/\-=]+", r"\1[redacted]", redacted)
    redacted = re.sub(
        r'("?(?:api_key|apikey|authorization|access_token|refresh_token|session_id|uuid)"?\s*[:=]\s*")([^"]+)(")',
        r"\1[redacted]\3",
        redacted,
        flags=re.IGNORECASE,
    )
    redacted = re.sub(
        r"((?:session id|session_id|uuid)\s*[:=]\s*)[A-Za-z0-9._~+/\-=:-]+",
        r"\1[redacted]",
        redacted,
        flags=re.IGNORECASE,
    )
    return redacted


def safe_snippet(value: str, limit: int = 220) -> str:
    redacted = redact_text(value).replace("\r", " ").replace("\n", " ").strip()
    redacted = re.sub(r"\s+", " ", redacted)
    if len(redacted) <= limit:
        return redacted
    return redacted[: limit - 3].rstrip() + "..."
