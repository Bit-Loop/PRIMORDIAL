from __future__ import annotations

import hashlib
import json
from typing import Any


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def payload_hash(payload: Any) -> str:
    return sha256_text(stable_json(payload))


def stable_id(prefix: str, *parts: object, length: int = 24) -> str:
    digest = sha256_text(stable_json([str(part) for part in parts]))[:length]
    return f"{prefix}_{digest}"
