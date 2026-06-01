from __future__ import annotations

import json
import re
from typing import Any


def parse_claude_stdout(stdout: str) -> tuple[str, dict[str, Any] | list[Any] | None]:
    stripped = stdout.strip()
    if not stripped:
        return "", None
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        return stripped, None
    if isinstance(data, dict):
        for key in ("result", "completion", "text", "message"):
            value = data.get(key)
            if isinstance(value, str):
                return value.strip(), data
        content = data.get("content")
        if isinstance(content, list):
            text = "\n".join(
                block.get("text", "")
                for block in content
                if isinstance(block, dict) and isinstance(block.get("text"), str)
            )
            if text:
                return text.strip(), data
    return stripped, data


def optional_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def parse_codex_session_id(stderr: str) -> str | None:
    match = re.search(r"session id:\s*([A-Za-z0-9._~+/\-=:-]+)", stderr, flags=re.IGNORECASE)
    return match.group(1) if match else None


def extract_stream_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if not isinstance(value, dict):
        return ""
    if isinstance(value.get("text"), str):
        return str(value["text"])
    delta = value.get("delta")
    if isinstance(delta, dict) and isinstance(delta.get("text"), str):
        return str(delta["text"])
    message = value.get("message")
    if isinstance(message, dict):
        text = content_to_text(message.get("content"))
        if text:
            return text
    return content_to_text(value.get("content"))


def content_to_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(str(item["text"]))
        return "".join(parts)
    return ""
