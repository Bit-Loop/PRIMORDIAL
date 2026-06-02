from __future__ import annotations

from pathlib import Path
import re

from primordial.adapters.caido_redaction import redact_request_path
from primordial.core.sensitive_text import redact_sensitive_text
from primordial.labs.ctf.hardcode import FLAG_PATTERN


AUTH_HEADER_RE = re.compile(r"(?i)(authorization\s*:\s*).*$")
HOME_PATH_RE = re.compile(r"(?<![\w/])/(?:home|run/media|tmp)/[^\s]+")


def safe_evidence_line(line: object) -> str:
    text = str(line or "")
    if "=" not in text:
        return safe_evidence_value(text)
    key, value = text.split("=", 1)
    return f"{key}={safe_evidence_value(value)}"


def safe_evidence_value(value: object) -> str:
    text = FLAG_PATTERN.sub("[redacted-flag]", redact_sensitive_text(str(value or "")))
    text = AUTH_HEADER_RE.sub(r"\1[redacted]", text)
    if "?" in text and text.startswith("/"):
        text = redact_request_path(text)
    return HOME_PATH_RE.sub(lambda match: _safe_path(match.group(0)), text)


def _safe_path(value: str) -> str:
    path = Path(value)
    name = path.name
    return f"[redacted-path]/{name}" if name else "[redacted-path]"
