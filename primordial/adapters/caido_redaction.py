from __future__ import annotations

import json
import re
from urllib import parse

from primordial.adapters.caido_constants import SENSITIVE_HEADER_RE, SENSITIVE_PARAM_RE
from primordial.core.sensitive_text import redact_sensitive_text

HTTPQL_QUOTED_PATH_RE = re.compile(r'(?P<quote>["\'])(?P<path>/[^"\'\s]*\?[^"\'\s]*)(?P=quote)')


def redacted_snippet(value: str, max_chars: int) -> dict[str, object]:
    redacted_lines = []
    for line in value.splitlines():
        if SENSITIVE_HEADER_RE.match(line):
            name = line.split(":", 1)[0]
            redacted_lines.append(f"{name}: [redacted]")
        else:
            redacted_lines.append(redact_sensitive_text(SENSITIVE_PARAM_RE.sub(r"\1=[redacted]", line)))
    redacted = "\n".join(redacted_lines)
    selected_max = max(256, int(max_chars))
    return {
        "text": redacted[:selected_max],
        "truncated": len(redacted) > selected_max,
    }


def redact_request_path(path: object, query: object = "") -> str:
    raw_path = str(path or "/").strip() or "/"
    raw_query = str(query or "").strip()
    path_part, embedded_query = _split_request_target(raw_path)
    selected_query = raw_query or embedded_query
    redacted_path = redact_sensitive_text(path_part or "/")
    redacted_query = redact_query_string(selected_query)
    return f"{redacted_path}?{redacted_query}" if redacted_query else redacted_path


def redact_query_string(query: object) -> str:
    raw_query = str(query or "").strip().lstrip("?")
    if not raw_query:
        return ""
    pairs = parse.parse_qsl(raw_query, keep_blank_values=True)
    if not pairs:
        return "[redacted]"
    return parse.urlencode([(key, "[redacted]") for key, _ in pairs])


def redact_httpql_text(value: object) -> str:
    text = redact_sensitive_text(str(value or ""))

    def replace(match: re.Match[str]) -> str:
        quote = match.group("quote")
        return f"{quote}{redact_request_path(match.group('path'))}{quote}"

    return HTTPQL_QUOTED_PATH_RE.sub(replace, text)


def _split_request_target(path: str) -> tuple[str, str]:
    parsed = parse.urlsplit(path)
    if parsed.scheme in {"http", "https"}:
        selected_path = parsed.path or "/"
        return selected_path, parsed.query
    if "?" not in path:
        return path or "/", ""
    selected_path, selected_query = path.split("?", 1)
    return selected_path or "/", selected_query


def sanitize_graphql_errors(errors: object, secret: str) -> list[object]:
    if not isinstance(errors, list):
        return []
    return [sanitize_json(item, secret) for item in errors]


def sanitize_json(value: object, secret: str) -> object:
    if isinstance(value, dict):
        return {str(key): sanitize_json(item, secret) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize_json(item, secret) for item in value]
    if isinstance(value, str):
        return redact_secret(value, secret)
    return value


def redact_secret(value: str, secret: str) -> str:
    if secret:
        value = value.replace(secret, "[redacted]")
    return value


def contains_auth_error(errors: list[object]) -> bool:
    return any(contains_auth_text(json.dumps(item, sort_keys=True)) for item in errors)


def contains_auth_text(value: str) -> bool:
    lowered = value.lower()
    return (
        "unauthorized" in lowered
        or "forbidden" in lowered
        or "invalid token" in lowered
        or "invalid_token" in lowered
        or '"authorization"' in lowered
    )


def graphql_error_message(result: dict[str, object] | None) -> str:
    if not result:
        return "Caido GraphQL request failed."
    if result.get("error"):
        return str(result["error"])
    errors = result.get("errors")
    if isinstance(errors, list) and errors:
        return _format_graphql_error(errors[0])
    return "Caido GraphQL request failed."


def _format_graphql_error(first: object) -> str:
    if not isinstance(first, dict):
        return str(first)
    caido = first.get("extensions", {}).get("CAIDO") if isinstance(first.get("extensions"), dict) else None
    if isinstance(caido, dict):
        reason = str(caido.get("reason") or "").strip()
        code = str(caido.get("code") or "").strip()
        if reason or code:
            category = code.lower() if code else "graphql"
            return f"Caido {category} error: {reason or code}"
    return str(first.get("message") or first.get("code") or first.get("__typename") or first)
