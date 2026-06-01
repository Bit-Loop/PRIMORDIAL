from __future__ import annotations

import json

from primordial.adapters.caido_constants import SENSITIVE_HEADER_RE, SENSITIVE_PARAM_RE


def redacted_snippet(value: str, max_chars: int) -> dict[str, object]:
    redacted_lines = []
    for line in value.splitlines():
        if SENSITIVE_HEADER_RE.match(line):
            name = line.split(":", 1)[0]
            redacted_lines.append(f"{name}: [redacted]")
        else:
            redacted_lines.append(SENSITIVE_PARAM_RE.sub(r"\1=[redacted]", line))
    redacted = "\n".join(redacted_lines)
    selected_max = max(256, int(max_chars))
    return {
        "text": redacted[:selected_max],
        "truncated": len(redacted) > selected_max,
    }


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
