from __future__ import annotations

from typing import Any

from .models import ChatRequest, RequestError


PROVIDERS = {"codex", "claude"}
REASONING_EFFORTS = {"low", "medium", "high", "xhigh"}


def messages_to_prompt(messages: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for item in messages:
        role = str(item.get("role", "user")).strip() or "user"
        content = item.get("content", "")
        if isinstance(content, list):
            chunks = []
            for block in content:
                if isinstance(block, dict):
                    chunks.append(str(block.get("text", block.get("content", ""))))
                else:
                    chunks.append(str(block))
            text = "\n".join(chunk for chunk in chunks if chunk)
        else:
            text = str(content)
        if text:
            parts.append(f"{role.upper()}:\n{text}")
    return "\n\n".join(parts).strip()


def request_from_payload(payload: dict[str, Any], default_provider: str) -> ChatRequest:
    if not isinstance(payload, dict):
        raise RequestError("JSON body must be an object.")

    provider = payload.get("provider")
    provider_explicit = provider is not None
    model = payload.get("model")
    effort = payload.get("effort", payload.get("reasoning_effort"))
    if isinstance(model, str) and ":" in model:
        prefix, remainder = model.split(":", 1)
        if prefix.lower() in PROVIDERS and remainder:
            provider = provider or prefix.lower()
            provider_explicit = True
            model = remainder

    messages = payload.get("messages")
    if messages is not None and not isinstance(messages, list):
        raise RequestError("messages must be a list when provided.")

    prompt = payload.get("prompt")
    if prompt is not None:
        prompt = str(prompt)

    return ChatRequest(
        provider=str(provider or default_provider).lower(),
        prompt=prompt,
        messages=messages,
        model=str(model) if model else None,
        effort=optional_effort(effort),
        cwd=str(payload.get("cwd")) if payload.get("cwd") else None,
        timeout_seconds=optional_int(payload.get("timeout_seconds")),
        system_prompt=str(payload.get("system_prompt")) if payload.get("system_prompt") else None,
        include_raw=optional_bool(payload.get("include_raw"), default=False, field_name="include_raw"),
        dry_run=optional_bool(payload.get("dry_run"), default=False, field_name="dry_run"),
        stream=optional_bool(payload.get("stream"), default=False, field_name="stream"),
        fallback=optional_bool(payload.get("fallback"), default=not provider_explicit, field_name="fallback") or False,
        conversation_id=str(payload.get("conversation_id")) if payload.get("conversation_id") else None,
        persist=optional_bool(payload.get("persist"), default=None, field_name="persist"),
        allow_tools=optional_bool(payload.get("allow_tools"), default=False, field_name="allow_tools"),
        claude_tools=str(payload.get("claude_tools", "")),
        claude_permission_mode=str(payload.get("claude_permission_mode", "dontAsk")),
        claude_max_turns=optional_int(payload.get("claude_max_turns")) or 1,
        codex_sandbox=str(payload.get("codex_sandbox", "read-only")),
        codex_ephemeral=optional_bool(payload.get("codex_ephemeral"), default=True, field_name="codex_ephemeral"),
        safe_guard=optional_bool(payload.get("safe_guard"), default=True, field_name="safe_guard"),
    )


def optional_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise RequestError(f"Expected integer value, got {value!r}") from exc


def optional_bool(value: Any, *, default: bool | None, field_name: str) -> bool | None:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    raise RequestError(f"{field_name} must be a boolean.")


def optional_effort(value: Any) -> str | None:
    if value in (None, ""):
        return None
    effort = str(value).strip().lower()
    if not effort:
        return None
    if effort not in REASONING_EFFORTS:
        raise RequestError(f"effort must be one of: {', '.join(sorted(REASONING_EFFORTS))}")
    return effort


def validate_provider(provider: str) -> str:
    normalized = provider.strip().lower()
    if normalized not in PROVIDERS:
        raise RequestError(f"provider must be one of: {', '.join(sorted(PROVIDERS))}")
    return normalized
