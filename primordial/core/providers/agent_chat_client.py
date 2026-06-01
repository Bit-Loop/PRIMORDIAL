from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any
from urllib import error, request


class AgentChatError(RuntimeError):
    pass


@dataclass(slots=True, frozen=True)
class AgentChatSettings:
    base_url: str = "http://127.0.0.1:8787"
    api_key: str | None = None
    provider: str = "claude"
    model: str | None = None
    timeout_seconds: int = 300
    cwd: Path | None = None
    safe_guard: bool = True
    codex_sandbox: str = "read-only"
    claude_permission_mode: str = "dontAsk"


@dataclass(slots=True, frozen=True)
class AgentChatResponse:
    provider: str
    model: str | None
    text: str
    exit_code: int
    elapsed_seconds: float
    request_id: str | None = None
    conversation_id: str | None = None
    session_resumed: bool = False
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    estimated_cost_usd: float = 0.0
    warnings: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


class AgentChatClient:
    def __init__(self, settings: AgentChatSettings) -> None:
        self.settings = settings

    def health(self, timeout_seconds: int | float = 5) -> dict[str, Any]:
        payload = self._json_request("GET", "/health", timeout_seconds=timeout_seconds)
        if not isinstance(payload, dict):
            raise AgentChatError("agent chat health response was not an object")
        return payload

    def chat(
        self,
        *,
        prompt: str,
        system_prompt: str | None = None,
        provider: str | None = None,
        model: str | None = None,
        effort: str | None = None,
        conversation_id: str | None = None,
        persist: bool = True,
    ) -> AgentChatResponse:
        selected_provider = (provider or self.settings.provider or "claude").strip().lower()
        payload = _chat_request_payload(self.settings, selected_provider, prompt, system_prompt, model, effort, persist)
        if conversation_id:
            payload["conversation_id"] = conversation_id

        response = self._json_request(
            "POST",
            "/api/chat",
            payload,
            timeout_seconds=self.settings.timeout_seconds + 10,
        )
        if not isinstance(response, dict):
            raise AgentChatError("agent chat response was not an object")
        return _chat_response_from_payload(response, selected_provider, model or self.settings.model)

    def _json_request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        timeout_seconds: int | float | None = None,
    ) -> Any:
        url = self.settings.base_url.rstrip("/") + path
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Accept": "application/json"}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        if self.settings.api_key:
            headers["Authorization"] = f"Bearer {self.settings.api_key}"
        req = request.Request(url, data=body, headers=headers, method=method)
        try:
            timeout = max(0.1, float(timeout_seconds if timeout_seconds is not None else self.settings.timeout_seconds))
            with request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            message = _error_message(raw) or f"HTTP {exc.code}"
            raise AgentChatError(f"agent chat API request failed: {message}") from exc
        except OSError as exc:
            raise AgentChatError(f"agent chat API is unreachable at {self.settings.base_url}: {exc}") from exc
        try:
            return json.loads(raw) if raw else {}
        except json.JSONDecodeError as exc:
            raise AgentChatError("agent chat API returned invalid JSON") from exc


def _chat_request_payload(
    settings: AgentChatSettings,
    selected_provider: str,
    prompt: str,
    system_prompt: str | None,
    model: str | None,
    effort: str | None,
    persist: bool,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "provider": selected_provider,
        "prompt": prompt,
        "include_raw": False,
        "stream": False,
        "dry_run": False,
        "persist": persist,
        "safe_guard": settings.safe_guard,
        "allow_tools": False,
        "codex_sandbox": settings.codex_sandbox,
        "claude_permission_mode": settings.claude_permission_mode,
        "timeout_seconds": settings.timeout_seconds,
    }
    if system_prompt:
        payload["system_prompt"] = system_prompt
    selected_model = model or settings.model
    if selected_model:
        payload["model"] = selected_model
    if effort:
        payload["effort"] = effort
    if settings.cwd is not None:
        payload["cwd"] = str(settings.cwd)
    return payload


def _chat_response_from_payload(
    response: dict[str, Any],
    selected_provider: str,
    selected_model: str | None,
) -> AgentChatResponse:
    usage = response.get("usage")
    usage_payload = usage if isinstance(usage, dict) else {}
    provider_meta = response.get("provider_meta")
    provider_meta_payload = provider_meta if isinstance(provider_meta, dict) else {}
    return AgentChatResponse(
        provider=str(response.get("provider") or selected_provider),
        model=str(response.get("model")) if response.get("model") else selected_model,
        text=str(response.get("text") or ""),
        exit_code=int(response.get("exit_code") or 0),
        elapsed_seconds=float(response.get("elapsed_seconds") or 0.0),
        request_id=str(response.get("request_id")) if response.get("request_id") else None,
        conversation_id=str(response.get("conversation_id")) if response.get("conversation_id") else None,
        session_resumed=bool(response.get("session_resumed")),
        prompt_tokens=_optional_int(usage_payload.get("prompt_tokens")),
        completion_tokens=_optional_int(usage_payload.get("completion_tokens")),
        estimated_cost_usd=_optional_float(
            response.get("estimated_cost_usd") or provider_meta_payload.get("estimated_cost_usd") or 0.0
        ),
        warnings=[str(item) for item in response.get("warnings", []) if str(item).strip()]
        if isinstance(response.get("warnings"), list)
        else [],
        raw=response,
    )


def _error_message(raw: str) -> str:
    try:
        payload = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return raw.strip()[:300]
    if isinstance(payload, dict):
        error_payload = payload.get("error")
        if isinstance(error_payload, dict):
            return str(error_payload.get("message") or error_payload)
        if error_payload:
            return str(error_payload)
    return raw.strip()[:300]


def _optional_int(value: object) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _optional_float(value: object) -> float:
    try:
        return float(value) if value is not None else 0.0
    except (TypeError, ValueError):
        return 0.0
