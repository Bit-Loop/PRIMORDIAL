from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .redaction import redact_json, redact_text


class RequestError(ValueError):
    pass


class ProviderError(RuntimeError):
    def __init__(self, message: str, *, status_code: int = 500) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass
class ChatRequest:
    provider: str | None = None
    prompt: str | None = None
    messages: list[dict[str, Any]] | None = None
    model: str | None = None
    effort: str | None = None
    cwd: str | None = None
    timeout_seconds: int | None = None
    system_prompt: str | None = None
    include_raw: bool = False
    dry_run: bool = False
    stream: bool = False
    fallback: bool = False
    conversation_id: str | None = None
    persist: bool | None = None
    allow_tools: bool = False
    claude_tools: str = ""
    claude_permission_mode: str = "dontAsk"
    claude_max_turns: int = 1
    codex_sandbox: str = "read-only"
    codex_ephemeral: bool = True
    safe_guard: bool = True


@dataclass
class ProviderResult:
    provider: str
    model: str | None
    text: str
    exit_code: int
    elapsed_seconds: float
    command: list[str]
    cwd: str
    stdout: str = ""
    stderr: str = ""
    raw_json: dict[str, Any] | list[Any] | None = None
    dry_run: bool = False
    request_id: str | None = None
    conversation_id: str | None = None
    session_resumed: bool = False
    warnings: list[str] = field(default_factory=list)
    fallback_attempts: list[dict[str, Any]] = field(default_factory=list)
    audit_events: list[dict[str, Any]] = field(default_factory=list)
    final_fallback: bool = False

    def public_dict(self, include_raw: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "request_id": self.request_id,
            "provider": self.provider,
            "model": self.model,
            "text": self.text,
            "exit_code": self.exit_code,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "cwd": self.cwd,
            "dry_run": self.dry_run,
            "conversation_id": self.conversation_id,
            "session_resumed": self.session_resumed,
            "command": shlex.join(self.command),
            "warnings": self.warnings,
            "fallback": {
                "used": bool(self.fallback_attempts),
                "attempts": self.fallback_attempts,
                "final": self.final_fallback,
            },
            "audit_events": self.audit_events,
        }
        if include_raw:
            data["stdout"] = redact_text(self.stdout)
            data["stderr"] = redact_text(self.stderr)
            data["raw_json"] = redact_json(self.raw_json)
        return data


@dataclass(frozen=True)
class PreparedRequest:
    request_id: str
    request: ChatRequest
    provider: str
    cwd: Path
    prompt: str
    timeout: int
    command: list[str]
    warnings: list[str]
    should_persist: bool
    conversation_id: str | None
    provider_session_id: str | None
    session_resumed: bool
