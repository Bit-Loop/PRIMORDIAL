from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path


def default_workspace_root() -> Path:
    return Path(__file__).resolve().parent


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _env_provider_order(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    value = os.getenv(name)
    if value is None:
        return default
    providers = tuple(item.strip().lower() for item in value.split(",") if item.strip())
    return providers or default


@dataclass(frozen=True)
class Settings:
    host: str = "127.0.0.1"
    port: int = 8787
    api_key: str | None = None
    workspace_root: Path = field(default_factory=default_workspace_root)
    allow_any_cwd: bool = False
    default_provider: str = "codex"
    fallback_providers: tuple[str, ...] = ("codex", "claude")
    provider_fallback_enabled: bool = True
    default_timeout_seconds: int = 300
    max_timeout_seconds: int = 900
    max_prompt_chars: int = 200_000
    codex_bin: str = "codex"
    claude_bin: str = "claude"
    allow_dangerous_sandboxes: bool = False
    session_store_path: Path | None = None
    audit_log_path: Path | None = None
    rate_limit_enabled: bool = True
    rate_limit_window_seconds: int = 60
    rate_limit_requests: int = 30

    @classmethod
    def from_env(cls) -> "Settings":
        workspace_root = Path(os.getenv("CHAT_API_WORKSPACE_ROOT", default_workspace_root())).expanduser().resolve()
        session_path = os.getenv("CHAT_API_SESSION_STORE")
        audit_path = os.getenv("CHAT_API_AUDIT_LOG")
        return cls(
            host=os.getenv("CHAT_API_HOST", "127.0.0.1"),
            port=_env_int("CHAT_API_PORT", 8787),
            api_key=os.getenv("CHAT_API_KEY") or None,
            workspace_root=workspace_root,
            allow_any_cwd=_env_bool("CHAT_API_ALLOW_ANY_CWD", False),
            default_provider=os.getenv("CHAT_API_DEFAULT_PROVIDER", "codex").strip().lower() or "codex",
            fallback_providers=_env_provider_order("CHAT_API_FALLBACK_PROVIDERS", ("codex", "claude")),
            provider_fallback_enabled=_env_bool("CHAT_API_PROVIDER_FALLBACK_ENABLED", True),
            default_timeout_seconds=_env_int("CHAT_API_TIMEOUT_SECONDS", 300),
            max_timeout_seconds=_env_int("CHAT_API_MAX_TIMEOUT_SECONDS", 900),
            max_prompt_chars=_env_int("CHAT_API_MAX_PROMPT_CHARS", 200_000),
            codex_bin=os.getenv("CHAT_API_CODEX_BIN") or shutil.which("codex") or "codex",
            claude_bin=os.getenv("CHAT_API_CLAUDE_BIN") or shutil.which("claude") or "claude",
            allow_dangerous_sandboxes=_env_bool("CHAT_API_ALLOW_DANGEROUS_SANDBOXES", False),
            session_store_path=Path(session_path).expanduser().resolve() if session_path else workspace_root / "runtime" / "sessions.json",
            audit_log_path=Path(audit_path).expanduser().resolve() if audit_path else workspace_root / "runtime" / "provider-audit.jsonl",
            rate_limit_enabled=_env_bool("CHAT_API_RATE_LIMIT_ENABLED", True),
            rate_limit_window_seconds=_env_int("CHAT_API_RATE_LIMIT_WINDOW_SECONDS", 60),
            rate_limit_requests=_env_int("CHAT_API_RATE_LIMIT_REQUESTS", 30),
        )

    def resolved_session_store_path(self) -> Path:
        return self.session_store_path or self.workspace_root / "runtime" / "sessions.json"

    def resolved_audit_log_path(self) -> Path:
        return self.audit_log_path or self.workspace_root / "runtime" / "provider-audit.jsonl"

    def provider_paths(self) -> dict[str, str | None]:
        return {
            "codex": shutil.which(self.codex_bin) or (self.codex_bin if Path(self.codex_bin).exists() else None),
            "claude": shutil.which(self.claude_bin) or (self.claude_bin if Path(self.claude_bin).exists() else None),
        }
