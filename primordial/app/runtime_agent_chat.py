from __future__ import annotations

from primordial.app.runtime_deps import (
    AgentChatClient,
    EventRecord,
    EventType,
    os,
    shutil,
    subprocess,
    sys,
    urlparse,
    utc_now,
)

class RuntimeAgentChatMixin:
    def agent_chat_status_payload(self, *, timeout_seconds: int | float = 1) -> dict[str, object]:
        base = {
            "ok": False,
            "base_url": self.config.agent_chat_base_url,
            "provider": self.config.agent_chat_provider,
            "model": self.config.agent_chat_model,
            "auto_start": self.config.agent_chat_auto_start,
        }
        try:
            health = self.agent_chat.health(timeout_seconds=timeout_seconds)
        except Exception as exc:  # noqa: BLE001 - surfaced as health/status, not a traceback
            return {**base, "error": str(exc)}
        return {
            **base,
            "ok": bool(health.get("ok", True)),
            "health": health,
            "workspace_root": str(health.get("workspace_root") or ""),
            "default_provider": str(health.get("default_provider") or ""),
        }

    def _ensure_agent_chat_api_available(self) -> dict[str, object]:
        if not isinstance(self.agent_chat, AgentChatClient):
            return {"ok": True, "injected_client": type(self.agent_chat).__name__}
        status = self.agent_chat_status_payload(timeout_seconds=0.5)
        if status.get("ok"):
            return status
        if not self.config.agent_chat_auto_start:
            return status
        started = self._start_local_agent_chat_api()
        status = self.agent_chat_status_payload(timeout_seconds=2)
        return {**status, "auto_start_attempt": started}

    def _start_local_agent_chat_api(self) -> dict[str, object]:
        parsed = urlparse.urlsplit(self.config.agent_chat_base_url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if parsed.scheme not in {"http", ""}:
            return {"started": False, "reason": "only local http agent_chat_api can be auto-started"}
        if host not in {"127.0.0.1", "localhost", "::1"}:
            return {"started": False, "reason": "agent_chat_api base_url is not local"}
        script = self.config.project_root / "agent_chat_api" / "app.py"
        if not script.exists():
            return {"started": False, "reason": f"agent_chat_api launcher not found: {script}"}
        process_dir = self.config.runtime_dir / "agent_chat_api"
        process_dir.mkdir(parents=True, exist_ok=True)
        log_path = process_dir / "agent_chat_api.log"
        env = os.environ.copy()
        env.setdefault("CHAT_API_HOST", host)
        env.setdefault("CHAT_API_PORT", str(port))
        env.setdefault("CHAT_API_WORKSPACE_ROOT", str(script.parent))
        env.setdefault("CHAT_API_SESSION_STORE", str(process_dir / "sessions.json"))
        env.setdefault("CHAT_API_AUDIT_LOG", str(process_dir / "provider-audit.jsonl"))
        if self.config.agent_chat_api_key:
            env.setdefault("CHAT_API_KEY", self.config.agent_chat_api_key)
        if self.config.agent_chat_provider:
            env.setdefault("CHAT_API_DEFAULT_PROVIDER", self.config.agent_chat_provider)
        command = [
            sys.executable or shutil.which("python3") or "python3",
            str(script),
            "--host",
            host,
            "--port",
            str(port),
            "--workspace-root",
            str(script.parent),
        ]
        try:
            with log_path.open("ab") as handle:
                process = subprocess.Popen(
                    command,
                    cwd=str(script.parent),
                    env=env,
                    stdout=handle,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
        except OSError as exc:
            return {"started": False, "reason": str(exc), "command": command}
        self.store.set_setting(
            self.AGENT_CHAT_PROCESS_SETTING,
            {
                "pid": process.pid,
                "base_url": self.config.agent_chat_base_url,
                "log_path": str(log_path),
                "started_at": utc_now().isoformat(),
            },
        )
        self.store.insert_event(
            EventRecord(
                type=EventType.BOOTSTRAP,
                summary="agent_chat_api auto-start requested",
                metadata={"pid": process.pid, "base_url": self.config.agent_chat_base_url, "log_path": str(log_path)},
            )
        )
        return {"started": True, "pid": process.pid, "log_path": str(log_path), "command": command}
