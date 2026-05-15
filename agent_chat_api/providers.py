from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import time
import uuid
from copy import deepcopy
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Iterator

from .config import Settings
from .sessions import SessionRecord, SessionStore, SessionStoreError


PROVIDERS = {"codex", "claude"}
FINAL_FALLBACK_PROVIDER = "wrapper"
CODEX_SANDBOXES = {"read-only", "workspace-write", "danger-full-access"}
REASONING_EFFORTS = {"low", "medium", "high", "xhigh"}
SENSITIVE_RAW_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "access_token",
    "refresh_token",
    "session_id",
    "uuid",
}

DEFAULT_GUARD = (
    "You are being called through a narrow HTTP chat API. Answer the user's prompt directly. "
    "Do not install packages, edit files, run network operations, execute exploits, brute force, "
    "or validate credentials. If the request needs tool execution, say what would be needed instead."
)


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
            data["stdout"] = _redact_text(self.stdout)
            data["stderr"] = _redact_text(self.stderr)
            data["raw_json"] = _redact_json(self.raw_json)
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


@dataclass(frozen=True)
class StreamEvent:
    event: str
    data: dict[str, Any]


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
        effort=_optional_effort(effort),
        cwd=str(payload.get("cwd")) if payload.get("cwd") else None,
        timeout_seconds=_optional_int(payload.get("timeout_seconds")),
        system_prompt=str(payload.get("system_prompt")) if payload.get("system_prompt") else None,
        include_raw=_optional_bool(payload.get("include_raw"), default=False, field_name="include_raw"),
        dry_run=_optional_bool(payload.get("dry_run"), default=False, field_name="dry_run"),
        stream=_optional_bool(payload.get("stream"), default=False, field_name="stream"),
        fallback=_optional_bool(payload.get("fallback"), default=not provider_explicit, field_name="fallback") or False,
        conversation_id=str(payload.get("conversation_id")) if payload.get("conversation_id") else None,
        persist=_optional_bool(payload.get("persist"), default=None, field_name="persist"),
        allow_tools=_optional_bool(payload.get("allow_tools"), default=False, field_name="allow_tools"),
        claude_tools=str(payload.get("claude_tools", "")),
        claude_permission_mode=str(payload.get("claude_permission_mode", "dontAsk")),
        claude_max_turns=_optional_int(payload.get("claude_max_turns")) or 1,
        codex_sandbox=str(payload.get("codex_sandbox", "read-only")),
        codex_ephemeral=_optional_bool(payload.get("codex_ephemeral"), default=True, field_name="codex_ephemeral"),
        safe_guard=_optional_bool(payload.get("safe_guard"), default=True, field_name="safe_guard"),
    )


class ChatRunner:
    def __init__(self, settings: Settings, session_store: SessionStore | None = None) -> None:
        self.settings = settings
        self.session_store = session_store or SessionStore(settings.resolved_session_store_path())

    def providers(self) -> dict[str, dict[str, Any]]:
        paths = self.settings.provider_paths()
        return {
            name: {
                "available": path is not None,
                "path": path,
                "safe_default": self._safe_default_for(name),
            }
            for name, path in paths.items()
        }

    def run(self, request: ChatRequest) -> ProviderResult:
        fallback_enabled = bool(
            request.fallback
            and self.settings.provider_fallback_enabled
            and not request.dry_run
            and not request.conversation_id
        )
        if not fallback_enabled:
            prepared = self.prepare(request, stream=False)
            return self._run_prepared(prepared)

        attempts: list[dict[str, Any]] = []
        audit_events: list[dict[str, Any]] = []
        last_prepared: PreparedRequest | None = None
        for provider in self._fallback_provider_order(request.provider or self.settings.default_provider):
            attempt_request = replace(request, provider=provider, fallback=False)
            prepared = self.prepare(attempt_request, stream=False)
            last_prepared = prepared
            try:
                result = self._run_prepared(prepared)
            except ProviderError as exc:
                event = self._audit_event_for_failure(prepared, str(exc), status_code=exc.status_code)
                audit_events.append(event)
                attempts.append(self._fallback_attempt(event))
                continue

            event = self._audit_event_for_text(prepared, result.text)
            if event is not None:
                audit_events.append(event)
                attempts.append(self._fallback_attempt(event))
                continue

            result.fallback_attempts = attempts
            result.audit_events = audit_events
            return result

        return self._final_fallback_result(
            request,
            last_prepared=last_prepared,
            attempts=attempts,
            audit_events=audit_events,
        )

    def _run_prepared(self, prepared: PreparedRequest) -> ProviderResult:
        request = prepared.request
        if request.dry_run:
            return ProviderResult(
                provider=prepared.provider,
                model=request.model,
                text="",
                exit_code=0,
                elapsed_seconds=0.0,
                command=prepared.command,
                cwd=str(prepared.cwd),
                dry_run=True,
                request_id=prepared.request_id,
                conversation_id=prepared.conversation_id,
                session_resumed=prepared.session_resumed,
                warnings=prepared.warnings,
            )

        started = time.monotonic()
        try:
            completed = subprocess.run(
                prepared.command,
                input=prepared.prompt,
                cwd=str(prepared.cwd),
                env=os.environ.copy(),
                capture_output=True,
                text=True,
                timeout=prepared.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ProviderError(f"{prepared.provider} timed out after {prepared.timeout} seconds.", status_code=504) from exc
        except OSError as exc:
            raise ProviderError(f"{prepared.provider} failed to start: {exc}", status_code=502) from exc

        elapsed = time.monotonic() - started
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        raw_json = None
        if prepared.provider == "claude":
            text, raw_json = _parse_claude_stdout(stdout)
        else:
            text = stdout.strip()

        if completed.returncode != 0:
            detail = stderr.strip() or stdout.strip() or f"{prepared.provider} exited with {completed.returncode}"
            raise ProviderError(detail, status_code=502)

        self._record_session_if_needed(prepared, stdout=stdout, stderr=stderr, raw_json=raw_json)

        return ProviderResult(
            provider=prepared.provider,
            model=request.model,
            text=text,
            exit_code=completed.returncode,
            elapsed_seconds=elapsed,
            command=prepared.command,
            cwd=str(prepared.cwd),
            stdout=stdout,
            stderr=stderr,
            raw_json=raw_json,
            warnings=prepared.warnings,
            request_id=prepared.request_id,
            conversation_id=prepared.conversation_id,
            session_resumed=prepared.session_resumed,
        )

    def _fallback_provider_order(self, primary: str) -> list[str]:
        order: list[str] = []
        for provider in (primary, *self.settings.fallback_providers):
            try:
                normalized = _validate_provider(provider)
            except RequestError:
                continue
            if normalized not in order:
                order.append(normalized)
        return order

    def _audit_event_for_failure(
        self,
        prepared: PreparedRequest,
        message: str,
        *,
        status_code: int,
    ) -> dict[str, Any]:
        reason = _classify_provider_failure(message)
        event = self._audit_event(
            "provider_failure",
            prepared=prepared,
            reason=reason,
            status_code=status_code,
            snippet=message,
        )
        return event

    def _audit_event_for_text(self, prepared: PreparedRequest, text: str) -> dict[str, Any] | None:
        reason = _classify_refusal_text(text)
        if reason is None:
            return None
        return self._audit_event(
            "provider_refusal",
            prepared=prepared,
            reason=reason,
            status_code=200,
            snippet=text,
        )

    def _audit_event(
        self,
        event_type: str,
        *,
        prepared: PreparedRequest,
        reason: str,
        status_code: int,
        snippet: str,
    ) -> dict[str, Any]:
        event = {
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "type": event_type,
            "provider": prepared.provider,
            "reason": reason,
            "request_id": prepared.request_id,
            "status_code": status_code,
            "snippet": _safe_snippet(snippet),
        }
        self._write_audit_event(event)
        return event

    def _write_audit_event(self, event: dict[str, Any]) -> None:
        path = self.settings.resolved_audit_log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            path.parent.chmod(0o700)
        except OSError:
            pass
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            with os.fdopen(fd, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
        finally:
            try:
                path.chmod(0o600)
            except OSError:
                pass

    @staticmethod
    def _fallback_attempt(event: dict[str, Any]) -> dict[str, Any]:
        return {
            "provider": event.get("provider"),
            "reason": event.get("reason"),
            "status_code": event.get("status_code"),
            "request_id": event.get("request_id"),
            "snippet": event.get("snippet"),
        }

    def _final_fallback_result(
        self,
        request: ChatRequest,
        *,
        last_prepared: PreparedRequest | None,
        attempts: list[dict[str, Any]],
        audit_events: list[dict[str, Any]],
    ) -> ProviderResult:
        cwd = str(last_prepared.cwd if last_prepared else self.settings.workspace_root)
        request_id = last_prepared.request_id if last_prepared else uuid.uuid4().hex
        text = (
            "All configured chat providers failed, hit usage limits, or returned a refusal-style response. "
            "No synthetic model answer was generated. Check provider auth and usage, then retry or choose a specific healthy provider. "
            "The response includes fallback attempts and audit events for the failed providers."
        )
        return ProviderResult(
            provider=FINAL_FALLBACK_PROVIDER,
            model=request.model,
            text=text,
            exit_code=0,
            elapsed_seconds=0.0,
            command=["agent-chat-api", "final-fallback"],
            cwd=cwd,
            request_id=request_id,
            warnings=["All provider fallbacks were exhausted; returned deterministic wrapper guidance."],
            fallback_attempts=attempts,
            audit_events=audit_events,
            final_fallback=True,
        )

    def stream(self, request: ChatRequest) -> Iterator[StreamEvent]:
        prepared = self.prepare(request, stream=True)
        yield StreamEvent(
            "meta",
            {
                "request_id": prepared.request_id,
                "provider": prepared.provider,
                "model": request.model,
                "cwd": str(prepared.cwd),
                "dry_run": request.dry_run,
                "conversation_id": prepared.conversation_id,
                "session_resumed": prepared.session_resumed,
                "command": shlex.join(prepared.command),
                "warnings": prepared.warnings,
            },
        )
        if request.dry_run:
            yield StreamEvent("done", {"request_id": prepared.request_id, "text": ""})
            return

        started = time.monotonic()
        text_parts: list[str] = []
        stderr = ""
        raw_result: dict[str, Any] | list[Any] | None = None
        try:
            process = subprocess.Popen(
                prepared.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(prepared.cwd),
                env=os.environ.copy(),
                text=True,
            )
        except OSError as exc:
            yield StreamEvent("error", {"request_id": prepared.request_id, "error": f"{prepared.provider} failed to start: {exc}"})
            return
        assert process.stdin is not None
        process.stdin.write(prepared.prompt)
        process.stdin.close()

        assert process.stdout is not None
        for raw_line in process.stdout:
            line = raw_line.strip()
            if not line:
                continue
            event_payload: dict[str, Any]
            try:
                parsed: Any = json.loads(line)
            except json.JSONDecodeError:
                parsed = {"text": line}
            event_payload = _redact_json_value(parsed) if isinstance(parsed, dict) else {"payload": _redact_json_value(parsed)}
            if isinstance(parsed, dict) and parsed.get("type") == "result":
                raw_result = parsed
            delta = _extract_stream_text(parsed)
            yield StreamEvent("provider_event", {"request_id": prepared.request_id, "payload": event_payload})
            if delta:
                text_parts.append(delta)
                yield StreamEvent("delta", {"request_id": prepared.request_id, "text": delta})

        assert process.stderr is not None
        stderr = process.stderr.read() or ""
        return_code = process.wait()
        if return_code != 0:
            detail = stderr.strip() or f"{prepared.provider} exited with {return_code}"
            yield StreamEvent("error", {"request_id": prepared.request_id, "error": _redact_text(detail), "exit_code": return_code})
            return

        full_text = "".join(text_parts)
        if not full_text and isinstance(raw_result, dict):
            full_text = str(raw_result.get("result") or "")
        self._record_session_if_needed(prepared, stdout="", stderr=stderr, raw_json=raw_result)
        yield StreamEvent(
            "done",
            {
                "request_id": prepared.request_id,
                "text": full_text,
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "conversation_id": prepared.conversation_id,
                "session_resumed": prepared.session_resumed,
            },
        )

    def prepare(self, request: ChatRequest, *, stream: bool) -> PreparedRequest:
        request_id = uuid.uuid4().hex
        provider = _validate_provider(request.provider or self.settings.default_provider)
        cwd = self.resolve_cwd(request.cwd)
        prompt = self.build_prompt(request)
        timeout = self._timeout(request.timeout_seconds)
        session_record = self._load_session_record(request, provider=provider, cwd=cwd)
        should_persist = bool(request.conversation_id and request.persist is not False)
        provider_session_id = session_record.provider_session_id if session_record else None
        if should_persist and provider == "claude" and provider_session_id is None:
            provider_session_id = str(uuid.uuid4())
        command, warnings = self.build_command(
            request,
            provider,
            cwd,
            stream=stream,
            should_persist=should_persist,
            provider_session_id=provider_session_id,
            session_resumed=session_record is not None,
        )
        return PreparedRequest(
            request_id=request_id,
            request=request,
            provider=provider,
            cwd=cwd,
            prompt=prompt,
            timeout=timeout,
            command=command,
            warnings=warnings,
            should_persist=should_persist,
            conversation_id=request.conversation_id if should_persist else None,
            provider_session_id=provider_session_id,
            session_resumed=session_record is not None,
        )

    def build_prompt(self, request: ChatRequest) -> str:
        message_prompt = messages_to_prompt(request.messages) if request.messages else ""
        request_prompt = request.prompt.strip() if request.prompt else ""
        if not request_prompt and not message_prompt:
            raise RequestError("Provide prompt or messages.")

        parts: list[str] = []
        if request.safe_guard:
            parts.append(DEFAULT_GUARD)
        if request.system_prompt:
            parts.append(f"SYSTEM:\n{request.system_prompt.strip()}")
        if request_prompt:
            parts.append(request_prompt)
        if message_prompt:
            parts.append(message_prompt)
        prompt = "\n\n".join(part for part in parts if part).strip()
        if len(prompt) > self.settings.max_prompt_chars:
            raise RequestError(f"Prompt exceeds max length of {self.settings.max_prompt_chars} characters.")
        return prompt

    def resolve_cwd(self, cwd: str | None) -> Path:
        root = self.settings.workspace_root.resolve()
        path = Path(cwd).expanduser().resolve() if cwd else root
        if not path.is_dir():
            raise RequestError(f"cwd does not exist or is not a directory: {path}")
        if not self.settings.allow_any_cwd and path != root and root not in path.parents:
            raise RequestError(f"cwd must stay under workspace root: {root}")
        return path

    def build_command(
        self,
        request: ChatRequest,
        provider: str,
        cwd: Path,
        *,
        stream: bool = False,
        should_persist: bool = False,
        provider_session_id: str | None = None,
        session_resumed: bool = False,
    ) -> tuple[list[str], list[str]]:
        if provider == "claude":
            return self._build_claude_command(
                request,
                stream=stream,
                should_persist=should_persist,
                provider_session_id=provider_session_id,
                session_resumed=session_resumed,
            )
        if provider == "codex":
            return self._build_codex_command(
                request,
                cwd,
                stream=stream,
                should_persist=should_persist,
                provider_session_id=provider_session_id,
                session_resumed=session_resumed,
            )
        raise RequestError(f"Unsupported provider: {provider}")

    def _build_claude_command(
        self,
        request: ChatRequest,
        *,
        stream: bool,
        should_persist: bool,
        provider_session_id: str | None,
        session_resumed: bool,
    ) -> tuple[list[str], list[str]]:
        warnings: list[str] = []
        output_format = "stream-json" if stream else "json"
        command = [
            self.settings.claude_bin,
            "-p",
            "--output-format",
            output_format,
            "--input-format",
            "text",
            "--disable-slash-commands",
        ]
        if stream:
            command.append("--include-partial-messages")
        if session_resumed and provider_session_id:
            command.extend(["--resume", provider_session_id])
        elif should_persist and provider_session_id:
            command.extend(["--session-id", provider_session_id])
        else:
            command.append("--no-session-persistence")
        if request.claude_max_turns != 1:
            warnings.append("claude_max_turns is ignored by the CLI wrapper; use the Claude Agent SDK for multi-turn clients.")
        if request.allow_tools:
            tools = request.claude_tools or "default"
            command.extend(["--tools", tools, "--permission-mode", request.claude_permission_mode or "default"])
        else:
            command.extend(["--tools", "", "--permission-mode", "dontAsk"])
        if request.model:
            command.extend(["--model", request.model])
        if request.effort:
            command.extend(["--effort", request.effort])
        return command, warnings

    def _build_codex_command(
        self,
        request: ChatRequest,
        cwd: Path,
        *,
        stream: bool,
        should_persist: bool,
        provider_session_id: str | None,
        session_resumed: bool,
    ) -> tuple[list[str], list[str]]:
        sandbox = request.codex_sandbox
        if sandbox not in CODEX_SANDBOXES:
            raise RequestError(f"codex_sandbox must be one of: {', '.join(sorted(CODEX_SANDBOXES))}")
        if sandbox == "danger-full-access" and not self.settings.allow_dangerous_sandboxes:
            raise RequestError("danger-full-access is disabled. Set CHAT_API_ALLOW_DANGEROUS_SANDBOXES=1 to allow it.")

        warnings: list[str] = []
        if not request.allow_tools:
            warnings.append("Codex CLI does not expose a hard no-tools flag here; read-only sandbox and guard prompt are used.")

        if session_resumed and provider_session_id:
            command = [self.settings.codex_bin, "exec", "resume", "--skip-git-repo-check"]
            if stream:
                command.append("--json")
            if request.model:
                command.extend(["--model", request.model])
            if request.effort:
                command.extend(["-c", f'model_reasoning_effort="{request.effort}"'])
            command.extend([provider_session_id, "-"])
            return command, warnings

        command = [
            self.settings.codex_bin,
            "exec",
            "--color",
            "never",
            "--sandbox",
            sandbox,
            "--cd",
            str(cwd),
            "--skip-git-repo-check",
        ]
        if stream:
            command.append("--json")
        if request.codex_ephemeral and not should_persist:
            command.append("--ephemeral")
        if request.model:
            command.extend(["--model", request.model])
        if request.effort:
            command.extend(["-c", f'model_reasoning_effort="{request.effort}"'])
        command.append("-")
        return command, warnings

    def _load_session_record(self, request: ChatRequest, *, provider: str, cwd: Path) -> SessionRecord | None:
        if not request.conversation_id or request.persist is False:
            return None
        record = self.session_store.get(request.conversation_id)
        if record is None:
            return None
        try:
            self.session_store.assert_compatible(
                record,
                provider=provider,
                cwd=str(cwd),
                codex_sandbox=request.codex_sandbox if provider == "codex" else None,
            )
        except SessionStoreError as exc:
            raise RequestError(str(exc)) from exc
        return record

    def _record_session_if_needed(
        self,
        prepared: PreparedRequest,
        *,
        stdout: str,
        stderr: str,
        raw_json: dict[str, Any] | list[Any] | None,
    ) -> None:
        if not prepared.should_persist or prepared.conversation_id is None:
            return
        provider_session_id = prepared.provider_session_id
        if provider_session_id is None:
            if prepared.provider == "claude" and isinstance(raw_json, dict):
                provider_session_id = _optional_string(raw_json.get("session_id"))
            elif prepared.provider == "codex":
                provider_session_id = _parse_codex_session_id(stderr)
        if not provider_session_id:
            return
        self.session_store.save(
            conversation_id=prepared.conversation_id,
            provider=prepared.provider,
            provider_session_id=provider_session_id,
            cwd=str(prepared.cwd),
            codex_sandbox=prepared.request.codex_sandbox if prepared.provider == "codex" else None,
        )

    def _timeout(self, timeout: int | None) -> int:
        selected = self.settings.default_timeout_seconds if timeout is None else timeout
        if selected <= 0:
            raise RequestError("timeout_seconds must be greater than zero.")
        return min(selected, self.settings.max_timeout_seconds)

    @staticmethod
    def _safe_default_for(name: str) -> str:
        if name == "claude":
            return "non-interactive print mode with built-in tools disabled"
        if name == "codex":
            return "non-interactive exec mode with read-only sandbox"
        return "unknown"


def _parse_claude_stdout(stdout: str) -> tuple[str, dict[str, Any] | list[Any] | None]:
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


def _classify_provider_failure(message: str) -> str:
    normalized = _normalize_text(message)
    if any(token in normalized for token in ("usage limit", "usage cap", "no usage", "quota", "insufficient_quota", "credit balance")):
        return "quota_exhausted"
    if any(token in normalized for token in ("too many requests", "rate limit", "429")):
        return "rate_limited"
    if "timed out" in normalized or "timeout" in normalized:
        return "provider_timeout"
    if "failed to start" in normalized or "no such file" in normalized or "not found" in normalized:
        return "provider_unavailable"
    refusal = _classify_refusal_text(message)
    if refusal is not None:
        return refusal
    return "provider_error"


def _classify_refusal_text(text: str) -> str | None:
    normalized = _normalize_text(text)
    if not normalized:
        return "empty_response"
    refusal_patterns = (
        r"\bsorry[, ]+i (?:can'?t|cannot|am unable to|won'?t|will not)\b",
        r"\bi (?:can'?t|cannot) (?:assist|help|comply|do that|provide)\b",
        r"\bi am unable to (?:assist|help|comply|provide)\b",
        r"\bi'?m unable to (?:assist|help|comply|provide)\b",
        r"\bi (?:won'?t|will not) (?:assist|help|comply|provide)\b",
        r"\bcan'?t help with that\b",
        r"\bcannot help with that\b",
        r"\bagainst (?:policy|safety policy)\b",
        r"\bpolicy (?:does not allow|prohibits)\b",
    )
    for pattern in refusal_patterns:
        if re.search(pattern, normalized):
            return "refusal_response"
    return None


def _normalize_text(value: str) -> str:
    return value.replace("’", "'").replace("`", "'").strip().lower()


def _safe_snippet(value: str, limit: int = 220) -> str:
    redacted = _redact_text(value).replace("\r", " ").replace("\n", " ").strip()
    redacted = re.sub(r"\s+", " ", redacted)
    if len(redacted) <= limit:
        return redacted
    return redacted[: limit - 3].rstrip() + "..."


def _optional_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise RequestError(f"Expected integer value, got {value!r}") from exc


def _optional_bool(value: Any, *, default: bool | None, field_name: str) -> bool | None:
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


def _optional_effort(value: Any) -> str | None:
    if value in (None, ""):
        return None
    effort = str(value).strip().lower()
    if not effort:
        return None
    if effort not in REASONING_EFFORTS:
        raise RequestError(f"effort must be one of: {', '.join(sorted(REASONING_EFFORTS))}")
    return effort


def _validate_provider(provider: str) -> str:
    normalized = provider.strip().lower()
    if normalized not in PROVIDERS:
        raise RequestError(f"provider must be one of: {', '.join(sorted(PROVIDERS))}")
    return normalized


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _parse_codex_session_id(stderr: str) -> str | None:
    match = re.search(r"session id:\s*([A-Za-z0-9._~+/\-=:-]+)", stderr, flags=re.IGNORECASE)
    return match.group(1) if match else None


def _extract_stream_text(value: Any) -> str:
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
        content = message.get("content")
        text = _content_to_text(content)
        if text:
            return text
    content = value.get("content")
    return _content_to_text(content)


def _content_to_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(str(item["text"]))
        return "".join(parts)
    return ""


def _redact_json(value: dict[str, Any] | list[Any] | None) -> dict[str, Any] | list[Any] | None:
    if value is None:
        return None
    return _redact_json_value(deepcopy(value))


def _redact_json_value(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            if str(key).lower() in SENSITIVE_RAW_KEYS:
                redacted[key] = "[redacted]"
            else:
                redacted[key] = _redact_json_value(item)
        return redacted
    if isinstance(value, list):
        return [_redact_json_value(item) for item in value]
    return value


def _redact_text(value: str) -> str:
    redacted = value
    redacted = re.sub(r"(Bearer\s+)[A-Za-z0-9._~+/\-=]+", r"\1[redacted]", redacted)
    redacted = re.sub(
        r'("?(?:api_key|apikey|authorization|access_token|refresh_token|session_id|uuid)"?\s*[:=]\s*")([^"]+)(")',
        r"\1[redacted]\3",
        redacted,
        flags=re.IGNORECASE,
    )
    redacted = re.sub(
        r"((?:session id|session_id|uuid)\s*[:=]\s*)[A-Za-z0-9._~+/\-=:-]+",
        r"\1[redacted]",
        redacted,
        flags=re.IGNORECASE,
    )
    return redacted
