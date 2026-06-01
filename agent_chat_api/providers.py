from __future__ import annotations

import os
import subprocess
import time
import uuid
from dataclasses import replace
from pathlib import Path
from typing import Any, Iterator

from .audit import (
    FINAL_FALLBACK_PROVIDER,
    audit_event_for_failure as _audit_event_for_failure,
    audit_event_for_text as _audit_event_for_text,
    classify_provider_failure as _classify_provider_failure,
    classify_refusal_text as _classify_refusal_text,
    fallback_attempt as _fallback_attempt,
    fallback_provider_order as _fallback_provider_order,
    final_fallback_result as _final_fallback_result,
    normalize_text as _normalize_text,
)
from .commands import (
    CODEX_SANDBOXES,
    build_claude_command as _build_claude_command,
    build_codex_command as _build_codex_command,
)
from .config import Settings
from .models import ChatRequest, PreparedRequest, ProviderError, ProviderResult, RequestError
from .parsing import (
    content_to_text as _content_to_text,
    extract_stream_text as _extract_stream_text,
    optional_string as _optional_string,
    parse_claude_stdout as _parse_claude_stdout,
    parse_codex_session_id as _parse_codex_session_id,
)
from .payloads import (
    PROVIDERS,
    REASONING_EFFORTS,
    messages_to_prompt,
    optional_bool as _optional_bool,
    optional_effort as _optional_effort,
    optional_int as _optional_int,
    request_from_payload,
    validate_provider as _validate_provider,
)
from .redaction import (
    SENSITIVE_RAW_KEYS,
    redact_json as _redact_json,
    redact_json_value as _redact_json_value,
    redact_text as _redact_text,
    safe_snippet as _safe_snippet,
)
from .sessions import SessionRecord, SessionStore, SessionStoreError
from .streaming import StreamEvent, stream_events


DEFAULT_GUARD = (
    "You are being called through a narrow HTTP chat API. Answer the user's prompt directly. "
    "Do not install packages, edit files, run network operations, execute exploits, brute force, "
    "or validate credentials. If the request needs tool execution, say what would be needed instead."
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
                "safe_default": _safe_default_for(name),
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
        audit_log_path = self.settings.resolved_audit_log_path()
        for provider in _fallback_provider_order(
            request.provider or self.settings.default_provider,
            self.settings.fallback_providers,
        ):
            attempt_request = replace(request, provider=provider, fallback=False)
            prepared = self.prepare(attempt_request, stream=False)
            last_prepared = prepared
            try:
                result = self._run_prepared(prepared)
            except ProviderError as exc:
                event = _audit_event_for_failure(
                    prepared,
                    str(exc),
                    status_code=exc.status_code,
                    audit_log_path=audit_log_path,
                )
                audit_events.append(event)
                attempts.append(_fallback_attempt(event))
                continue

            event = _audit_event_for_text(prepared, result.text, audit_log_path=audit_log_path)
            if event is not None:
                audit_events.append(event)
                attempts.append(_fallback_attempt(event))
                continue

            result.fallback_attempts = attempts
            result.audit_events = audit_events
            return result

        return _final_fallback_result(
            request,
            settings=self.settings,
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

    def stream(self, request: ChatRequest) -> Iterator[StreamEvent]:
        prepared = self.prepare(request, stream=True)
        yield from stream_events(
            prepared,
            record_session=self._record_session_if_needed,
            redact_json_value=_redact_json_value,
            redact_text=_redact_text,
            extract_stream_text=_extract_stream_text,
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
            return _build_claude_command(
                self.settings,
                request,
                stream=stream,
                should_persist=should_persist,
                provider_session_id=provider_session_id,
                session_resumed=session_resumed,
            )
        if provider == "codex":
            return _build_codex_command(
                self.settings,
                request,
                cwd,
                stream=stream,
                should_persist=should_persist,
                provider_session_id=provider_session_id,
                session_resumed=session_resumed,
            )
        raise RequestError(f"Unsupported provider: {provider}")

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


def _safe_default_for(name: str) -> str:
    if name == "claude":
        return "non-interactive print mode with built-in tools disabled"
    if name == "codex":
        return "non-interactive exec mode with read-only sandbox"
    return "unknown"
