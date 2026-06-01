from __future__ import annotations

import json
import os
import shlex
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterator


@dataclass(frozen=True)
class StreamEvent:
    event: str
    data: dict[str, Any]


def stream_events(
    prepared: Any,
    *,
    record_session: Callable[..., None],
    redact_json_value: Callable[[Any], Any],
    redact_text: Callable[[str], str],
    extract_stream_text: Callable[[Any], str],
) -> Iterator[StreamEvent]:
    yield StreamEvent("meta", _stream_meta_payload(prepared))
    if prepared.request.dry_run:
        yield StreamEvent("done", {"request_id": prepared.request_id, "text": ""})
        return

    started = time.monotonic()
    text_parts: list[str] = []
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
    try:
        for raw_line in process.stdout:
            parsed = _parse_stream_line(raw_line)
            if parsed is None:
                continue
            event_payload = redact_json_value(parsed) if isinstance(parsed, dict) else {"payload": redact_json_value(parsed)}
            if isinstance(parsed, dict) and parsed.get("type") == "result":
                raw_result = parsed
            delta = extract_stream_text(parsed)
            yield StreamEvent("provider_event", {"request_id": prepared.request_id, "payload": event_payload})
            if delta:
                text_parts.append(delta)
                yield StreamEvent("delta", {"request_id": prepared.request_id, "text": delta})
    finally:
        process.stdout.close()

    assert process.stderr is not None
    try:
        stderr = process.stderr.read() or ""
    finally:
        process.stderr.close()
    return_code = process.wait()
    if return_code != 0:
        detail = stderr.strip() or f"{prepared.provider} exited with {return_code}"
        yield StreamEvent("error", {"request_id": prepared.request_id, "error": redact_text(detail), "exit_code": return_code})
        return

    raw_text = str(raw_result.get("result") or "") if isinstance(raw_result, dict) else ""
    record_session(prepared, stdout="", stderr=stderr, raw_json=raw_result)
    yield StreamEvent("done", _stream_done_payload(prepared, "".join(text_parts) or raw_text, started))


def _parse_stream_line(raw_line: str) -> Any | None:
    line = raw_line.strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return {"text": line}


def _stream_meta_payload(prepared: Any) -> dict[str, Any]:
    request = prepared.request
    return {
        "request_id": prepared.request_id,
        "provider": prepared.provider,
        "model": request.model,
        "cwd": str(prepared.cwd),
        "dry_run": request.dry_run,
        "conversation_id": prepared.conversation_id,
        "session_resumed": prepared.session_resumed,
        "command": shlex.join(prepared.command),
        "warnings": prepared.warnings,
    }


def _stream_done_payload(prepared: Any, text: str, started: float) -> dict[str, Any]:
    return {
        "request_id": prepared.request_id,
        "text": text,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "conversation_id": prepared.conversation_id,
        "session_resumed": prepared.session_resumed,
    }
