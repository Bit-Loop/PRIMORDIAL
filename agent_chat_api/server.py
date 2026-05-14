from __future__ import annotations

import json
import time
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from .config import Settings
from .providers import ChatRunner, ProviderError, RequestError, request_from_payload
from .rate_limit import InMemoryRateLimiter, bucket_key_for_request


def create_app(settings: Settings) -> type[BaseHTTPRequestHandler]:
    runner = ChatRunner(settings)
    rate_limiter = InMemoryRateLimiter(settings)

    class Handler(BaseHTTPRequestHandler):
        server_version = "AgentChatAPI/0.1"

        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            if path in {"/health", "/api/health"}:
                self._write_json(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        "workspace_root": str(settings.workspace_root),
                        "default_provider": settings.default_provider,
                        "provider_fallback_enabled": settings.provider_fallback_enabled,
                        "fallback_providers": list(settings.fallback_providers),
                        "providers": runner.providers(),
                    },
                )
                return
            if path in {"/providers", "/api/providers"}:
                self._write_json(HTTPStatus.OK, {"providers": runner.providers()})
                return
            self._write_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

        def do_POST(self) -> None:
            if settings.api_key and self.headers.get("Authorization") != f"Bearer {settings.api_key}":
                self._write_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                return
            path = urlsplit(self.path).path
            if path == "/api/chat":
                self._handle_chat()
                return
            if path == "/v1/chat/completions":
                self._handle_openai_chat()
                return
            self._write_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _handle_chat(self) -> None:
            payload = self._read_json()
            if payload is None:
                return
            try:
                request = request_from_payload(payload, settings.default_provider)
                if not self._check_rate_limit(request):
                    return
                if request.stream:
                    self._handle_api_stream(request)
                    return
                result = runner.run(request)
            except RequestError as exc:
                self._write_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            except ProviderError as exc:
                self._write_json(exc.status_code, {"error": str(exc)})
                return
            self._write_json(HTTPStatus.OK, result.public_dict(include_raw=request.include_raw))

        def _handle_openai_chat(self) -> None:
            payload = self._read_json()
            if payload is None:
                return
            try:
                request = request_from_payload(payload, settings.default_provider)
                if not self._check_rate_limit(request):
                    return
                if request.stream:
                    self._handle_openai_stream(request, payload)
                    return
                result = runner.run(request)
            except RequestError as exc:
                self._write_json(HTTPStatus.BAD_REQUEST, {"error": {"message": str(exc), "type": "invalid_request_error"}})
                return
            except ProviderError as exc:
                self._write_json(exc.status_code, {"error": {"message": str(exc), "type": "provider_error"}})
                return

            now = int(time.time())
            response = {
                "id": f"chatcmpl-{uuid.uuid4().hex}",
                "object": "chat.completion",
                "created": now,
                "model": payload.get("model") or result.model or result.provider,
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": result.text},
                        "finish_reason": "stop",
                    }
                ],
                "provider": result.provider,
                "provider_meta": {
                    "request_id": result.request_id,
                    "elapsed_seconds": round(result.elapsed_seconds, 3),
                    "cwd": result.cwd,
                    "dry_run": result.dry_run,
                    "warnings": result.warnings,
                    "fallback": {
                        "used": bool(result.fallback_attempts),
                        "attempts": result.fallback_attempts,
                        "final": result.final_fallback,
                    },
                    "audit_events": result.audit_events,
                },
            }
            self._write_json(HTTPStatus.OK, response)

        def _handle_api_stream(self, request) -> None:
            self._write_sse_headers()
            for event in runner.stream(request):
                self._write_sse(event.event, event.data)

        def _handle_openai_stream(self, request, payload: dict[str, Any]) -> None:
            self._write_sse_headers()
            stream_id = f"chatcmpl-{uuid.uuid4().hex}"
            created = int(time.time())
            model = payload.get("model") or request.model or request.provider or settings.default_provider
            role_sent = False
            for event in runner.stream(request):
                if event.event == "meta":
                    self._write_sse_data(
                        {
                            "id": stream_id,
                            "object": "chat.completion.chunk",
                            "created": created,
                            "model": model,
                            "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}],
                            "provider": event.data.get("provider"),
                            "provider_meta": event.data,
                        }
                    )
                    role_sent = True
                    continue
                if event.event == "delta":
                    if not role_sent:
                        self._write_sse_data(
                            {
                                "id": stream_id,
                                "object": "chat.completion.chunk",
                                "created": created,
                                "model": model,
                                "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}],
                            }
                        )
                        role_sent = True
                    self._write_sse_data(
                        {
                            "id": stream_id,
                            "object": "chat.completion.chunk",
                            "created": created,
                            "model": model,
                            "choices": [{"index": 0, "delta": {"content": event.data.get("text", "")}, "finish_reason": None}],
                        }
                    )
                    continue
                if event.event == "error":
                    self._write_sse_data({"error": {"message": event.data.get("error", "provider error"), "type": "provider_error"}})
                    self._write_sse_raw("[DONE]")
                    return
                if event.event == "done":
                    self._write_sse_data(
                        {
                            "id": stream_id,
                            "object": "chat.completion.chunk",
                            "created": created,
                            "model": model,
                            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                            "provider_meta": event.data,
                        }
                    )
                    self._write_sse_raw("[DONE]")
                    return
            self._write_sse_raw("[DONE]")

        def _check_rate_limit(self, request) -> bool:
            if request.dry_run:
                return True
            authorization = self.headers.get("Authorization")
            client_ip = self.client_address[0] if self.client_address else "unknown"
            decision = rate_limiter.check(bucket_key_for_request(authorization=authorization, client_ip=client_ip))
            if decision.allowed:
                return True
            self._write_json(
                HTTPStatus.TOO_MANY_REQUESTS,
                {"error": "rate_limited", "reset_epoch": decision.reset_epoch},
                headers=decision.headers(),
            )
            return False

        def _read_json(self) -> dict[str, Any] | None:
            length_header = self.headers.get("Content-Length", "0")
            try:
                length = int(length_header)
            except ValueError:
                self._write_json(HTTPStatus.BAD_REQUEST, {"error": "invalid Content-Length"})
                return None
            raw = self.rfile.read(length)
            try:
                data = json.loads(raw.decode("utf-8") if raw else "{}")
            except json.JSONDecodeError as exc:
                self._write_json(HTTPStatus.BAD_REQUEST, {"error": f"invalid JSON: {exc}"})
                return None
            if not isinstance(data, dict):
                self._write_json(HTTPStatus.BAD_REQUEST, {"error": "JSON body must be an object"})
                return None
            return data

        def _write_json(self, status: int | HTTPStatus, payload: dict[str, Any], headers: dict[str, str] | None = None) -> None:
            body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_response(int(status))
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def _write_sse_headers(self) -> None:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()

        def _write_sse(self, event: str, data: dict[str, Any]) -> None:
            self.wfile.write(f"event: {event}\n".encode("utf-8"))
            self._write_sse_raw(json.dumps(data, ensure_ascii=False, separators=(",", ":")))

        def _write_sse_data(self, data: dict[str, Any]) -> None:
            self._write_sse_raw(json.dumps(data, ensure_ascii=False, separators=(",", ":")))

        def _write_sse_raw(self, data: str) -> None:
            for line in data.splitlines() or [""]:
                self.wfile.write(f"data: {line}\n".encode("utf-8"))
            self.wfile.write(b"\n")

    return Handler


class ReusableThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True


def run_server(settings: Settings) -> None:
    handler = create_app(settings)
    httpd = ReusableThreadingHTTPServer((settings.host, settings.port), handler)
    print(f"agent-chat-api listening on http://{settings.host}:{settings.port}")
    print(f"workspace_root={settings.workspace_root}")
    httpd.serve_forever()
