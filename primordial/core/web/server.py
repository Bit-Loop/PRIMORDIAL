from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from threading import Event, Thread
from typing import Any

from primordial.app.runtime import PrimordialRuntime
from primordial.core.web.app import PrimordialWebApp, WebResponse


class _WebConsoleRequestHandler(BaseHTTPRequestHandler):
    server_version = "PrimordialWeb/0.1"

    @property
    def web_app(self) -> PrimordialWebApp:
        return self.server.web_app  # type: ignore[attr-defined]

    def do_GET(self) -> None:
        self._handle("GET")

    def do_POST(self) -> None:
        self._handle("POST")

    def do_DELETE(self) -> None:
        self._handle("DELETE")

    def _handle(self, method: str) -> None:
        try:
            body = self._read_body()
            response = self.web_app.dispatch(method, self.path, body, headers=dict(self.headers.items()))
        except ValueError as exc:
            response = WebResponse(
                status=400,
                body=json.dumps({"error": str(exc)}).encode("utf-8"),
                content_type="application/json; charset=utf-8",
                headers={"Cache-Control": "no-store"},
            )
        except Exception as exc:  # pragma: no cover
            response = WebResponse(
                status=500,
                body=json.dumps({"error": "internal server error", "detail": str(exc)}).encode("utf-8"),
                content_type="application/json; charset=utf-8",
                headers={"Cache-Control": "no-store"},
            )
        self._write_response(response)

    def _read_body(self) -> bytes:
        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = max(0, int(raw_length))
        except ValueError:
            length = 0
        return self.rfile.read(length) if length else b""

    def _write_response(self, response: WebResponse) -> None:
        self.send_response(response.status)
        self.send_header("Content-Type", response.content_type)
        for key, value in response.headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(response.body)

    def log_message(self, format: str, *args: Any) -> None:
        return


def build_web_console_server(
    runtime: PrimordialRuntime,
    *,
    host: str = "127.0.0.1",
    port: int = 1337,
    web_app: PrimordialWebApp | None = None,
) -> ThreadingHTTPServer:
    web_app = web_app or PrimordialWebApp(runtime)
    server = ThreadingHTTPServer((host, port), _WebConsoleRequestHandler)
    server.web_app = web_app  # type: ignore[attr-defined]
    return server


class WebConsoleThread:
    def __init__(self, runtime: PrimordialRuntime, *, host: str = "127.0.0.1", port: int = 1337) -> None:
        self.host = host
        self.port = port
        self.web_app = PrimordialWebApp(runtime)
        self.server = build_web_console_server(runtime, host=host, port=port, web_app=self.web_app)
        self.tick_runner = _ContinuousTickRunner(self.web_app)
        self.thread = Thread(target=self.server.serve_forever, name="primordial-web-console", daemon=True)

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def running(self) -> bool:
        return self.thread.is_alive()

    def start(self) -> None:
        if not self.thread.is_alive():
            self.web_app.runtime.repair_execution_state()
            self.tick_runner.start()
            self.thread.start()

    def stop(self) -> None:
        self.tick_runner.stop()
        self.server.shutdown()
        self.server.server_close()
        if self.thread.is_alive():
            self.thread.join(timeout=2)


class _ContinuousTickRunner:
    def __init__(self, web_app: PrimordialWebApp) -> None:
        self.web_app = web_app
        self._stop = Event()
        self._thread = Thread(target=self._run, name="primordial-continuous-tick", daemon=True)

    def start(self) -> None:
        if not self._thread.is_alive():
            self._stop.clear()
            self._thread = Thread(target=self._run, name="primordial-continuous-tick", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=2)

    def _run(self) -> None:
        while not self._stop.is_set():
            interval_seconds = 30
            try:
                outcome = self.web_app.continuous_tick_once()
                interval_seconds = max(2, int(outcome.get("interval_seconds") or 30))
            except Exception:
                interval_seconds = 30
            self._stop.wait(interval_seconds)


def serve_web_console(
    runtime: PrimordialRuntime,
    *,
    host: str = "127.0.0.1",
    port: int = 1337,
) -> None:
    runtime.repair_execution_state()
    web_app = PrimordialWebApp(runtime)
    tick_runner = _ContinuousTickRunner(web_app)
    server = build_web_console_server(runtime, host=host, port=port, web_app=web_app)
    print(f"Primordial web console listening on http://{host}:{port}")
    try:
        tick_runner.start()
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        tick_runner.stop()
        server.server_close()
