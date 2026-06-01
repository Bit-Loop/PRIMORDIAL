from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlsplit

from primordial.core.web.control_routes import dispatch_control_routes
from primordial.core.web.rag_routes import dispatch_rag_routes


def dispatch_web_request(
    app: Any,
    method: str,
    raw_path: str,
    body: bytes = b"",
    headers: dict[str, str] | None = None,
) -> Any:
    parsed = urlsplit(raw_path)
    path = parsed.path or "/"
    query = parse_qs(parsed.query)
    for handler in (_static_routes, _system_routes, dispatch_rag_routes, dispatch_control_routes):
        response = handler(app, method, path, query, body)
        if response is not None:
            return response
    return app._json_response({"error": "not found", "path": path}, status=404)


def _static_routes(app: Any, method: str, path: str, query: dict[str, list[str]], body: bytes) -> Any | None:
    if method == "GET" and path == "/":
        return app._static_response("index.html", "text/html; charset=utf-8")
    if method == "GET" and not path.startswith("/api/"):
        static = app._static_asset_response(path)
        if static is not None:
            return static
    return None


def _system_routes(app: Any, method: str, path: str, query: dict[str, list[str]], body: bytes) -> Any | None:
    if method == "GET" and path == "/api/health":
        return app._json_response(app.runtime.health_payload())
    if method == "GET" and path == "/api/control-plane":
        target = app._optional_query_string(query, "target")
        live_metrics = app._bool_param(query, "live_metrics", False)
        return app._json_response(app._control_plane_payload(target=target, live_metrics=live_metrics))
    if method == "GET" and path == "/api/system-metrics":
        return app._json_response(app._system_metrics_payload())
    if method == "GET" and path == "/api/storage-status":
        return app._json_response(app.runtime.storage_status_payload())
    if method == "GET" and path == "/api/self-test":
        with app._lock:
            return app._json_response(app.runtime.self_test_payload())
    if method == "GET" and path == "/api/operator-intent":
        return app._json_response(app.runtime.operator_intent_payload())
    if method == "GET" and path == "/api/credentials":
        return app._json_response(app.runtime.credentials_payload())
    return None
