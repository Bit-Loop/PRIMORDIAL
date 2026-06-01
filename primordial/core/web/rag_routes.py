from __future__ import annotations

from typing import Any
from urllib.parse import unquote

from primordial.core.context import is_operational_context_purpose


def dispatch_rag_routes(
    app: Any,
    method: str,
    path: str,
    query: dict[str, list[str]],
    body: bytes,
) -> Any | None:
    for handler in (
        _rag_status_routes,
        _rag_vuln_routes,
        _rag_inspection_routes,
        _rag_import_search_routes,
        _rag_synthesis_routes,
    ):
        response = handler(app, method, path, query, body)
        if response is not None:
            return response
    return None


def _rag_status_routes(app: Any, method: str, path: str, query: dict[str, list[str]], body: bytes) -> Any | None:
    if method == "GET" and path == "/api/rag/status":
        return app._json_response(app.runtime.rag_status())
    if method == "GET" and path == "/api/rag/config":
        return app._json_response(app.runtime.rag_config_payload())
    if method == "GET" and path == "/api/rag/vuln/status":
        return app._json_response(app.runtime.rag_vuln_status())
    return None


def _rag_vuln_routes(app: Any, method: str, path: str, query: dict[str, list[str]], body: bytes) -> Any | None:
    if method == "POST" and path == "/api/rag/vuln/sync":
        return _rag_vuln_sync(app, body)
    if method == "POST" and path == "/api/rag/vuln/search":
        payload = app._parse_json_body(body)
        query_text = str(payload.get("query") or "vulnerability remediation detection affected package").strip()
        try:
            return app._json_response(
                app.runtime.rag_vuln_search(
                    query_text,
                    limit=app._optional_int(payload, "limit") or 8,
                    filters=app._rag_filters_payload(payload),
                )
            )
        except ValueError as exc:
            return app._json_response({"ok": False, "error": str(exc)}, status=400)
    if method == "POST" and path == "/api/rag/vuln/hints":
        payload = app._parse_json_body(body)
        try:
            return app._json_response(
                app.runtime.rag_vuln_hints(
                    str(payload.get("query") or ""),
                    limit=app._optional_int(payload, "limit") or 8,
                    filters=app._rag_filters_payload(payload),
                )
            )
        except ValueError as exc:
            return app._json_response({"ok": False, "error": str(exc)}, status=400)
    return None


def _rag_vuln_sync(app: Any, body: bytes) -> Any:
    payload = app._parse_json_body(body)
    try:
        return app._run_tracked_action(
            "Sync CVE/Vuln RAG",
            "rag-vuln-sync",
            lambda: app.runtime.rag_vuln_sync(
                since_year=app._optional_int(payload, "since_year") or 2020,
                embed_all=bool(payload.get("embed_all", True)),
                sources=app._payload_list(payload, "source") or app._payload_list(payload, "sources"),
                timeout_seconds=float(payload.get("timeout_seconds") or payload.get("timeout") or 45.0),
                rate_limit_seconds=_optional_float(payload, "rate_limit_seconds"),
                max_nvd_pages=app._optional_int(payload, "max_nvd_pages"),
                max_enrichment_cves=app._optional_int(payload, "max_enrichment_cves") or 250,
                skip_import=bool(payload.get("skip_import", False)),
                force=bool(payload.get("force", False)),
                reembed=bool(payload.get("reembed", False)),
                skip_embeddings=bool(payload.get("skip_embeddings", False)),
                limit=app._optional_int(payload, "limit"),
            ),
            use_runtime_lock=False,
        )
    except (TypeError, ValueError) as exc:
        return app._json_response({"ok": False, "error": str(exc)}, status=400)


def _rag_inspection_routes(app: Any, method: str, path: str, query: dict[str, list[str]], body: bytes) -> Any | None:
    if method == "GET" and path.startswith("/api/inspect/group/"):
        group_id = unquote(path.rsplit("/", 1)[-1])
        try:
            return app._json_response(app._inspect_group_payload(group_id))
        except ValueError as exc:
            return app._json_response({"ok": False, "error": str(exc)}, status=404)
    if method == "GET" and path.startswith("/api/inspect/"):
        return _inspect_object_route(app, path)
    if method == "GET" and path.startswith("/api/rag/chunks/"):
        chunk_id = unquote(path.rsplit("/", 1)[-1])
        try:
            return app._json_response(app._rag_chunk_api_payload(app.runtime.rag_chunk_inspect(chunk_id)))
        except ValueError as exc:
            return app._json_response({"ok": False, "error": str(exc)}, status=404)
    if method == "GET" and path.startswith("/api/rag/sources/"):
        doc_id = unquote(path.rsplit("/", 1)[-1])
        try:
            return app._json_response(app.runtime.rag_source_profile(doc_id, limit=app._int_param(query, "limit", 50)))
        except ValueError as exc:
            return app._json_response({"ok": False, "error": str(exc)}, status=404)
    return None


def _inspect_object_route(app: Any, path: str) -> Any:
    parts = path[len("/api/inspect/"):].split("/", 1)
    if len(parts) != 2:
        return app._json_response({"ok": False, "error": "inspect kind and id are required"}, status=400)
    kind, object_id = (unquote(parts[0]), unquote(parts[1]))
    try:
        return app._json_response(app.runtime.inspect_object(kind, object_id))
    except ValueError as exc:
        return app._json_response({"ok": False, "error": str(exc)}, status=404)


def _rag_import_search_routes(app: Any, method: str, path: str, query: dict[str, list[str]], body: bytes) -> Any | None:
    if method == "POST" and path == "/api/rag/import":
        return _rag_import_route(app, body)
    if method == "POST" and path == "/api/rag/search":
        payload = app._parse_json_body(body)
        query_text = str(payload.get("query") or "").strip()
        if not query_text:
            return app._json_response({"ok": False, "error": "query is required"}, status=400)
        return _rag_search_response(app, payload, query_text)
    if method == "POST" and path == "/api/rag/hints":
        payload = app._parse_json_body(body)
        target = str(payload.get("target") or "").strip()
        if not target:
            return app._json_response({"ok": False, "error": "target is required"}, status=400)
        try:
            return app._json_response(
                app.runtime.rag_hints(str(payload.get("query") or ""), target=target, limit=app._optional_int(payload, "limit") or 8)
            )
        except ValueError as exc:
            return app._json_response({"ok": False, "error": str(exc)}, status=400)
    return None


def _rag_import_route(app: Any, body: bytes) -> Any:
    payload = app._parse_json_body(body)
    try:
        return app._run_tracked_action(
            "Import RAG corpus",
            "rag-import",
            lambda: app.runtime.rag_import_chunks(
                app._optional_string(payload, "chunks_dir"),
                dry_run=bool(payload.get("dry_run", False)),
                force=bool(payload.get("force", False)),
                reembed=bool(payload.get("reembed", False)),
                skip_embeddings=bool(payload.get("skip_embeddings", False)),
                domains=app._payload_list(payload, "domain"),
                source_files=app._payload_list(payload, "source_file"),
                doc_ids=app._payload_list(payload, "doc_id"),
                limit=app._optional_int(payload, "limit"),
            ),
            use_runtime_lock=False,
        )
    except (TypeError, ValueError) as exc:
        return app._json_response({"ok": False, "error": str(exc)}, status=400)


def _rag_search_response(app: Any, payload: dict[str, Any], query_text: str) -> Any:
    try:
        return app._json_response(
            app.runtime.rag_search(
                query_text,
                target=app._optional_string(payload, "target"),
                limit=app._optional_int(payload, "limit") or 5,
                corpus_types=app._payload_list(payload, "corpus_types") or app._payload_list(payload, "corpus_type"),
                filters=app._rag_filters_payload(payload),
            )
        )
    except ValueError as exc:
        return app._json_response({"ok": False, "error": str(exc)}, status=400)


def _rag_synthesis_routes(app: Any, method: str, path: str, query: dict[str, list[str]], body: bytes) -> Any | None:
    if method == "POST" and path == "/api/rag/synthesize":
        return _rag_synthesize_route(app, body)
    if method == "POST" and path == "/api/rag/eval":
        return _rag_eval_route(app, body)
    return None


def _rag_synthesize_route(app: Any, body: bytes) -> Any:
    payload = app._parse_json_body(body)
    query_text = str(payload.get("query") or "").strip()
    if not query_text:
        return app._json_response({"ok": False, "error": "query is required"}, status=400)
    retrieved_chunks = payload.get("retrieved_chunks")
    if retrieved_chunks is not None and not isinstance(retrieved_chunks, list):
        return app._json_response({"ok": False, "error": "retrieved_chunks must be a list"}, status=400)
    safety_context = payload.get("safety_context")
    if safety_context is not None and not isinstance(safety_context, dict):
        return app._json_response({"ok": False, "error": "safety_context must be an object"}, status=400)
    mode = str(payload.get("mode") or "grounded_answer")
    if retrieved_chunks is None and is_operational_context_purpose(mode):
        return _synthesize_response(app, query_text, mode=mode, retrieved_chunks=None, safety_context=safety_context or {})
    if retrieved_chunks is None:
        search = _rag_search_payload(app, payload, query_text)
        if "error" in search:
            return app._json_response({"ok": False, "error": search["error"]}, status=400)
        retrieved_chunks = search.get("results", []) if isinstance(search.get("results"), list) else []
    clean_chunks = [item for item in retrieved_chunks if isinstance(item, dict)]
    return _synthesize_response(app, query_text, mode=mode, retrieved_chunks=clean_chunks, safety_context=safety_context or {})


def _rag_search_payload(app: Any, payload: dict[str, Any], query_text: str) -> dict[str, Any]:
    try:
        return app.runtime.rag_search(
            query_text,
            target=app._optional_string(payload, "target"),
            limit=app._optional_int(payload, "limit") or 5,
            corpus_types=app._payload_list(payload, "corpus_types") or app._payload_list(payload, "corpus_type"),
            filters=app._rag_filters_payload(payload),
        )
    except ValueError as exc:
        return {"error": str(exc)}


def _synthesize_response(app: Any, query_text: str, *, mode: str, retrieved_chunks: Any, safety_context: dict[str, Any]) -> Any:
    result = app.runtime.synthesize_rag_answer(
        query_text,
        mode=mode,
        retrieved_chunks=retrieved_chunks,
        safety_context=safety_context,
    )
    return app._json_response(result, status=200 if result.get("status") != "provider_error" else 502)


def _rag_eval_route(app: Any, body: bytes) -> Any:
    payload = app._parse_json_body(body)
    queries = payload.get("queries")
    if isinstance(queries, str):
        query_list = [line.strip() for line in queries.splitlines() if line.strip()]
    elif isinstance(queries, list):
        query_list = [str(item).strip() for item in queries if str(item).strip()]
    else:
        return app._json_response({"ok": False, "error": "queries must be a list or newline-delimited string"}, status=400)
    try:
        return app._json_response(
            app.runtime.rag_eval_probes(
                query_list,
                target=app._optional_string(payload, "target"),
                limit=app._optional_int(payload, "limit") or 5,
                corpus_types=app._payload_list(payload, "corpus_types") or app._payload_list(payload, "corpus_type"),
                filters=app._rag_filters_payload(payload),
            )
        )
    except ValueError as exc:
        return app._json_response({"ok": False, "error": str(exc)}, status=400)


def _optional_float(payload: dict[str, Any], key: str) -> float | None:
    if payload.get(key) in {None, ""}:
        return None
    return float(payload[key])
