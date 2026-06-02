from __future__ import annotations

import base64
import binascii
import hashlib

from primordial.adapters.caido_redaction import redact_query_string, redact_request_path, redacted_snippet


def normalize_request_summary(payload: dict[str, object] | None) -> dict[str, object]:
    payload = payload or {}
    response_payload = payload.get("response") if isinstance(payload.get("response"), dict) else {}
    query = str(payload.get("query") or "")
    path = str(payload.get("path") or "/")
    redacted_query = redact_query_string(query)
    redacted_path = redact_request_path(path, query)
    return {
        "id": str(payload.get("id") or ""),
        "method": str(payload.get("method") or ""),
        "host": str(payload.get("host") or ""),
        "port": payload.get("port"),
        "path": redacted_path,
        "query": redacted_query,
        "is_tls": bool(payload.get("isTls")),
        "length": int(payload.get("length") or 0),
        "created_at": payload.get("createdAt"),
        "source": str(payload.get("source") or ""),
        "status": int(response_payload.get("statusCode") or 0) if isinstance(response_payload, dict) else 0,
        "response_id": str(response_payload.get("id") or "") if isinstance(response_payload, dict) else "",
        "response_length": int(response_payload.get("length") or 0) if isinstance(response_payload, dict) else 0,
        "roundtrip_time_ms": int(response_payload.get("roundtripTime") or 0) if isinstance(response_payload, dict) else 0,
    }


def normalize_request_detail(payload: dict[str, object], *, snippet_chars: int) -> dict[str, object]:
    summary = normalize_request_summary(payload)
    response_payload = payload.get("response") if isinstance(payload.get("response"), dict) else {}
    request_raw = blob_to_text(payload.get("raw"))
    response_raw = blob_to_text(response_payload.get("raw") if isinstance(response_payload, dict) else None)
    request_snippet = redacted_snippet(request_raw, snippet_chars)
    response_snippet = redacted_snippet(response_raw, snippet_chars)
    summary.update(
        {
            "request_sha256": hashlib.sha256(request_raw.encode("utf-8", errors="replace")).hexdigest()
            if request_raw
            else "",
            "response_sha256": hashlib.sha256(response_raw.encode("utf-8", errors="replace")).hexdigest()
            if response_raw
            else "",
            "request_snippet": request_snippet["text"],
            "response_snippet": response_snippet["text"],
            "request_truncated": request_snippet["truncated"],
            "response_truncated": response_snippet["truncated"],
            "raw_bodies_stored": False,
        }
    )
    return summary


def normalize_replay_session(payload: dict[str, object]) -> dict[str, object]:
    active = payload.get("activeEntry") if isinstance(payload.get("activeEntry"), dict) else {}
    collection = payload.get("collection") if isinstance(payload.get("collection"), dict) else {}
    entry_ids: list[str] = []
    entries = payload.get("entries") if isinstance(payload.get("entries"), dict) else {}
    for edge in entries.get("edges", []) if isinstance(entries, dict) else []:
        node = edge.get("node") if isinstance(edge, dict) and isinstance(edge.get("node"), dict) else {}
        if node.get("id"):
            entry_ids.append(str(node["id"]))
    return {
        "id": str(payload.get("id") or ""),
        "name": str(payload.get("name") or ""),
        "active_entry_id": str(active.get("id") or ""),
        "collection_id": str(collection.get("id") or ""),
        "entry_ids": entry_ids,
    }


def connection_count(payload: dict[str, object]) -> int:
    count = payload.get("count") if isinstance(payload.get("count"), dict) else {}
    try:
        return int(count.get("value") or 0)
    except (TypeError, ValueError):
        return 0


def blob_to_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    text = str(value)
    compact = text.strip()
    if not compact:
        return ""
    try:
        decoded = base64.b64decode(compact, validate=True)
    except (ValueError, binascii.Error):
        return text
    try:
        return decoded.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        return decoded.decode("latin-1", errors="replace")
