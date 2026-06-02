from __future__ import annotations

from primordial.core.domain.enums import ArtifactKind, EvidenceType, EventType, VerificationStatus
from primordial.core.domain.models import ArtifactRecord, EvidenceRecord, EventRecord, Target


def selected_caido_request_ids(request_ids: list[str], *, limit: int = 50) -> list[str]:
    selected = [str(item).strip() for item in request_ids if str(item).strip()]
    if not selected:
        raise ValueError("request_ids is required")
    return selected[:limit]


def caido_request_payload(detail: dict[str, object]) -> dict[str, object]:
    request_payload = detail.get("request")
    return request_payload if isinstance(request_payload, dict) else {}


def caido_detail_error(request_id: str, detail: dict[str, object]) -> dict[str, object]:
    return {"id": request_id, "error": str(detail.get("error") or "detail fetch failed")}


def caido_scope_error(request_id: str, host: str) -> dict[str, object]:
    return {"id": request_id, "error": f"host is not in target scope: {host}"}


def caido_capture_evidence(
    *,
    target: Target,
    request_id: str,
    request_payload: dict[str, object],
    artifact: ArtifactRecord,
    httpql: str,
) -> EvidenceRecord:
    method = str(request_payload.get("method") or "HTTP").upper()
    path = str(request_payload.get("path") or "/")
    host = str(request_payload.get("host") or "")
    status = int(request_payload.get("status") or 0)
    return EvidenceRecord(
        target_id=target.id,
        type=EvidenceType.HTTP_REPLAY,
        title=f"Caido capture: {method} {path}",
        summary=f"Imported Caido request {request_id}: {method} {host}{path} returned HTTP {status or 'unknown'}.",
        source_ref=f"caido://request/{request_id}",
        verification_status=VerificationStatus.PARTIAL,
        confidence=0.75,
        freshness=0.85,
        artifact_path=artifact.path,
        metadata=_caido_capture_metadata(target, request_id, request_payload, artifact, httpql),
    )


def caido_import_row(request_id: str, evidence: EvidenceRecord, artifact: ArtifactRecord) -> dict[str, object]:
    return {"request_id": request_id, "evidence": evidence.as_payload(), "artifact": artifact.as_payload()}


def caido_import_event(target: Target, imported: list[dict[str, object]], httpql: str) -> EventRecord:
    return EventRecord(
        type=EventType.CAIDO_IMPORT,
        summary=f"Imported {len(imported)} Caido capture(s)",
        target_id=target.id,
        metadata={
            "request_ids": [item["request_id"] for item in imported],
            "httpql": httpql,
            "artifact_ids": [item["artifact"]["id"] for item in imported],
            "evidence_ids": [item["evidence"]["id"] for item in imported],
            "raw_bodies_stored": False,
            "snippets_stored": False,
        },
    )


def caido_import_response(
    *,
    target: Target,
    imported: list[dict[str, object]],
    errors: list[dict[str, object]],
    records: dict[str, object],
) -> dict[str, object]:
    return {
        "target": target.as_payload(),
        "imported": imported,
        "errors": errors,
        "records": records,
    }


def _caido_capture_metadata(
    target: Target,
    request_id: str,
    request_payload: dict[str, object],
    artifact: ArtifactRecord,
    httpql: str,
) -> dict[str, object]:
    metadata = {
        "kind": ArtifactKind.CAIDO_CAPTURE.value,
        "caido_request_id": request_id,
        "httpql": httpql,
        "method": str(request_payload.get("method") or "HTTP").upper(),
        "host": str(request_payload.get("host") or ""),
        "path": str(request_payload.get("path") or "/"),
        "status_code": int(request_payload.get("status") or 0),
        "request_length": int(request_payload.get("length") or 0),
        "response_length": int(request_payload.get("response_length") or 0),
        "request_sha256": request_payload.get("request_sha256") or "",
        "response_sha256": request_payload.get("response_sha256") or "",
        "raw_bodies_stored": False,
        "snippets_stored": False,
        "request_snippet_stored": False,
        "response_snippet_stored": False,
        "artifact_id": artifact.id,
    }
    if target.metadata.get("active_ip_generation") is not None:
        metadata["active_ip_generation"] = target.metadata["active_ip_generation"]
    if target.metadata.get("active_ip"):
        metadata["active_ip"] = target.metadata["active_ip"]
    return metadata
