from __future__ import annotations

from primordial.app.runtime_deps import (
    ArtifactKind,
    ArtifactRecord,
    hashlib,
    json,
    json_ready,
    Target,
    urlparse,
    utc_now,
)
from primordial.adapters.caido_redaction import redact_httpql_text

class RuntimeCaidoCaptureMixin:
    def _caido_scope_terms(self, target: Target) -> list[str]:
        terms: list[str] = []
        if target.handle:
            terms.append(target.handle)
        active_ip = str(target.metadata.get("active_ip") or "").strip()
        if active_ip:
            terms.append(active_ip)
        for asset in self.store.list_scope_assets(target.id):
            value = str(asset.asset or "").strip()
            if value:
                terms.append(value)
        seen: set[str] = set()
        deduped = []
        for item in terms:
            normalized = item.lower()
            if normalized in seen:
                continue
            seen.add(normalized)
            deduped.append(item)
        return deduped

    def _caido_host_in_scope(self, target: Target, host: str) -> bool:
        if not target.in_scope:
            return False
        selected = self._normalize_scope_host(host)
        if not selected:
            return False
        allowed = {self._normalize_scope_host(target.handle)}
        active_ip = str(target.metadata.get("active_ip") or "").strip()
        if active_ip:
            allowed.add(self._normalize_scope_host(active_ip))
        for asset in self.store.list_scope_assets(target.id):
            value = str(asset.asset or "").strip()
            if value:
                allowed.add(self._normalize_scope_host(value))
        allowed.discard("")
        return selected in allowed

    def _normalize_scope_host(self, value: str) -> str:
        raw = str(value or "").strip()
        if not raw:
            return ""
        parsed = urlparse.urlsplit(raw if "://" in raw else f"//{raw}")
        if parsed.hostname:
            return parsed.hostname.strip("[]").rstrip(".").lower()
        return raw.split("/", 1)[0].split(":", 1)[0].strip("[]").rstrip(".").lower()

    def _write_caido_capture_artifact(
        self,
        target: Target,
        request_payload: dict[str, object],
        *,
        httpql: str,
    ) -> ArtifactRecord:
        request_id = str(request_payload.get("id") or "unknown")
        stored_httpql = redact_httpql_text(httpql)
        artifact_dir = self.config.artifacts_dir / "caido" / self._safe_log_fragment(target.handle)
        artifact_dir.mkdir(parents=True, exist_ok=True)
        path = artifact_dir / f"{self._safe_log_fragment(request_id)}.json"
        payload = {
            "version": 1,
            "kind": ArtifactKind.CAIDO_CAPTURE.value,
            "target": target.as_payload(),
            "caido_request_id": request_id,
            "httpql": stored_httpql,
            "imported_at": utc_now().isoformat(),
            "raw_bodies_stored": False,
            "snippets_stored": False,
            "request": {
                "id": request_id,
                "method": request_payload.get("method") or "",
                "host": request_payload.get("host") or "",
                "port": request_payload.get("port"),
                "path": request_payload.get("path") or "",
                "status": request_payload.get("status") or 0,
                "source": request_payload.get("source") or "",
                "request_length": request_payload.get("length") or 0,
                "response_length": request_payload.get("response_length") or 0,
                "request_sha256": request_payload.get("request_sha256") or "",
                "response_sha256": request_payload.get("response_sha256") or "",
                "request_snippet_stored": False,
                "response_snippet_stored": False,
            },
        }
        path.write_text(json.dumps(json_ready(payload), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        content = path.read_bytes()
        return ArtifactRecord(
            task_id=None,
            target_id=target.id,
            kind=ArtifactKind.CAIDO_CAPTURE,
            path=str(path),
            sha256=hashlib.sha256(content).hexdigest(),
            size_bytes=len(content),
            metadata={
                "caido_request_id": request_id,
                "httpql": stored_httpql,
                "raw_bodies_stored": False,
                "snippets_stored": False,
            },
        )
