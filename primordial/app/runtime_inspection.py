from __future__ import annotations

from primordial.app.runtime_deps import (
    json_ready,
    Path,
    re,
)

class RuntimeInspectionMixin:
    def inspect_object(self, kind: str, object_id: str, *, limit: int = 25) -> dict[str, object]:
        normalized = self._normalize_inspect_kind(kind)
        record = self._lookup_inspect_record(normalized, object_id)
        if record is None:
            raise ValueError(f"{normalized} not found: {object_id}")
        payload = self._inspect_payload(record)
        related = self._inspect_related(normalized, payload, limit=limit)
        artifact_preview = self._inspect_artifact_preview(payload) if normalized in {"artifact", "checkpoint"} else None
        error_detail = self._inspect_error_detail(payload, related)
        return {
            "ok": True,
            "kind": normalized,
            "id": str(payload.get("id") or object_id),
            "title": self._inspect_title(normalized, payload),
            "summary": str(payload.get("summary") or payload.get("trace_summary") or payload.get("title") or ""),
            "record": payload,
            "related": related,
            "artifact_preview": artifact_preview,
            "error_detail": error_detail,
        }

    def inspect_many(self, kind: str, object_ids: list[str], *, limit: int = 25) -> dict[str, object]:
        normalized = self._normalize_inspect_kind(kind)
        members: list[dict[str, object]] = []
        failures: list[dict[str, str]] = []
        for object_id in object_ids:
            try:
                members.append(self.inspect_object(normalized, object_id, limit=limit))
            except ValueError as exc:
                failures.append({"id": object_id, "error": str(exc)})
        return {
            "ok": not failures,
            "kind": "group",
            "group_kind": normalized,
            "count": len(members),
            "members": members,
            "failures": failures,
        }

    def _normalize_inspect_kind(self, kind: str) -> str:
        value = str(kind or "").strip().lower().replace("-", "_")
        aliases = {
            "tasks": "task",
            "task_run": "run",
            "task_runs": "run",
            "taskrun": "run",
            "runs": "run",
            "agent_trace": "trace",
            "agent_traces": "trace",
            "traces": "trace",
            "events": "event",
            "evidences": "evidence",
            "artifacts": "artifact",
            "findings": "finding",
            "interests": "interest",
            "checkpoints": "checkpoint",
            "notifications": "notification",
            "external_sync": "sync_job",
            "external_sync_job": "sync_job",
            "external_sync_jobs": "sync_job",
            "sync": "sync_job",
            "sync_jobs": "sync_job",
            "handoffs": "handoff",
            "notes": "note",
            "memory_entry": "memory",
            "memory_entries": "memory",
            "document_chunk": "chunk",
            "document_chunks": "chunk",
            "rag_chunk": "chunk",
        }
        normalized = aliases.get(value, value)
        allowed = {
            "task",
            "run",
            "trace",
            "event",
            "evidence",
            "artifact",
            "finding",
            "interest",
            "checkpoint",
            "notification",
            "sync_job",
            "handoff",
            "note",
            "memory",
            "chunk",
            "target",
        }
        if normalized not in allowed:
            raise ValueError(f"unsupported inspect kind: {kind}")
        return normalized

    def _lookup_inspect_record(self, kind: str, object_id: str) -> object | None:
        if kind == "task":
            return self.store.get_task(object_id)
        if kind == "run":
            return self.store.get_task_run(object_id)
        if kind == "trace":
            return self.store.get_trace(object_id)
        if kind == "event":
            return self.store.get_event(object_id)
        if kind == "evidence":
            return self.store.get_evidence(object_id)
        if kind == "artifact":
            return self.store.get_artifact(object_id)
        if kind == "finding":
            return self.store.get_finding(object_id)
        if kind == "interest":
            return self.store.get_interest(object_id)
        if kind == "checkpoint":
            return self.store.get_checkpoint(object_id)
        if kind == "notification":
            return self.store.get_notification(object_id)
        if kind == "sync_job":
            return self.store.get_external_sync_job(object_id)
        if kind == "handoff":
            return self.store.get_handoff(object_id)
        if kind == "note":
            return self.store.get_note(object_id)
        if kind == "memory":
            return self.store.get_memory_entry(object_id)
        if kind == "chunk":
            return self.store.get_document_chunk(object_id)
        if kind == "target":
            return self.store.get_target(object_id)
        return None

    def _inspect_payload(self, record: object) -> dict[str, object]:
        if hasattr(record, "as_payload"):
            payload = record.as_payload()
            return payload if isinstance(payload, dict) else {"value": payload}
        if isinstance(record, dict):
            return json_ready(record)
        return {"value": str(record)}

    def _inspect_title(self, kind: str, payload: dict[str, object]) -> str:
        title = payload.get("title") or payload.get("summary") or payload.get("trace_summary") or payload.get("path")
        if title:
            return f"{kind}: {title}"
        return f"{kind}: {payload.get('id') or 'record'}"

    def _inspect_related(self, kind: str, payload: dict[str, object], *, limit: int) -> dict[str, object]:
        related: dict[str, object] = {}
        task_id = str(payload.get("task_id") or "")
        target_id = str(payload.get("target_id") or "")
        run_id = str(payload.get("run_id") or "")
        if kind == "task":
            task_id = str(payload.get("id") or "")
        elif kind == "run":
            task_id = str(payload.get("task_id") or "")
            run_id = str(payload.get("id") or run_id)
        if kind == "target":
            target_id = str(payload.get("id") or "")

        task = self.store.get_task(task_id) if task_id else None
        if task is not None:
            related["task"] = task.as_payload()
            target_id = target_id or str(task.target_id or "")
        target = self.store.get_target(target_id) if target_id else None
        if target is not None:
            related["target"] = target.as_payload()

        if task_id:
            runs = self.store.list_task_runs(task_id=task_id, limit=limit)
            run_ids = {run.id for run in runs}
            if run_id:
                run_ids.add(run_id)
            related["runs"] = [item.as_payload() for item in runs]
            related["traces"] = [item.as_payload() for item in self.store.list_traces(task_id=task_id, limit=limit)]
            related["handoffs"] = [item.as_payload() for item in self.store.list_handoffs(task_id=task_id, limit=limit)]
            related["artifacts"] = [item.as_payload() for item in self.store.list_artifacts(task_id=task_id, limit=limit)]
            related["checkpoints"] = [
                item.as_payload()
                for item in self.store.list_checkpoints(limit=limit * 5)
                if item.task_id == task_id or item.run_id in run_ids
            ][:limit]
            related["events"] = [
                item.as_payload()
                for item in self.store.list_events(limit=limit * 5)
                if item.task_id == task_id
            ][:limit]
            if target_id:
                related["evidence"] = [
                    item.as_payload()
                    for item in self.store.list_evidence(target_id=target_id, limit=limit * 5)
                    if item.task_id == task_id
                ][:limit]
        return related

    def _inspect_artifact_preview(self, payload: dict[str, object], *, max_bytes: int = 65536) -> dict[str, object] | None:
        raw_path = str(payload.get("path") or "")
        if not raw_path:
            return None
        path = Path(raw_path)
        try:
            resolved = path.resolve()
        except OSError as exc:
            return {"available": False, "path": raw_path, "error": str(exc)}
        allowed_roots = (self.config.artifacts_dir.resolve(), self.config.checkpoints_dir.resolve())
        if not any(root == resolved or root in resolved.parents for root in allowed_roots):
            return {"available": False, "path": raw_path, "error": "preview blocked outside runtime artifact roots"}
        if not resolved.exists() or not resolved.is_file():
            return {"available": False, "path": str(resolved), "error": "file is not present on disk"}
        data = resolved.read_bytes()[: max_bytes + 1]
        truncated = len(data) > max_bytes
        if truncated:
            data = data[:max_bytes]
        text = data.decode("utf-8", errors="replace")
        return {
            "available": True,
            "path": str(resolved),
            "size_bytes": resolved.stat().st_size,
            "truncated": truncated,
            "text": self._redact_inspector_text(text),
        }

    def _redact_inspector_text(self, text: str) -> str:
        redacted = re.sub(
            r"(?i)(api[_-]?key|token|secret|password|passwd|webhook)([\"']?\s*[:=]\s*[\"']?)([^\"'\s,}]{4,})",
            lambda match: f"{match.group(1)}{match.group(2)}[redacted]",
            text,
        )
        return re.sub(
            r"(?i)(authorization\s*:\s*bearer\s+)([A-Za-z0-9._~+/=-]{8,})",
            lambda match: f"{match.group(1)}[redacted]",
            redacted,
        )

    def _inspect_error_detail(self, payload: dict[str, object], related: dict[str, object]) -> dict[str, object]:
        messages: list[dict[str, str]] = []
        tracebacks: list[dict[str, str]] = []

        def scan(item: object, source: str) -> None:
            if not isinstance(item, dict):
                return
            metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
            for key in ("error", "last_error", "failure_reason"):
                value = item.get(key) or metadata.get(key)
                if value:
                    messages.append({"source": source, "key": key, "message": str(value)})
            for key in ("traceback", "stack", "stack_trace"):
                value = metadata.get(key) or item.get(key)
                if value:
                    tracebacks.append({"source": source, "key": key, "traceback": str(value)})
            exception_type = metadata.get("exception_type") or item.get("exception_type")
            if exception_type:
                messages.append({"source": source, "key": "exception_type", "message": str(exception_type)})

        scan(payload, "record")
        for key, value in related.items():
            if isinstance(value, dict):
                scan(value, key)
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    scan(item, f"{key}[{index}]")

        seen_messages: set[tuple[str, str, str]] = set()
        deduped_messages = []
        for item in messages:
            marker = (item["source"], item["key"], item["message"])
            if marker in seen_messages:
                continue
            seen_messages.add(marker)
            deduped_messages.append(item)
        seen_tracebacks: set[str] = set()
        deduped_tracebacks = []
        for item in tracebacks:
            text = item["traceback"]
            if text in seen_tracebacks:
                continue
            seen_tracebacks.add(text)
            deduped_tracebacks.append(item)
        return {
            "available": bool(deduped_messages or deduped_tracebacks),
            "messages": deduped_messages,
            "tracebacks": deduped_tracebacks,
            "stack_available": bool(deduped_tracebacks),
            "stack_note": "" if deduped_tracebacks else "No traceback was recorded for this object.",
        }
