from __future__ import annotations

from primordial.core.storage.runtime_common import *


class RuntimeRowMappersExtendedMixin:
    def _artifact_from_row(self, row: Any) -> ArtifactRecord:
        return ArtifactRecord(
            id=row["id"],
            task_id=row["task_id"],
            target_id=row["target_id"],
            kind=ArtifactKind(row["kind"]),
            path=row["path"],
            sha256=row["sha256"],
            size_bytes=int(row["size_bytes"]),
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
        )

    def _document_chunk_from_row(self, row: Any) -> DocumentChunk:
        return DocumentChunk(
            id=row["id"],
            target_id=row["target_id"],
            source_artifact_id=row["source_artifact_id"],
            source_sha256=row["source_sha256"],
            chunk_index=int(row["chunk_index"]),
            title=row["title"],
            text=row["text"],
            token_count=int(row["token_count"]),
            evidence_refs=_load(row["evidence_refs"], []),
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
        )

    def _record_embedding_from_row(self, row: Any) -> RecordEmbedding:
        return RecordEmbedding(
            id=row["id"],
            target_id=row["target_id"],
            record_type=row["record_type"],
            record_id=row["record_id"],
            embedding_model=row["embedding_model"],
            embedding_dim=int(row["embedding_dim"]),
            embedding=self._embedding_from_value(row["embedding"]),
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
        )

    def _embedding_from_value(self, value: Any) -> list[float]:
        if isinstance(value, list | tuple):
            return [float(item) for item in value]
        text = str(value).strip()
        if text.startswith("[") and text.endswith("]"):
            body = text[1:-1].strip()
            if not body:
                return []
            return [float(item.strip()) for item in body.split(",")]
        return []

    def _notification_from_row(self, row: Any) -> NotificationRecord:
        return NotificationRecord(
            id=row["id"],
            channel=NotificationChannel(row["channel"]),
            event_type=row["event_type"],
            summary=row["summary"],
            target_id=row["target_id"],
            task_id=row["task_id"],
            finding_id=row["finding_id"],
            status=NotificationStatus(row["status"]),
            urgency=row["urgency"],
            dedupe_key=row["dedupe_key"],
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _sync_job_from_row(self, row: Any) -> ExternalSyncJob:
        return ExternalSyncJob(
            id=row["id"],
            kind=ExternalSyncKind(row["kind"]),
            target_id=row["target_id"],
            summary=row["summary"],
            payload=_load(row["payload"], {}),
            status=ExternalSyncStatus(row["status"]),
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
            last_error=row["last_error"],
        )

    def _notion_page_from_row(self, row: Any) -> NotionPage:
        return NotionPage(
            id=row["id"],
            target_id=row["target_id"],
            page_type=row["page_type"],
            title=row["title"],
            external_id=row["external_id"],
            status=row["status"],
            url=row["url"],
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _discord_delivery_from_row(self, row: Any) -> DiscordDelivery:
        return DiscordDelivery(
            id=row["id"],
            notification_id=row["notification_id"],
            status=NotificationStatus(row["status"]),
            external_ref=row["external_ref"],
            attempts=int(row["attempts"]),
            last_error=row["last_error"],
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _checkpoint_from_row(self, row: Any) -> CheckpointRecord:
        return CheckpointRecord(
            id=row["id"],
            task_id=row["task_id"],
            run_id=row["run_id"],
            kind=CheckpointKind(row["kind"]),
            path=row["path"],
            summary=row["summary"],
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
        )

    def _trace_from_row(self, row: Any) -> AgentTrace:
        return AgentTrace(
            id=row["id"],
            task_id=row["task_id"],
            role=AgentRole(row["role"]),
            status=row["status"],
            summary=row["summary"],
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
        )

    def _attempt_trajectory_from_row(self, row: Any) -> AttemptTrajectory:
        return AttemptTrajectory(
            id=row["id"],
            attempt_id=row["attempt_id"],
            target_id=row["target_id"],
            task_id=row["task_id"],
            challenge_id=row["challenge_id"],
            repo_relpath_sha=row["repo_relpath_sha"],
            step_index=int(row["step_index"]),
            kind=row["kind"],
            role=row["role"],
            payload_json=_load(row["payload_json"], {}),
            evidence_refs=_load(row["evidence_refs"], []),
            redacted=bool(row["redacted"]),
            created_at=parse_datetime(row["created_at"]),
        )

    def _event_from_row(self, row: Any) -> EventRecord:
        return EventRecord(
            id=row["id"],
            type=EventType(row["event_type"]),
            summary=row["summary"],
            target_id=row["target_id"],
            task_id=row["task_id"],
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
        )

    def _operator_message_from_row(self, row: Any) -> OperatorMessage:
        return OperatorMessage(
            id=row["id"],
            role=row["role"],
            target_id=row["target_id"],
            model=row["model"],
            body=row["body"],
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
        )
