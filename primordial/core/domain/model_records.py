from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, ClassVar

from primordial.core.domain.enums import (
    AgentRole,
    ArtifactKind,
    CheckpointKind,
    EventType,
    EvidenceType,
    ExternalSyncKind,
    ExternalSyncStatus,
    FindingSeverity,
    InterestStatus,
    MemoryLayer,
    MemoryStatus,
    NotificationChannel,
    NotificationStatus,
    VerificationStatus,
)
from primordial.core.domain.model_utils import json_ready, new_id, utc_now


@dataclass(slots=True)
class EvidenceRecord:
    target_id: str
    type: EvidenceType
    title: str
    summary: str
    source_ref: str
    task_id: str | None = None
    verification_status: VerificationStatus = VerificationStatus.UNVERIFIED
    confidence: float = 0.5
    freshness: float = 0.5
    artifact_path: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("evidence"))
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    def as_payload(self) -> dict[str, Any]:
        return json_ready(self)


@dataclass(slots=True)
class Note:
    target_id: str
    title: str
    body: str
    task_id: str | None = None
    confidence: float = 0.5
    freshness: float = 0.5
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("note"))
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    def as_payload(self) -> dict[str, Any]:
        return json_ready(self)


@dataclass(slots=True)
class Interest:
    target_id: str
    title: str
    summary: str
    evidence_refs: list[str] = field(default_factory=list)
    status: InterestStatus = InterestStatus.OPEN
    confidence: float = 0.5
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("interest"))
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    def as_payload(self) -> dict[str, Any]:
        return json_ready(self)


@dataclass(slots=True)
class Finding:
    target_id: str
    title: str
    summary: str
    severity: FindingSeverity
    evidence_refs: list[str] = field(default_factory=list)
    confidence: float = 0.5
    verification_status: VerificationStatus = VerificationStatus.UNVERIFIED
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("finding"))
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    def as_payload(self) -> dict[str, Any]:
        return json_ready(self)


@dataclass(slots=True)
class MemoryEntry:
    target_id: str
    layer: MemoryLayer
    title: str
    summary: str
    evidence_refs: list[str] = field(default_factory=list)
    confidence: float = 0.5
    freshness: float = 0.5
    status: MemoryStatus = MemoryStatus.ACTIVE
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("memory"))
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    def as_payload(self) -> dict[str, Any]:
        return json_ready(self)


@dataclass(slots=True)
class ArtifactRecord:
    task_id: str | None
    target_id: str | None
    kind: ArtifactKind
    path: str
    sha256: str
    size_bytes: int
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("artifact"))
    created_at: datetime = field(default_factory=utc_now)

    def as_payload(self) -> dict[str, Any]:
        return json_ready(self)


@dataclass(slots=True)
class DocumentChunk:
    target_id: str
    source_artifact_id: str
    source_sha256: str
    chunk_index: int
    title: str
    text: str
    token_count: int
    evidence_refs: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("chunk"))
    created_at: datetime = field(default_factory=utc_now)

    def as_payload(self) -> dict[str, Any]:
        return json_ready(self)


@dataclass(slots=True)
class RecordEmbedding:
    record_type: str
    record_id: str
    embedding_model: str
    embedding_dim: int
    embedding: list[float]
    target_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("embed"))
    created_at: datetime = field(default_factory=utc_now)

    def as_payload(self) -> dict[str, Any]:
        return json_ready(self)


@dataclass(slots=True)
class NotificationRecord:
    channel: NotificationChannel
    event_type: str
    summary: str
    target_id: str | None = None
    task_id: str | None = None
    finding_id: str | None = None
    status: NotificationStatus = NotificationStatus.PENDING
    urgency: str = "info"
    dedupe_key: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("notify"))
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    def as_payload(self) -> dict[str, Any]:
        return json_ready(self)


@dataclass(slots=True)
class ExternalSyncJob:
    kind: ExternalSyncKind
    target_id: str
    summary: str
    payload: dict[str, Any] = field(default_factory=dict)
    status: ExternalSyncStatus = ExternalSyncStatus.PENDING
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("sync"))
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)
    last_error: str | None = None

    def as_payload(self) -> dict[str, Any]:
        return json_ready(self)


@dataclass(slots=True)
class NotionPage:
    target_id: str
    page_type: str
    title: str
    external_id: str
    status: str
    url: str
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("notion"))
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    def as_payload(self) -> dict[str, Any]:
        return json_ready(self)


@dataclass(slots=True)
class DiscordDelivery:
    notification_id: str
    status: NotificationStatus
    external_ref: str | None = None
    attempts: int = 0
    last_error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("discord"))
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    def as_payload(self) -> dict[str, Any]:
        return json_ready(self)


@dataclass(slots=True)
class CheckpointRecord:
    task_id: str | None
    run_id: str | None
    kind: CheckpointKind
    path: str
    summary: str
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("checkpoint"))
    created_at: datetime = field(default_factory=utc_now)

    def as_payload(self) -> dict[str, Any]:
        return json_ready(self)


@dataclass(slots=True)
class TraceMetadata:
    """Typed container for required trace fields (CLAUDE.md Required Trace Metadata).

    Build with as_dict() when passing to AgentTrace.metadata so callers get type-checked
    field names without having to remember raw string keys.
    """

    model: str
    role_name: str
    task_type: str
    stage: str
    passed: bool | None = None
    confidence: float | None = None
    outcome_notes: str | None = None
    failure_reason: str | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    latency_seconds: float | None = None
    retry_count: int | None = None
    evidence_quality: str | None = None
    REQUIRED_KEYS: ClassVar[frozenset[str]] = frozenset({"model", "role_name", "task_type", "stage"})

    def as_dict(self) -> dict[str, Any]:
        return {
            key: value
            for key, value in asdict(self).items()
            if not key.startswith("REQUIRED") and value is not None
        }


@dataclass(slots=True)
class AgentTrace:
    task_id: str | None
    role: AgentRole
    status: str
    summary: str
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("trace"))
    created_at: datetime = field(default_factory=utc_now)

    def as_payload(self) -> dict[str, Any]:
        return json_ready(self)


@dataclass(slots=True)
class AttemptTrajectory:
    attempt_id: str
    target_id: str
    task_id: str | None
    challenge_id: str
    repo_relpath_sha: str
    step_index: int
    kind: str
    role: str
    payload_json: dict[str, Any]
    evidence_refs: list[str] = field(default_factory=list)
    redacted: bool = True
    id: str = field(default_factory=lambda: new_id("trajectory"))
    created_at: datetime = field(default_factory=utc_now)

    def as_payload(self) -> dict[str, Any]:
        return json_ready(self)


@dataclass(slots=True)
class EventRecord:
    type: EventType
    summary: str
    target_id: str | None = None
    task_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("event"))
    created_at: datetime = field(default_factory=utc_now)

    def as_payload(self) -> dict[str, Any]:
        return json_ready(self)


@dataclass(slots=True)
class OperatorMessage:
    role: str
    body: str
    target_id: str | None = None
    model: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("opmsg"))
    created_at: datetime = field(default_factory=utc_now)

    def as_payload(self) -> dict[str, Any]:
        return json_ready(self)
