from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, ClassVar
from uuid import uuid4

from primordial.core.domain.enums import (
    AgentRole,
    ArtifactKind,
    CheckpointKind,
    EventType,
    EvidenceType,
    ExternalSyncKind,
    ExternalSyncStatus,
    FindingSeverity,
    HandoffStatus,
    InterestStatus,
    MemoryLayer,
    MemoryStatus,
    MethodologyName,
    MethodologyPhase,
    NotificationChannel,
    NotificationStatus,
    PolicyVerdict,
    PrimitiveRuntime,
    ProviderRoute,
    RiskTier,
    ScopeProfile,
    SessionStatus,
    SideEffectLevel,
    TaskKind,
    TaskRunStatus,
    TaskStatus,
    VerificationStatus,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:12]}"


def json_ready(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if hasattr(value, "value"):
        return value.value
    if is_dataclass(value):
        return {name: json_ready(item) for name, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): json_ready(item) for key, item in value.items()}
    if isinstance(value, list | tuple | set):
        return [json_ready(item) for item in value]
    return value


def parse_datetime(value: str | datetime | None) -> datetime:
    if not value:
        return utc_now()
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(value)


@dataclass(slots=True)
class Session:
    methodology: MethodologyName
    profile: ScopeProfile
    autonomy_mode: str
    status: SessionStatus = SessionStatus.ACTIVE
    title: str = "Primordial Session"
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("session"))
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    def as_payload(self) -> dict[str, Any]:
        return json_ready(self)


@dataclass(slots=True)
class Target:
    handle: str
    display_name: str
    profile: ScopeProfile
    in_scope: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("target"))
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    def as_payload(self) -> dict[str, Any]:
        return json_ready(self)


@dataclass(slots=True)
class TargetMethodologyState:
    phase: MethodologyPhase
    subphase: str
    completion: str
    transition_reason: str
    candidate_actions: list[dict[str, Any]] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    next_unblock_action: str | None = None
    no_progress_reason: str | None = None
    retry_budget: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    updated_at: datetime = field(default_factory=utc_now)

    def as_payload(self) -> dict[str, Any]:
        return json_ready(self)


@dataclass(slots=True)
class ScopeAsset:
    target_id: str
    asset: str
    asset_type: str
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("asset"))
    created_at: datetime = field(default_factory=utc_now)

    def as_payload(self) -> dict[str, Any]:
        return json_ready(self)


@dataclass(slots=True)
class Task:
    target_id: str | None
    phase: MethodologyPhase
    kind: TaskKind
    title: str
    summary: str
    role: AgentRole
    session_id: str | None = None
    methodology: MethodologyName = MethodologyName.WEB_APP_CORE
    required_capabilities: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    status: TaskStatus = TaskStatus.PENDING
    priority: int = 50
    risk_tier: RiskTier = RiskTier.LOW
    attempts: int = 0
    max_attempts: int = 2
    requires_approval: bool = False
    provider_route: ProviderRoute | None = None
    provider_model: str | None = None
    parent_task_id: str | None = None
    latest_run_id: str | None = None
    id: str = field(default_factory=lambda: new_id("task"))
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    def as_payload(self) -> dict[str, Any]:
        return json_ready(self)


@dataclass(slots=True)
class TaskRun:
    task_id: str
    status: TaskRunStatus
    attempt_number: int
    role: AgentRole
    provider_route: ProviderRoute
    model_name: str
    cold_path: bool = False
    heartbeat_at: datetime | None = None
    lease_expires_at: datetime | None = None
    started_at: datetime = field(default_factory=utc_now)
    finished_at: datetime | None = None
    trace_summary: str = ""
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("run"))

    def as_payload(self) -> dict[str, Any]:
        return json_ready(self)


@dataclass(slots=True)
class TaskHandoff:
    task_id: str
    source_agent: AgentRole
    destination_agent: AgentRole
    reason: str
    expected_output_type: str
    evidence_refs: list[str] = field(default_factory=list)
    hypothesis: str | None = None
    budget: str | None = None
    deadline_at: datetime | None = None
    status: HandoffStatus = HandoffStatus.OPEN
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("handoff"))
    created_at: datetime = field(default_factory=utc_now)
    consumed_at: datetime | None = None

    def as_payload(self) -> dict[str, Any]:
        return json_ready(self)


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
class PolicyDecision:
    action_kind: str
    verdict: PolicyVerdict
    reason: str
    target_id: str | None = None
    task_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("policy"))
    created_at: datetime = field(default_factory=utc_now)

    def as_payload(self) -> dict[str, Any]:
        return json_ready(self)


@dataclass(slots=True)
class PrimitiveManifest:
    name: str
    version: str
    description: str
    capability_tags: list[str]
    allowed_phases: list[MethodologyPhase]
    runtime: PrimitiveRuntime
    risk_tier: RiskTier
    side_effect_level: SideEffectLevel
    required_secrets: list[str] = field(default_factory=list)
    input_schema: dict[str, Any] = field(default_factory=dict)
    output_schema: dict[str, Any] = field(default_factory=dict)
    timeout_seconds: int = 120
    retry_policy: dict[str, Any] = field(default_factory=dict)
    evidence_adapter: str | None = None
    sandbox_profile: str | None = None
    healthcheck: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("primitive"))
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
    """Typed container for required trace fields (CLAUDE.md §Required Trace Metadata).

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

    # Required fields — any AgentTrace whose metadata dict lacks these keys will
    # trigger a warning at insert_trace.
    REQUIRED_KEYS: ClassVar[frozenset[str]] = frozenset({"model", "role_name", "task_type", "stage"})

    def as_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if not k.startswith("REQUIRED") and v is not None}


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


@dataclass(slots=True)
class RouteSelection:
    route: ProviderRoute
    model_name: str
    rationale: str
    cold_path: bool = False


@dataclass(slots=True)
class ContextSlice:
    target_id: str
    role: AgentRole
    working: list[MemoryEntry]
    episodic: list[MemoryEntry]
    semantic: list[MemoryEntry]
    recent_evidence: list[EvidenceRecord]
    recent_interests: list[Interest]
    summary: str


@dataclass(slots=True)
class EscalationPackage:
    task_id: str
    target_id: str
    mode: str
    reason: str
    expected_value: str
    cost_tier: str
    question: str
    evidence_refs: list[str]
    evidence_summaries: list[str]
    disagreement_signal: str
    expected_output_type: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_payload(self) -> dict[str, Any]:
        return json_ready(self)


@dataclass(slots=True)
class TaskExecutionResult:
    traces: list[AgentTrace] = field(default_factory=list)
    evidence: list[EvidenceRecord] = field(default_factory=list)
    notes: list[Note] = field(default_factory=list)
    interests: list[Interest] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    artifacts: list[ArtifactRecord] = field(default_factory=list)
    events: list[EventRecord] = field(default_factory=list)
    handoffs: list[TaskHandoff] = field(default_factory=list)
    notifications: list[NotificationRecord] = field(default_factory=list)
    sync_jobs: list[ExternalSyncJob] = field(default_factory=list)
    next_tasks: list[Task] = field(default_factory=list)
    escalation_package: EscalationPackage | None = None
    success: bool = True
    summary: str = ""
    error: str | None = None


@dataclass(slots=True)
class DashboardSnapshot:
    counts: dict[str, int]
    sessions: list[Session]
    targets: list[Target]
    tasks: list[Task]
    task_runs: list[TaskRun]
    notes: list[Note]
    interests: list[Interest]
    findings: list[Finding]
    notifications: list[NotificationRecord]
    sync_jobs: list[ExternalSyncJob]
    events: list[EventRecord]


@dataclass(slots=True)
class OrchestrationReport:
    created_tasks: list[Task] = field(default_factory=list)
    decisions: list[PolicyDecision] = field(default_factory=list)
    events: list[EventRecord] = field(default_factory=list)
    completed_runs: list[TaskRun] = field(default_factory=list)

    @property
    def summary(self) -> str:
        return (
            f"created_tasks={len(self.created_tasks)} "
            f"policy_decisions={len(self.decisions)} "
            f"events={len(self.events)} "
            f"completed_runs={len(self.completed_runs)}"
        )
