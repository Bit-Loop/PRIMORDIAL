from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from primordial.core.domain.enums import AgentRole
from primordial.core.domain.model_records import (
    AgentTrace,
    ArtifactRecord,
    EventRecord,
    EvidenceRecord,
    ExternalSyncJob,
    Finding,
    Interest,
    MemoryEntry,
    Note,
    NotificationRecord,
)
from primordial.core.domain.model_sessions import Session, Target
from primordial.core.domain.model_tasks import PolicyDecision, Task, TaskHandoff, TaskRun
from primordial.core.domain.model_utils import json_ready


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
