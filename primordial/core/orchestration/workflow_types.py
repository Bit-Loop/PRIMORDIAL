from __future__ import annotations

from primordial.core.orchestration.workflow_deps import (
    AgentRole,
    CredentialedAccessSurface,
    PrimitiveManifest,
    Protocol,
    Task,
    TaskKind,
    dataclass,
    field,
)


class MemoryServiceProtocol(Protocol):
    def needs_compaction(self, target_id: str) -> bool: ...

    def build_context_slice(self, target_id: str, role: AgentRole): ...

    def compact_target(self, target_id: str): ...

    def apply_freshness_decay(self, target_id: str) -> None: ...


class PrimitiveResolverProtocol(Protocol):
    def resolve_primitives(self, task: Task) -> list[PrimitiveManifest]: ...


@dataclass(slots=True, frozen=True)
class PlannedTargetAction:
    kind: TaskKind
    title: str
    summary: str
    confidence: float
    phase_label: str
    subphase: str
    transition_reason: str
    prerequisite: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True, frozen=True)
class RemoteReviewAdmissionContext:
    current_evidence_ids: set[str]
    available_primitives: set[str]
    active_generation: str | None
    surface: CredentialedAccessSurface
