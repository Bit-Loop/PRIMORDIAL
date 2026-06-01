from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from primordial.core.domain.enums import (
    AgentRole,
    HandoffStatus,
    MethodologyName,
    MethodologyPhase,
    PolicyVerdict,
    PrimitiveRuntime,
    ProviderRoute,
    RiskTier,
    SideEffectLevel,
    TaskKind,
    TaskRunStatus,
    TaskStatus,
)
from primordial.core.domain.model_utils import json_ready, new_id, utc_now


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
class RouteSelection:
    route: ProviderRoute
    model_name: str
    rationale: str
    cold_path: bool = False
