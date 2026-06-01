from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from primordial.core.domain.enums import MethodologyName, MethodologyPhase, ScopeProfile, SessionStatus
from primordial.core.domain.model_utils import json_ready, new_id, utc_now


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
