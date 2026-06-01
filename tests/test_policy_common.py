from __future__ import annotations

import unittest

from primordial.config import AutonomySettings

from primordial.core.domain.enums import (
    AgentRole,
    AutonomyMode,
    MethodologyPhase,
    PolicyVerdict,
    PrimitiveRuntime,
    ProviderRoute,
    RiskTier,
    SideEffectLevel,
    ScopeProfile,
    TaskKind,
)

from primordial.core.domain.models import PrimitiveManifest, Target, Task

from primordial.core.orchestration.policy import PolicyEngine

class PolicyEngineTestsBase(unittest.TestCase):
    def _agent_safety_approval(self) -> dict[str, object]:
        return {
            "reviewer_agent": "behavior_verifier",
            "approved": True,
            "scope_verified": True,
            "bounded_execution": True,
            "dos_risk": False,
            "ddos_risk": False,
            "timeout_seconds": 10,
            "max_requests": 3,
            "evidence_refs": ["ev-1"],
        }

__all__ = [name for name in globals() if not name.startswith("__")]
