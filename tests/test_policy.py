from __future__ import annotations

import unittest

from primordial.config import AppConfig, AutonomySettings
from primordial.core.domain.enums import (
    AgentRole,
    AutonomyMode,
    MethodologyPhase,
    PolicyVerdict,
    ProviderRoute,
    RiskTier,
    ScopeProfile,
    TaskKind,
)
from primordial.core.domain.models import Target, Task
from primordial.core.orchestration.policy import PolicyEngine


class PolicyEngineTests(unittest.TestCase):
    def test_exploitation_requires_approval_in_assisted_mode(self) -> None:
        engine = PolicyEngine(
            AutonomySettings(
                mode=AutonomyMode.ASSISTED,
                allow_remote_premium=True,
                require_human_for_high_risk=True,
            )
        )
        target = Target(handle="policy-target.test", display_name="App", profile=ScopeProfile.HACKERONE)
        task = Task(
            target_id=target.id,
            phase=MethodologyPhase.EXPLOITATION,
            kind=TaskKind.VERIFY_HYPOTHESIS,
            title="Verify auth bug",
            summary="Bounded verification",
            role=AgentRole.EXPLOITATION_WORKER,
            risk_tier=RiskTier.HIGH,
        )
        task.provider_route = ProviderRoute.LOCAL_DEEP

        decision = engine.evaluate_task(task, target)

        self.assertEqual(decision.verdict, PolicyVerdict.NEEDS_APPROVAL)

    def test_remote_premium_can_be_denied(self) -> None:
        engine = PolicyEngine(
            AutonomySettings(
                mode=AutonomyMode.SUPERVISED,
                allow_remote_premium=False,
                require_human_for_high_risk=True,
            )
        )
        target = Target(handle="policy-target.test", display_name="App", profile=ScopeProfile.HACKERONE)
        task = Task(
            target_id=target.id,
            phase=MethodologyPhase.ANALYSIS,
            kind=TaskKind.REVIEW_PREMIUM_ESCALATION,
            title="Premium review",
            summary="Escalation",
            role=AgentRole.CLAUDE_REVIEWER,
        )
        task.provider_route = ProviderRoute.REMOTE_PREMIUM

        decision = engine.evaluate_task(task, target)

        self.assertEqual(decision.verdict, PolicyVerdict.DENY)

    def test_exploitation_still_requires_gate_when_exploit_actions_are_enabled(self) -> None:
        engine = PolicyEngine(
            AutonomySettings(
                mode=AutonomyMode.SUPERVISED_AUTO,
                allow_exploitative_actions=True,
            )
        )
        target = Target(handle="pirate.htb", display_name="Pirate", profile=ScopeProfile.HACK_THE_BOX)
        task = Task(
            target_id=target.id,
            phase=MethodologyPhase.EXPLOITATION,
            kind=TaskKind.VERIFY_HYPOTHESIS,
            title="Run bounded PoC",
            summary="Execute a version-matched proof of concept.",
            role=AgentRole.EXPLOITATION_WORKER,
            risk_tier=RiskTier.HIGH,
        )

        decision = engine.evaluate_task(task, target)

        self.assertEqual(decision.verdict, PolicyVerdict.NEEDS_APPROVAL)
        self.assertIn("missing agent safety approval", decision.reason)

    def test_htb_poc_task_can_use_agent_safety_review_when_enabled(self) -> None:
        engine = PolicyEngine(
            AutonomySettings(
                mode=AutonomyMode.SUPERVISED_AUTO,
                allow_exploitative_actions=True,
            )
        )
        target = Target(handle="pirate.htb", display_name="Pirate", profile=ScopeProfile.HACK_THE_BOX)
        task = Task(
            target_id=target.id,
            phase=MethodologyPhase.EXPLOITATION,
            kind=TaskKind.VERIFY_HYPOTHESIS,
            title="Run bounded PoC",
            summary="Execute a version-matched proof of concept.",
            role=AgentRole.EXPLOITATION_WORKER,
            evidence_refs=["ev-1"],
            risk_tier=RiskTier.HIGH,
            metadata={
                "agent_safety_approval": {
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
            },
        )

        decision = engine.evaluate_task(task, target)

        self.assertEqual(decision.verdict, PolicyVerdict.ALLOW)
        self.assertEqual(decision.metadata["approval_source"], "behavior_verifier")


if __name__ == "__main__":
    unittest.main()
