from __future__ import annotations

from tests.test_policy_common import *


class PolicyEngineTestsPart1(PolicyEngineTestsBase):
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

    def test_local_chat_wrapper_remote_premium_is_not_blocked_by_remote_flag_or_budget(self) -> None:
        def fail_loader() -> float:
            raise RuntimeError("ledger should not gate local wrapper usage")

        engine = PolicyEngine(
            AutonomySettings(
                mode=AutonomyMode.SUPERVISED,
                allow_remote_premium=False,
                daily_remote_budget=0.0,
            ),
            daily_remote_cost_loader=fail_loader,
        )
        target = Target(handle="policy-target.test", display_name="App", profile=ScopeProfile.HACKERONE)
        task = Task(
            target_id=target.id,
            phase=MethodologyPhase.ANALYSIS,
            kind=TaskKind.REVIEW_PREMIUM_ESCALATION,
            title="Premium review",
            summary="Escalation through the local chat wrapper",
            role=AgentRole.CLAUDE_REVIEWER,
            metadata={
                "local_chat_wrapper": "agent_chat_api",
                "remote_premium_local_wrapper": True,
                "estimated_remote_cost_usd": 50.0,
            },
        )
        task.provider_route = ProviderRoute.REMOTE_PREMIUM

        decision = engine.evaluate_task(task, target)

        self.assertEqual(decision.verdict, PolicyVerdict.ALLOW)

    def test_remote_premium_budget_accounts_for_estimated_task_cost(self) -> None:
        engine = PolicyEngine(
            AutonomySettings(
                mode=AutonomyMode.SUPERVISED,
                allow_remote_premium=True,
                daily_remote_budget=1.0,
            ),
            daily_remote_cost_loader=lambda: 0.75,
        )
        target = Target(handle="policy-target.test", display_name="App", profile=ScopeProfile.HACKERONE)
        task = Task(
            target_id=target.id,
            phase=MethodologyPhase.ANALYSIS,
            kind=TaskKind.REVIEW_PREMIUM_ESCALATION,
            title="Premium review",
            summary="Escalation",
            role=AgentRole.CLAUDE_REVIEWER,
            metadata={"estimated_remote_cost_usd": 0.30},
        )
        task.provider_route = ProviderRoute.REMOTE_PREMIUM

        decision = engine.evaluate_task(task, target)

        self.assertEqual(decision.verdict, PolicyVerdict.DENY)
        self.assertEqual(decision.metadata["daily_spent_usd"], 0.75)
        self.assertEqual(decision.metadata["estimated_task_cost_usd"], 0.30)

    def test_remote_premium_budget_loader_failure_denies(self) -> None:
        def fail_loader() -> float:
            raise RuntimeError("ledger unavailable")

        engine = PolicyEngine(
            AutonomySettings(
                mode=AutonomyMode.SUPERVISED,
                allow_remote_premium=True,
                daily_remote_budget=1.0,
            ),
            daily_remote_cost_loader=fail_loader,
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
        self.assertIn("could not be read", decision.reason)

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

    def test_supervised_auto_agent_safety_review_still_needs_operator_approval(self) -> None:
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
            metadata={"agent_safety_approval": self._agent_safety_approval()},
        )

        decision = engine.evaluate_task(task, target)

        self.assertEqual(decision.verdict, PolicyVerdict.NEEDS_APPROVAL)
        self.assertTrue(decision.metadata["operator_approval_required"])

        task.metadata["operator_approved"] = True
        approved = engine.evaluate_task(task, target)

        self.assertEqual(approved.verdict, PolicyVerdict.ALLOW)
        self.assertEqual(approved.metadata["approval_source"], "behavior_verifier")

    def test_high_autonomy_can_use_agent_safety_review_when_enabled(self) -> None:
        engine = PolicyEngine(
            AutonomySettings(
                mode=AutonomyMode.HIGH_AUTONOMY,
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
            metadata={"agent_safety_approval": self._agent_safety_approval()},
        )

        decision = engine.evaluate_task(task, target)

        self.assertEqual(decision.verdict, PolicyVerdict.ALLOW)
        self.assertEqual(decision.metadata["approval_source"], "behavior_verifier")

    def test_out_of_scope_task_is_denied(self) -> None:
        engine = PolicyEngine(AutonomySettings(mode=AutonomyMode.SUPERVISED_AUTO, allow_exploitative_actions=True))
        target = Target(handle="pirate.htb", display_name="Pirate", profile=ScopeProfile.HACK_THE_BOX, in_scope=False)
        task = Task(
            target_id=target.id,
            phase=MethodologyPhase.RECON,
            kind=TaskKind.RECON_SCAN,
            title="Run recon",
            summary="Out of scope fixture.",
            role=AgentRole.RECON_WORKER,
            risk_tier=RiskTier.LOW,
        )

        decision = engine.evaluate_task(task, target)

        self.assertEqual(decision.verdict, PolicyVerdict.DENY)
        self.assertIn("out of scope", decision.reason)

    def test_high_risk_task_bounds_violation_needs_approval(self) -> None:
        engine = PolicyEngine(AutonomySettings(mode=AutonomyMode.SUPERVISED_AUTO, allow_exploitative_actions=True))
        target = Target(handle="pirate.htb", display_name="Pirate", profile=ScopeProfile.HACK_THE_BOX)
        task = Task(
            target_id=target.id,
            phase=MethodologyPhase.EXPLOITATION,
            kind=TaskKind.VERIFY_HYPOTHESIS,
            title="Run long verification",
            summary="Bounds should gate this task.",
            role=AgentRole.EXPLOITATION_WORKER,
            risk_tier=RiskTier.HIGH,
            metadata={"timeout_seconds": 300, "max_requests": 3},
        )

        decision = engine.evaluate_task(task, target)

        self.assertEqual(decision.verdict, PolicyVerdict.NEEDS_APPROVAL)
        self.assertIn("timeout ceiling", decision.reason)

__all__ = ["PolicyEngineTestsPart1"]
