from __future__ import annotations

from tests.test_policy_common import *


class PolicyEngineTestsPart2(PolicyEngineTestsBase):
    def test_secret_bearing_primitive_needs_gate_when_credentials_are_missing(self) -> None:
        engine = PolicyEngine(
            AutonomySettings(mode=AutonomyMode.SUPERVISED_AUTO, allow_exploitative_actions=True),
            credentials_status_loader=lambda: {
                "services": {
                    "lab": {
                        "username": {"configured": False},
                        "password": {"configured": False},
                    }
                }
            },
        )
        target = Target(handle="pirate.htb", display_name="Pirate", profile=ScopeProfile.HACK_THE_BOX)
        task = Task(
            target_id=target.id,
            phase=MethodologyPhase.EXPLOITATION,
            kind=TaskKind.CREDENTIALED_ACCESS_CHECK,
            title="Verify credentialed access",
            summary="Use known credentials.",
            role=AgentRole.EXPLOITATION_WORKER,
            risk_tier=RiskTier.HIGH,
        )
        primitive = PrimitiveManifest(
            name="credentialed-access-check",
            version="1.0",
            description="Check SMB/WinRM credentials",
            capability_tags=["credentialed-access-check"],
            allowed_phases=[MethodologyPhase.EXPLOITATION],
            runtime=PrimitiveRuntime.HOST,
            risk_tier=RiskTier.HIGH,
            side_effect_level=SideEffectLevel.EXPLOITATIVE,
            required_secrets=["lab.username", "lab.password"],
        )

        decision = engine.evaluate_primitive(task, target, primitive)

        self.assertEqual(decision.verdict, PolicyVerdict.NEEDS_APPROVAL)
        self.assertIn("not configured", decision.reason)
        self.assertEqual(decision.metadata["action_policy"]["credential_usage_class"], "lab")

    def test_operator_approved_high_risk_read_only_primitive_within_cap_is_allowed(self) -> None:
        engine = PolicyEngine(AutonomySettings(mode=AutonomyMode.ASSISTED))
        target = Target(handle="helix.htb", display_name="Helix", profile=ScopeProfile.HACK_THE_BOX)
        task = Task(
            target_id=target.id,
            phase=MethodologyPhase.EXPLOITATION,
            kind=TaskKind.VERIFY_HYPOTHESIS,
            title="Verify finding candidates",
            summary="Cross-reference candidates against observed banners.",
            role=AgentRole.EXPLOITATION_WORKER,
            risk_tier=RiskTier.HIGH,
            metadata={"operator_approved": True},
        )
        primitive = PrimitiveManifest(
            name="finding-verification",
            version="0.1.0",
            description="Read-only verification planning",
            capability_tags=["finding-verification"],
            allowed_phases=[MethodologyPhase.EXPLOITATION],
            runtime=PrimitiveRuntime.HOST,
            risk_tier=RiskTier.HIGH,
            side_effect_level=SideEffectLevel.READ_ONLY,
            required_secrets=[],
            timeout_seconds=30,
        )

        decision = engine.evaluate_primitive(task, target, primitive)

        self.assertEqual(decision.verdict, PolicyVerdict.ALLOW)

    def test_operator_approval_does_not_bypass_mutating_primitive_gate(self) -> None:
        engine = PolicyEngine(AutonomySettings(mode=AutonomyMode.ASSISTED))
        target = Target(handle="helix.htb", display_name="Helix", profile=ScopeProfile.HACK_THE_BOX)
        task = Task(
            target_id=target.id,
            phase=MethodologyPhase.EXPLOITATION,
            kind=TaskKind.VERIFY_HYPOTHESIS,
            title="Verify finding candidates",
            summary="Cross-reference candidates against observed banners.",
            role=AgentRole.EXPLOITATION_WORKER,
            risk_tier=RiskTier.HIGH,
            metadata={"operator_approved": True},
        )
        primitive = PrimitiveManifest(
            name="mutating-check",
            version="0.1.0",
            description="Mutating fixture",
            capability_tags=["mutating-check"],
            allowed_phases=[MethodologyPhase.EXPLOITATION],
            runtime=PrimitiveRuntime.HOST,
            risk_tier=RiskTier.HIGH,
            side_effect_level=SideEffectLevel.MUTATING,
            required_secrets=[],
            timeout_seconds=30,
        )

        decision = engine.evaluate_primitive(task, target, primitive)

        self.assertEqual(decision.verdict, PolicyVerdict.NEEDS_APPROVAL)
        self.assertIn("mutating or exploitative primitive", decision.reason)

__all__ = ["PolicyEngineTestsPart2"]
