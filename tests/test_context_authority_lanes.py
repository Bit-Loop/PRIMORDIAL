from __future__ import annotations

import unittest

from primordial.core.context import ContextAssembler, ContextEnvelope


class ContextAuthorityLaneTests(unittest.TestCase):
    def test_policy_gate_keeps_authority_records_in_authority_lane(self) -> None:
        envelopes = [
            self._authority("scope:target-a", "scope", "Target A is explicitly in scope."),
            self._authority("approval:none", "approval", "No exploit approval is active."),
            self._authority("operator_intent:current", "operator_intent", "Active intent is recon_only."),
            self._authority("target_status:active", "target_status", "Target A is the active target."),
            self._authority("profile:co-htb", "engagement_profile", "Profile does not override intent."),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="policy_gate",
            role="policy_gate",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        authority_refs = [item["ref"] for item in packet["sections"]["AUTHORITATIVE_RUNTIME_STATE"]]
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}

        for envelope in envelopes:
            with self.subTest(ref=envelope.ref):
                self.assertIn(envelope.ref, authority_refs)
                self.assertNotIn(envelope.ref, omitted_refs)
        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])

    def test_policy_gate_keeps_candidate_action_but_omits_model_summaries(self) -> None:
        candidate = ContextEnvelope(
            ref="task:candidate-action",
            kind="candidate_task",
            authority="asserted",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="policy_gate",
            sink="prompt",
            content="Candidate action for PolicyEngine to decide.",
            citations=["task:candidate-action"],
        )
        summary = ContextEnvelope(
            ref="model:policy-opinion",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="policy_gate",
            sink="prompt",
            content="The model thinks the action should be allowed.",
            citations=["model:policy-opinion"],
        )

        packet = ContextAssembler().assemble(
            [candidate, summary],
            purpose="policy_gate",
            role="policy_gate",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        model_refs = [item["ref"] for item in packet["sections"]["MODEL_DERIVED"]]
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}

        self.assertEqual(model_refs, ["task:candidate-action"])
        self.assertNotIn("task:candidate-action", omitted_refs)
        self.assertEqual(omitted_refs["model:policy-opinion"], "role_forbidden")
        self.assertNotIn("model thinks", packet["rendered"].lower())

    def test_policy_gate_omits_unbound_candidate_actions(self) -> None:
        no_target = ContextEnvelope(
            ref="task:no-target",
            kind="candidate_task",
            authority="asserted",
            source_type="ai_output",
            active_generation_id="generation:2",
            purpose="policy_gate",
            sink="prompt",
            content="Targetless candidate action must not enter a policy packet.",
            citations=["task:no-target"],
        )
        no_generation = ContextEnvelope(
            ref="task:no-generation",
            kind="candidate_task",
            authority="asserted",
            source_type="ai_output",
            target_id="target-a",
            purpose="policy_gate",
            sink="prompt",
            content="Generationless candidate action must not enter a policy packet.",
            citations=["task:no-generation"],
        )

        packet = ContextAssembler().assemble(
            [no_target, no_generation],
            purpose="policy_gate",
            role="policy_gate",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}

        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        self.assertEqual(omitted_refs["task:no-target"], "missing_target_binding")
        self.assertEqual(omitted_refs["task:no-generation"], "missing_generation_binding")
        self.assertNotIn("Targetless candidate action", packet["rendered"])
        self.assertNotIn("Generationless candidate action", packet["rendered"])

    def test_policy_gate_omits_unbound_target_authority_but_keeps_global_controls(self) -> None:
        no_target_approval = ContextEnvelope(
            ref="approval:no-target",
            kind="approval",
            authority="authoritative",
            source_type="runtime_state",
            active_generation_id="generation:2",
            purpose="policy_gate",
            sink="prompt",
            content="Targetless approval must not authorize a target-bound policy decision.",
            citations=["approval:no-target"],
        )
        no_generation_scope = ContextEnvelope(
            ref="scope:no-generation",
            kind="scope",
            authority="authoritative",
            source_type="runtime_state",
            target_id="target-a",
            purpose="policy_gate",
            sink="prompt",
            content="Generationless scope must not enter a current policy packet.",
            citations=["scope:no-generation"],
        )
        global_intent = ContextEnvelope(
            ref="operator_intent:current",
            kind="operator_intent",
            authority="authoritative",
            source_type="runtime_state",
            purpose="policy_gate",
            sink="prompt",
            content="Active intent is recon_only.",
            citations=["operator_intent:current"],
        )
        global_profile = ContextEnvelope(
            ref="profile:co-htb",
            kind="engagement_profile",
            authority="authoritative",
            source_type="runtime_state",
            purpose="policy_gate",
            sink="prompt",
            content="Profile labels do not authorize exploit-like behavior.",
            citations=["profile:co-htb"],
        )

        packet = ContextAssembler().assemble(
            [no_target_approval, no_generation_scope, global_intent, global_profile],
            purpose="policy_gate",
            role="policy_gate",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        authority_refs = [item["ref"] for item in packet["sections"]["AUTHORITATIVE_RUNTIME_STATE"]]
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}

        self.assertNotIn("approval:no-target", authority_refs)
        self.assertNotIn("scope:no-generation", authority_refs)
        self.assertIn("operator_intent:current", authority_refs)
        self.assertIn("profile:co-htb", authority_refs)
        self.assertEqual(omitted_refs["approval:no-target"], "missing_target_binding")
        self.assertEqual(omitted_refs["scope:no-generation"], "missing_generation_binding")
        self.assertNotIn("Targetless approval", packet["rendered"])
        self.assertNotIn("Generationless scope", packet["rendered"])

    def test_policy_gate_omits_stale_authority_and_candidate_actions_even_when_historical_requested(self) -> None:
        stale_approval = ContextEnvelope(
            ref="approval:stale",
            kind="approval",
            authority="authoritative",
            source_type="runtime_state",
            target_id="target-a",
            active_generation_id="generation:1",
            purpose="policy_gate",
            sink="prompt",
            content="Old generation approval must not influence the current policy gate.",
            citations=["approval:stale"],
        )
        stale_candidate = ContextEnvelope(
            ref="task:stale-action",
            kind="candidate_task",
            authority="asserted",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:1",
            purpose="policy_gate",
            sink="prompt",
            content="Old generation candidate action must not be reconsidered as current.",
            citations=["task:stale-action"],
        )

        packet = ContextAssembler().assemble(
            [stale_approval, stale_candidate],
            purpose="policy_gate",
            role="policy_gate",
            target_id="target-a",
            active_generation_id="generation:2",
            include_historical=True,
        )

        authority_refs = [item["ref"] for item in packet["sections"]["AUTHORITATIVE_RUNTIME_STATE"]]
        model_refs = [item["ref"] for item in packet["sections"]["MODEL_DERIVED"]]
        historical_refs = [item["ref"] for item in packet["historical_context"]]
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}

        self.assertNotIn("approval:stale", authority_refs)
        self.assertNotIn("task:stale-action", model_refs)
        self.assertNotIn("approval:stale", historical_refs)
        self.assertNotIn("task:stale-action", historical_refs)
        self.assertEqual(omitted_refs["approval:stale"], "stale_generation")
        self.assertEqual(omitted_refs["task:stale-action"], "stale_generation")
        self.assertNotIn("Old generation approval", packet["rendered"])
        self.assertNotIn("Old generation candidate", packet["rendered"])

    def _authority(self, ref: str, kind: str, content: str) -> ContextEnvelope:
        return ContextEnvelope(
            ref=ref,
            kind=kind,
            authority="authoritative",
            source_type="runtime_state",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="policy_gate",
            sink="prompt",
            content=content,
            citations=[ref],
        )


if __name__ == "__main__":
    unittest.main()
