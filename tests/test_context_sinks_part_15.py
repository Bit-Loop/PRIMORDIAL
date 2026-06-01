from __future__ import annotations

from tests.test_context_sinks_common import *


class ContextSinkValidatorTestsPart15(ContextSinkValidatorTestsBase):
    def test_task_metadata_sink_rejects_plural_nested_recon_only_intents_for_executable_action(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-recon-only-intents-exploit",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level assisted intent must not mask nested plural recon-only task intent.",
            citations=["policy_decision:recon-only", "evidence:service-banner"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "exploit_execution",
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:service-banner"],
                "metadata": {"active_intents": ["recon_only"]},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:service-banner"},
            known_policy_decision_refs={"policy_decision:recon-only"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-recon-only-intents-exploit"])
        self.assertTrue(any("exploit_execution under recon_only" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_unresolved_supporting_evidence(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-unresolved-supporting-evidence",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level supporting evidence must not mask a nested fabricated evidence ref.",
            citations=["policy_decision:assisted-lab", "evidence:service-banner"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:service-banner"],
                "metadata": {"supporting_evidence_refs": ["evidence:made-up"]},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:service-banner"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-unresolved-supporting-evidence"])
        self.assertTrue(any("unresolved supporting evidence refs" in error for error in result.errors))
        self.assertTrue(any("evidence:made-up" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_singular_unresolved_supporting_evidence(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-singular-unresolved-supporting-evidence",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level supporting evidence must not mask a nested singular fabricated evidence ref.",
            citations=["policy_decision:assisted-lab", "evidence:service-banner"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:service-banner"],
                "metadata": {"supporting_evidence_ref": "evidence:made-up"},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:service-banner"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-singular-unresolved-supporting-evidence"])
        self.assertTrue(any("unresolved supporting evidence refs" in error for error in result.errors))
        self.assertTrue(any("evidence:made-up" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_out_of_scope_task(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-out-of-scope",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level scope metadata must not mask a nested out-of-scope executable task.",
            citations=["policy_decision:assisted-lab", "evidence:service-banner"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:service-banner"],
                "in_scope": True,
                "metadata": {"in_scope": False},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:service-banner"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-out-of-scope"])
        self.assertTrue(any("out-of-scope executable task" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_plural_falsey_scope(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-plural-falsey-scope",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level scope metadata must not mask nested plural falsey in-scope values.",
            citations=["policy_decision:assisted-lab", "evidence:service-banner"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:service-banner"],
                "in_scope": True,
                "metadata": {"in_scopes": [False]},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:service-banner"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-plural-falsey-scope"])
        self.assertTrue(any("out-of-scope executable task" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_plural_scope_status(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-plural-scope-status",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level scope metadata must not mask nested plural out-of-scope statuses.",
            citations=["policy_decision:assisted-lab", "evidence:service-banner"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:service-banner"],
                "in_scope": True,
                "metadata": {"scope_statuses": ["out_of_scope"]},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:service-banner"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-plural-scope-status"])
        self.assertTrue(any("out-of-scope executable task" in error for error in result.errors))

    def test_task_metadata_sink_rejects_writeup_derived_executable_authority(self) -> None:
        envelope = ContextEnvelope(
            ref="task:writeup-exploit-step",
            kind="candidate_task",
            authority="asserted",
            source_type="writeup",
            target_id="target-a",
            purpose="task_generation",
            sink="task_metadata",
            content="Run the exploit step because the writeup says it is the path forward.",
            citations=["policy_decision:assisted-lab", "evidence:observed-service"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "exploit_validation",
                "creates_executable_task": True,
                "permission_basis": "writeup",
                "supporting_evidence_refs": ["evidence:observed-service"],
            },
        )

        result = ContextSinkValidator().validate("task_metadata", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.rejected_refs, ["task:writeup-exploit-step"])
        self.assertTrue(any("writeup-derived action authority" in error for error in result.errors))

__all__ = ["ContextSinkValidatorTestsPart15"]
