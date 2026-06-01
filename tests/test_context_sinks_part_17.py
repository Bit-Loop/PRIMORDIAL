from __future__ import annotations

from tests.test_context_sinks_common import *


class ContextSinkValidatorTestsPart17(ContextSinkValidatorTestsBase):
    def test_task_metadata_sink_rejects_nested_vuln_intel_source_type_under_recon_only(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-vuln-intel-recon-only",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level tool output must not mask nested vuln intel task source under recon-only.",
            citations=["policy_decision:recon-block", "evidence:observed-service"],
            metadata={
                "active_intent": "recon_only",
                "action_class": "tool_execution",
                "creates_executable_task": True,
                "source_type": "tool_output",
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:observed-service"],
                "metadata": {"source_type": "vuln_intel"},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:observed-service"},
            known_policy_decision_refs={"policy_decision:recon-block"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-vuln-intel-recon-only"])
        self.assertTrue(any("vuln_intel executable action under recon_only" in error for error in result.errors))

    def test_task_metadata_sink_rejects_stale_generation_executable_task(self) -> None:
        envelope = ContextEnvelope(
            ref="task:old-generation-service-check",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:1",
            purpose="task_generation",
            sink="task_metadata",
            content="Probe a service observed only during an old active-IP generation.",
            citations=["policy_decision:assisted-lab", "evidence:old-service"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "creates_executable_task": True,
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:old-service"],
            },
        )

        result = ContextSinkValidator().validate("task_metadata", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.rejected_refs, ["task:old-generation-service-check"])
        self.assertTrue(any("stale generation" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_stale_generation(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-stale-generation",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level generation metadata must not mask a nested stale generation marker.",
            citations=["policy_decision:assisted-lab", "evidence:service-banner"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "creates_executable_task": True,
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:service-banner"],
                "metadata": {"current_active_generation_id": "generation:1"},
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
        self.assertEqual(result.rejected_refs, ["task:masked-nested-stale-generation"])
        self.assertTrue(any("stale generation" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_plural_current_generation(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-plural-current-generation",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level generation metadata must not mask nested plural stale current generations.",
            citations=["policy_decision:assisted-lab", "evidence:service-banner"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "creates_executable_task": True,
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:service-banner"],
                "metadata": {"current_active_generation_ids": ["generation:1"]},
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
        self.assertEqual(result.rejected_refs, ["task:masked-nested-plural-current-generation"])
        self.assertTrue(any("stale generation" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_task_generation_binding(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-task-generation-binding",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Envelope generation metadata must not mask a nested stale task generation binding.",
            citations=["policy_decision:assisted-lab", "evidence:service-banner"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "creates_executable_task": True,
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:service-banner"],
                "metadata": {"generation_id": "generation:1"},
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
        self.assertEqual(result.rejected_refs, ["task:masked-nested-task-generation-binding"])
        self.assertTrue(any("stale generation" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_plural_task_generation_binding(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-plural-task-generation-binding",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Envelope generation metadata must not mask nested plural stale task generation bindings.",
            citations=["policy_decision:assisted-lab", "evidence:service-banner"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "creates_executable_task": True,
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:service-banner"],
                "metadata": {"generation_ids": ["generation:1"]},
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
        self.assertEqual(result.rejected_refs, ["task:masked-nested-plural-task-generation-binding"])
        self.assertTrue(any("stale generation" in error for error in result.errors))

    def test_task_metadata_sink_rejects_wrong_target_executable_task(self) -> None:
        envelope = ContextEnvelope(
            ref="task:wrong-target-service-check",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Probe a service observed for a different current target.",
            citations=["policy_decision:assisted-lab", "evidence:target-a-service"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "creates_executable_task": True,
                "current_target_id": "target-b",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:target-a-service"],
            },
        )

        result = ContextSinkValidator().validate("task_metadata", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.rejected_refs, ["task:wrong-target-service-check"])
        self.assertTrue(any("wrong target" in error for error in result.errors))

__all__ = ["ContextSinkValidatorTestsPart17"]
