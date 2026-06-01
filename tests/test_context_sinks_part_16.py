from __future__ import annotations

from tests.test_context_sinks_common import *


class ContextSinkValidatorTestsPart16(ContextSinkValidatorTestsBase):
    def test_task_metadata_sink_rejects_masked_nested_writeup_action_authority(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-writeup-authority",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level permission basis must not mask nested writeup action authority.",
            citations=["policy_decision:assisted-lab", "evidence:observed-service"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "exploit_validation",
                "creates_executable_task": True,
                "permission_basis": "tool_output",
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:observed-service"],
                "metadata": {"permission_basis": "writeup"},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:observed-service"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-writeup-authority"])
        self.assertTrue(any("writeup-derived action authority" in error for error in result.errors))

    def test_task_metadata_sink_rejects_plural_nested_writeup_action_authorities(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-writeup-authorities",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level permission basis must not mask plural nested writeup action authority.",
            citations=["policy_decision:assisted-lab", "evidence:observed-service"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "exploit_validation",
                "creates_executable_task": True,
                "permission_basis": "tool_output",
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:observed-service"],
                "metadata": {"permission_bases": ["writeup"]},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:observed-service"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-writeup-authorities"])
        self.assertTrue(any("writeup-derived action authority" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_writeup_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-writeup-source-type",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level source type must not mask nested writeup-derived task authority.",
            citations=["policy_decision:assisted-lab", "evidence:observed-service"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "exploit_validation",
                "creates_executable_task": True,
                "source_type": "tool_output",
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:observed-service"],
                "metadata": {"source_type": "writeup"},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:observed-service"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-writeup-source-type"])
        self.assertTrue(any("writeup-derived action authority" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_ctfd_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-ctfd-source-type",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level source type must not mask nested CTFd task authority.",
            citations=["policy_decision:assisted-lab", "evidence:observed-service"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "creates_executable_task": True,
                "source_type": "tool_output",
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:observed-service"],
                "metadata": {"source_type": "ctfd"},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:observed-service"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-ctfd-source-type"])
        self.assertTrue(any("ctfd executable task authority" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_collaboration_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-collaboration-source-type",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level source type must not mask nested collaboration task authority.",
            citations=["policy_decision:assisted-lab", "evidence:observed-service"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "creates_executable_task": True,
                "source_type": "tool_output",
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:observed-service"],
                "metadata": {"source_type": "github"},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:observed-service"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-collaboration-source-type"])
        self.assertTrue(any("collaboration executable task authority" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_advisory_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-advisory-source-type",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level source type must not mask nested advisory task permission.",
            citations=["policy_decision:assisted-lab", "evidence:observed-service"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "creates_executable_task": True,
                "source_type": "tool_output",
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:observed-service"],
                "metadata": {"source_type": "ai_output"},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:observed-service"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-advisory-source-type"])
        self.assertTrue(any("advisory executable permission source" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_profile_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-profile-source-type",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level source type must not mask nested scope profile task permission.",
            citations=["policy_decision:assisted-lab", "evidence:observed-service"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "creates_executable_task": True,
                "source_type": "tool_output",
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:observed-service"],
                "metadata": {"source_type": "scope_profile"},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:observed-service"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-profile-source-type"])
        self.assertTrue(any("profile label as executable permission" in error for error in result.errors))

__all__ = ["ContextSinkValidatorTestsPart16"]
