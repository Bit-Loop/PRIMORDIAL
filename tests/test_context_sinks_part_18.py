from __future__ import annotations

from tests.test_context_sinks_common import *


class ContextSinkValidatorTestsPart18(ContextSinkValidatorTestsBase):
    def test_task_metadata_sink_rejects_masked_nested_wrong_target(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-wrong-target",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level target metadata must not mask a nested wrong target marker.",
            citations=["policy_decision:assisted-lab", "evidence:target-a-service"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "creates_executable_task": True,
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:target-a-service"],
                "metadata": {"current_target_id": "target-b"},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:target-a-service"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-wrong-target"])
        self.assertTrue(any("wrong target" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_plural_current_target(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-plural-current-target",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level target metadata must not mask nested plural wrong target markers.",
            citations=["policy_decision:assisted-lab", "evidence:target-a-service"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "creates_executable_task": True,
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:target-a-service"],
                "metadata": {"current_target_ids": ["target-b"]},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:target-a-service"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-plural-current-target"])
        self.assertTrue(any("wrong target" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_task_target_binding(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-task-target-binding",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Envelope target metadata must not mask a nested conflicting task target binding.",
            citations=["policy_decision:assisted-lab", "evidence:target-a-service"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "creates_executable_task": True,
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:target-a-service"],
                "metadata": {"task_target_id": "target-b"},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:target-a-service"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-task-target-binding"])
        self.assertTrue(any("wrong target" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_plural_task_target_binding(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-plural-task-target-binding",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Envelope target metadata must not mask nested plural conflicting task target bindings.",
            citations=["policy_decision:assisted-lab", "evidence:target-a-service"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "creates_executable_task": True,
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:target-a-service"],
                "metadata": {"task_target_ids": ["target-b"]},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:target-a-service"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-plural-task-target-binding"])
        self.assertTrue(any("wrong target" in error for error in result.errors))

    def test_task_metadata_sink_rejects_context_restrictions_that_exclude_task_metadata(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="task:prompt-only-task",
                kind="candidate_task",
                authority="asserted",
                source_type="tool_output",
                target_id="target-a",
                purpose="task_generation",
                sink="task_metadata",
                content="Prompt-only task metadata must not enter the durable task metadata sink.",
                citations=["policy:manual-review"],
                valid_for=["prompt"],
                metadata={
                    "valid_for": ["prompt"],
                    "active_intent": "recon_only",
                    "action_class": "documentation",
                    "creates_executable_task": False,
                },
            ),
            ContextEnvelope(
                ref="task:task-metadata-denied",
                kind="candidate_task",
                authority="asserted",
                source_type="tool_output",
                target_id="target-a",
                purpose="task_generation",
                sink="task_metadata",
                content="Task-metadata-denied records must not enter the durable task metadata sink.",
                citations=["policy:manual-review"],
                invalid_for=["task_metadata"],
                metadata={
                    "invalid_for": ["task_metadata"],
                    "active_intent": "recon_only",
                    "action_class": "documentation",
                    "creates_executable_task": False,
                },
            ),
        ]

        result = ContextSinkValidator().validate(
            "task_metadata",
            envelopes,
            known_policy_decision_refs={"policy:manual-review"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:prompt-only-task", "task:task-metadata-denied"])
        self.assertTrue(any("valid_for excludes task_metadata" in error for error in result.errors))
        self.assertTrue(any("invalid_for excludes task_metadata" in error for error in result.errors))

    def test_notion_export_quarantines_uncited_rag_advisory(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:uncited-methodology",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            target_id="target-a",
            purpose="export",
            sink="notion_export",
            content="Advisory RAG material must preserve its rag citation in exports.",
            citations=[],
        )

        result = ContextSinkValidator().validate("notion_export", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.quarantined_refs, ["rag:uncited-methodology"])
        self.assertTrue(any("missing rag citation" in error for error in result.errors))

    def test_notion_export_quarantines_ai_output_disguised_as_operator_note(self) -> None:
        operator_note = ContextEnvelope(
            ref="note:operator-1",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            target_id="target-a",
            purpose="export",
            sink="notion_export",
            content="Human-authored operator note may be projected to Notion as a note.",
            citations=["note:operator-1"],
        )
        model_note = ContextEnvelope(
            ref="note:model-generated",
            kind="operator_note",
            authority="asserted",
            source_type="ai_output",
            target_id="target-a",
            purpose="export",
            sink="notion_export",
            content="AI output must not be projected as a human operator note.",
            citations=["note:model-generated"],
        )

        result = ContextSinkValidator().validate("notion_export", [operator_note, model_note])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["note:operator-1"])
        self.assertEqual(result.quarantined_refs, ["note:model-generated"])
        self.assertTrue(any("non_operator_note_source" in error for error in result.errors))

__all__ = ["ContextSinkValidatorTestsPart18"]
