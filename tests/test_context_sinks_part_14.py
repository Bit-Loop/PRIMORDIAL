from __future__ import annotations

from tests.test_context_sinks_common import *


class ContextSinkValidatorTestsPart14(ContextSinkValidatorTestsBase):
    def test_evidence_sink_rejects_non_evidence_citation_support(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="evidence:model-backed",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                purpose="evidence_review",
                sink="evidence",
                content="Model summary support must not become observed evidence.",
                citations=["model:summary"],
            ),
            ContextEnvelope(
                ref="evidence:github-backed",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                purpose="evidence_review",
                sink="evidence",
                content="GitHub issue support must not become observed evidence.",
                citations=["github:issue-1"],
            ),
            ContextEnvelope(
                ref="evidence:notion-backed",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                purpose="evidence_review",
                sink="evidence",
                content="Notion note support must not become observed evidence.",
                citations=["notion:note-1"],
            ),
            ContextEnvelope(
                ref="evidence:ctfd-backed",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                purpose="evidence_review",
                sink="evidence",
                content="CTFd challenge prose support must not become observed evidence.",
                citations=["ctfd:challenge-1"],
            ),
            ContextEnvelope(
                ref="evidence:chat-backed",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                purpose="evidence_review",
                sink="evidence",
                content="Chat support must not become observed evidence.",
                citations=["chat:operator-context"],
            ),
            ContextEnvelope(
                ref="evidence:self-backed",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                purpose="evidence_review",
                sink="evidence",
                content="Evidence-supported evidence remains acceptable.",
                citations=["evidence:self-backed"],
            ),
        ]

        result = ContextSinkValidator().validate("evidence", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["evidence:self-backed"])
        self.assertEqual(
            result.rejected_refs,
            [
                "evidence:chat-backed",
                "evidence:ctfd-backed",
                "evidence:github-backed",
                "evidence:model-backed",
                "evidence:notion-backed",
            ],
        )
        self.assertTrue(any("non-evidence citation support" in error for error in result.errors))

    def test_evidence_sink_resolves_human_readable_known_evidence_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="evidence:service-summary",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            purpose="evidence_review",
            sink="evidence",
            content="Evidence records may cite prior observed evidence records by canonical ref.",
            citations=["evidence:http-banner"],
        )

        result = ContextSinkValidator().validate(
            "evidence",
            [envelope],
            known_evidence_refs={"Evidence:http-banner"},
        )

        self.assertTrue(result.valid)
        self.assertEqual(result.accepted_refs, ["evidence:service-summary"])
        self.assertEqual(result.rejected_refs, [])

    def test_task_metadata_sink_rejects_profile_label_as_executable_permission(self) -> None:
        envelope = ContextEnvelope(
            ref="task:credential-validation",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            purpose="task_generation",
            sink="task_metadata",
            content="Validate captured credentials because the profile is hack_the_box.",
            citations=["policy_decision:profile-label", "evidence:credential-artifact"],
            metadata={
                "active_intent": "recon_only",
                "engagement_profile": "hack_the_box",
                "action_class": "credential_validation",
                "creates_executable_task": True,
                "permission_source": "profile_label",
                "supporting_evidence_refs": ["evidence:credential-artifact"],
            },
        )

        result = ContextSinkValidator().validate("task_metadata", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.rejected_refs, ["task:credential-validation"])
        self.assertTrue(any("profile label" in error for error in result.errors))

    def test_task_metadata_sink_rejects_nested_executable_action_under_recon_only(self) -> None:
        envelope = ContextEnvelope(
            ref="task:nested-recon-only-exploit",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Executable action metadata must not be hidden from recon-only task gates.",
            citations=["policy_decision:recon-only", "evidence:service-banner"],
            metadata={
                "metadata": {
                    "active_intent": "recon_only",
                    "action_class": "exploit_execution",
                    "current_target_id": "target-a",
                    "current_active_generation_id": "generation:2",
                    "supporting_evidence_refs": ["evidence:service-banner"],
                },
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
        self.assertEqual(result.rejected_refs, ["task:nested-recon-only-exploit"])
        self.assertTrue(any("exploit_execution under recon_only" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_executable_action_under_recon_only(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-recon-only-exploit",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level action metadata must not mask a nested exploit action under recon-only intent.",
            citations=["policy_decision:recon-only", "evidence:service-banner"],
            metadata={
                "active_intent": "recon_only",
                "action_class": "tool_execution",
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:service-banner"],
                "metadata": {"action_class": "exploit_execution"},
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
        self.assertEqual(result.rejected_refs, ["task:masked-nested-recon-only-exploit"])
        self.assertTrue(any("exploit_execution under recon_only" in error for error in result.errors))

    def test_task_metadata_sink_rejects_plural_nested_executable_actions_under_recon_only(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-recon-only-action-classes",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level action metadata must not mask nested plural exploit actions under recon-only intent.",
            citations=["policy_decision:recon-only", "evidence:service-banner"],
            metadata={
                "active_intent": "recon_only",
                "action_class": "tool_execution",
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:service-banner"],
                "metadata": {"action_classes": ["exploit_execution"]},
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
        self.assertEqual(result.rejected_refs, ["task:masked-nested-recon-only-action-classes"])
        self.assertTrue(any("exploit_execution under recon_only" in error for error in result.errors))

__all__ = ["ContextSinkValidatorTestsPart14"]
