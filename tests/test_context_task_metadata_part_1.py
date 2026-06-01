from __future__ import annotations

from tests.test_context_task_metadata_common import *


class ContextTaskMetadataTestsPart1(ContextTaskMetadataTestsBase):
    def test_executable_task_requires_metadata_supporting_evidence_to_be_cited(self) -> None:
        envelope = ContextEnvelope(
            ref="task:cve-validation",
            kind="candidate_task",
            authority="advisory",
            source_type="vuln_intel",
            target_id="target-a",
            purpose="task_generation",
            sink="task_metadata",
            content="Validate exploit applicability using advisory CVE context.",
            citations=["policy_decision:recon-block", "rag:cve-advisory"],
            metadata={
                "active_intent": "recon_only",
                "action_class": "exploit_validation",
                "creates_executable_task": True,
                "supporting_evidence_refs": ["evidence:observed-service"],
            },
        )

        result = ContextSinkValidator().validate("task_metadata", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:cve-validation"])
        self.assertTrue(any("supporting evidence refs" in error for error in result.errors))
        self.assertTrue(any("evidence:observed-service" in error for error in result.errors))
        self.assertTrue(any("recon_only" in error for error in result.errors))

    def test_human_readable_action_class_still_triggers_executable_task_gates(self) -> None:
        envelope = ContextEnvelope(
            ref="task:display-credential-validation",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            purpose="task_generation",
            sink="task_metadata",
            content="Validate credentials because the selected profile is Hack The Box.",
            citations=["policy_decision:profile-label", "evidence:credential-artifact"],
            metadata={
                "active_intent": "Recon only",
                "engagement_profile": "hack_the_box",
                "action_class": "Credential validation",
                "permission_source": "Profile label",
                "supporting_evidence_refs": ["evidence:credential-artifact"],
            },
        )

        result = ContextSinkValidator().validate("task_metadata", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:display-credential-validation"])
        self.assertTrue(any("profile label" in error for error in result.errors))

    def test_human_readable_metadata_keys_still_trigger_executable_task_gates(self) -> None:
        envelope = ContextEnvelope(
            ref="task:display-key-credential-validation",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            purpose="task_generation",
            sink="task_metadata",
            content="Validate credentials because the selected profile is Hack The Box.",
            citations=["policy_decision:profile-label", "evidence:credential-artifact"],
            metadata={
                "Active intent": "Recon only",
                "Engagement profile": "hack_the_box",
                "Action class": "Credential validation",
                "Permission source": "Profile label",
                "Supporting evidence refs": ["evidence:credential-artifact"],
            },
        )

        result = ContextSinkValidator().validate("task_metadata", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:display-key-credential-validation"])
        self.assertTrue(any("profile label" in error for error in result.errors))

    def test_scalar_supporting_evidence_ref_must_be_cited_for_executable_task(self) -> None:
        envelope = ContextEnvelope(
            ref="task:scalar-supporting-evidence",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            purpose="task_generation",
            sink="task_metadata",
            content="Schedule an executable task that claims supporting evidence in scalar metadata.",
            citations=["policy_decision:assisted-lab"],
            metadata={
                "Active intent": "ctf_solve_assisted",
                "Action class": "Tool execution",
                "Supporting evidence refs": "evidence:observed-service",
            },
        )

        result = ContextSinkValidator().validate("task_metadata", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:scalar-supporting-evidence"])
        self.assertTrue(any("supporting evidence refs" in error for error in result.errors))
        self.assertTrue(any("evidence:observed-service" in error for error in result.errors))

    def test_executable_task_rejects_unresolved_supporting_evidence_when_known_refs_are_supplied(self) -> None:
        envelope = ContextEnvelope(
            ref="task:fabricated-supporting-evidence",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            purpose="task_generation",
            sink="task_metadata",
            content="Schedule a tool action using a fabricated evidence citation.",
            citations=["policy_decision:assisted-lab", "evidence:made-up"],
            metadata={
                "Active intent": "ctf_solve_assisted",
                "Action class": "Tool execution",
                "Creates executable task": "true",
                "Supporting evidence refs": ["evidence:made-up"],
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
        self.assertEqual(result.rejected_refs, ["task:fabricated-supporting-evidence"])
        self.assertTrue(any("unresolved supporting evidence refs" in error for error in result.errors))
        self.assertTrue(any("evidence:made-up" in error for error in result.errors))

    def test_executable_task_resolves_human_readable_supporting_evidence_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="task:display-supporting-evidence",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Schedule a tool action using a registered evidence citation.",
            citations=["policy_decision:assisted-lab", "evidence:observed-service"],
            metadata={
                "Active intent": "ctf_solve_assisted",
                "Action class": "Tool execution",
                "Creates executable task": "true",
                "Supporting evidence refs": ["Evidence:observed-service"],
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"Evidence:observed-service"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertTrue(result.valid)
        self.assertEqual(result.accepted_refs, ["task:display-supporting-evidence"])
        self.assertEqual(result.rejected_refs, [])

    def test_executable_task_requires_active_operator_intent(self) -> None:
        envelope = ContextEnvelope(
            ref="task:missing-active-intent",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            purpose="task_generation",
            sink="task_metadata",
            content="Executable task metadata must carry the active Operator Intent boundary.",
            citations=["policy_decision:assisted-lab", "evidence:observed-service"],
            metadata={
                "Action class": "Tool execution",
                "Creates executable task": "true",
                "Supporting evidence refs": ["evidence:observed-service"],
            },
        )

        result = ContextSinkValidator().validate("task_metadata", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:missing-active-intent"])
        self.assertTrue(any("active Operator Intent" in error for error in result.errors))

    def test_executable_task_requires_target_binding(self) -> None:
        envelope = ContextEnvelope(
            ref="task:missing-target-binding",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            purpose="task_generation",
            sink="task_metadata",
            content="Executable task metadata must bind to an explicit target.",
            citations=["policy_decision:assisted-lab", "evidence:observed-service"],
            metadata={
                "Active intent": "ctf_solve_assisted",
                "Action class": "Tool execution",
                "Creates executable task": "true",
                "Supporting evidence refs": ["evidence:observed-service"],
            },
        )

        result = ContextSinkValidator().validate("task_metadata", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:missing-target-binding"])
        self.assertTrue(any("target binding" in error for error in result.errors))

    def test_executable_task_requires_active_generation_binding(self) -> None:
        envelope = ContextEnvelope(
            ref="task:missing-generation-binding",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            purpose="task_generation",
            sink="task_metadata",
            content="Executable task metadata must bind to the active target generation.",
            citations=["policy_decision:assisted-lab", "evidence:observed-service"],
            metadata={
                "Active intent": "ctf_solve_assisted",
                "Action class": "Tool execution",
                "Creates executable task": "true",
                "Supporting evidence refs": ["evidence:observed-service"],
            },
        )

        result = ContextSinkValidator().validate("task_metadata", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:missing-generation-binding"])
        self.assertTrue(any("active generation" in error for error in result.errors))

__all__ = ["ContextTaskMetadataTestsPart1"]
