from __future__ import annotations

import unittest

from primordial.core.context import ContextEnvelope, ContextSinkValidator


class ContextTaskMetadataTests(unittest.TestCase):
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
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:fabricated-supporting-evidence"])
        self.assertTrue(any("unresolved supporting evidence refs" in error for error in result.errors))
        self.assertTrue(any("evidence:made-up" in error for error in result.errors))

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

    def test_task_metadata_target_fact_requires_evidence_citation(self) -> None:
        envelope = ContextEnvelope(
            ref="task:rag-only-target-fact",
            kind="candidate_task",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Create a candidate task from a target fact supported only by advisory RAG.",
            citations=["rag:service-methodology"],
            metadata={"contains_target_fact": True},
        )

        result = ContextSinkValidator().validate("task_metadata", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:rag-only-target-fact"])
        self.assertTrue(any("requires evidence:<id>" in error for error in result.errors))

    def test_generated_export_cannot_authorize_executable_task(self) -> None:
        envelope = ContextEnvelope(
            ref="task:export-recursive-service-check",
            kind="candidate_task",
            authority="derived",
            source_type="generated_export",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="A generated export must not loop back into executable task authority.",
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
        self.assertEqual(result.rejected_refs, ["task:export-recursive-service-check"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_ctfd_cannot_authorize_executable_task(self) -> None:
        envelope = ContextEnvelope(
            ref="task:ctfd-recursive-service-check",
            kind="candidate_task",
            authority="asserted",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="CTFd challenge metadata must not authorize executable task metadata.",
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
        self.assertEqual(result.rejected_refs, ["task:ctfd-recursive-service-check"])
        self.assertTrue(any("ctfd" in error.lower() for error in result.errors))

    def test_collaboration_sources_cannot_authorize_executable_tasks(self) -> None:
        for source_type in ("github", "notion"):
            with self.subTest(source_type=source_type):
                envelope = ContextEnvelope(
                    ref=f"task:{source_type}-recursive-service-check",
                    kind="candidate_task",
                    authority="asserted",
                    source_type=source_type,
                    target_id="target-a",
                    active_generation_id="generation:2",
                    purpose="task_generation",
                    sink="task_metadata",
                    content="Collaboration material must not authorize executable task metadata.",
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
                self.assertEqual(result.rejected_refs, [f"task:{source_type}-recursive-service-check"])
                self.assertTrue(any("collaboration" in error.lower() for error in result.errors))

    def test_advisory_material_cannot_be_executable_permission_source(self) -> None:
        for permission_source in ("rag", "ai_output", "chat", "vuln_intel", "methodology_doc", "model_summary"):
            with self.subTest(permission_source=permission_source):
                envelope = ContextEnvelope(
                    ref=f"task:{permission_source}-permission-source",
                    kind="candidate_task",
                    authority="asserted",
                    source_type="tool_output",
                    target_id="target-a",
                    active_generation_id="generation:2",
                    purpose="task_generation",
                    sink="task_metadata",
                    content="Advisory material must not be recorded as executable permission authority.",
                    citations=["policy_decision:assisted-lab", "evidence:observed-service"],
                    metadata={
                        "Active intent": "ctf_solve_assisted",
                        "Action class": "Tool execution",
                        "Creates executable task": "true",
                        "Permission source": permission_source,
                        "Supporting evidence refs": ["evidence:observed-service"],
                    },
                )

                result = ContextSinkValidator().validate("task_metadata", [envelope])

                self.assertFalse(result.valid)
                self.assertEqual(result.accepted_refs, [])
                self.assertEqual(result.rejected_refs, [f"task:{permission_source}-permission-source"])
                self.assertTrue(any("advisory" in error.lower() for error in result.errors))

    def test_advisory_sources_cannot_originate_executable_task_metadata(self) -> None:
        for source_type in ("ai_output", "chat", "methodology_doc", "vuln_intel"):
            with self.subTest(source_type=source_type):
                envelope = ContextEnvelope(
                    ref=f"task:{source_type}-executable-origin",
                    kind="candidate_task",
                    authority="advisory",
                    source_type=source_type,
                    target_id="target-a",
                    active_generation_id="generation:2",
                    purpose="task_generation",
                    sink="task_metadata",
                    content="Advisory context must not originate executable task metadata authority.",
                    citations=["policy_decision:assisted-lab", "evidence:observed-service"],
                    metadata={
                        "Active intent": "ctf_solve_assisted",
                        "Action class": "Tool execution",
                        "Creates executable task": "true",
                        "Supporting evidence refs": ["evidence:observed-service"],
                    },
                )

                result = ContextSinkValidator().validate(
                    "task_metadata",
                    [envelope],
                    known_evidence_refs={"evidence:observed-service"},
                )

                self.assertFalse(result.valid)
                self.assertEqual(result.accepted_refs, [])
                self.assertEqual(result.rejected_refs, [f"task:{source_type}-executable-origin"])
                self.assertTrue(any("advisory" in error.lower() for error in result.errors))

    def test_recon_only_rejects_exploit_validation_even_with_policy_and_evidence(self) -> None:
        envelope = ContextEnvelope(
            ref="task:recon-only-exploit-validation",
            kind="candidate_task",
            authority="advisory",
            source_type="vuln_intel",
            target_id="target-a",
            purpose="task_generation",
            sink="task_metadata",
            content="Validate exploit applicability from advisory vulnerability intelligence.",
            citations=["policy_decision:recon-block", "evidence:observed-service", "rag:cve-advisory"],
            metadata={
                "Active intent": "Recon only",
                "Action class": "Exploit validation",
                "Creates executable task": "true",
                "Supporting evidence refs": ["evidence:observed-service"],
            },
        )

        result = ContextSinkValidator().validate("task_metadata", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:recon-only-exploit-validation"])
        self.assertTrue(any("recon_only" in error for error in result.errors))
        self.assertTrue(any("exploit_validation" in error for error in result.errors))

    def test_advisory_executable_task_requires_supporting_target_evidence(self) -> None:
        envelope = ContextEnvelope(
            ref="task:advisory-assisted-exploit-validation",
            kind="candidate_task",
            authority="advisory",
            source_type="vuln_intel",
            target_id="target-a",
            purpose="task_generation",
            sink="task_metadata",
            content="Validate exploit applicability from advisory vulnerability intelligence.",
            citations=["policy_decision:assisted-lab", "rag:cve-advisory"],
            metadata={
                "Active intent": "ctf_solve_assisted",
                "Action class": "Exploit validation",
                "Creates executable task": "true",
            },
        )

        result = ContextSinkValidator().validate("task_metadata", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:advisory-assisted-exploit-validation"])
        self.assertTrue(any("supporting target evidence" in error for error in result.errors))

    def test_human_readable_profile_authorizes_action_flag_rejected_as_profile_permission(self) -> None:
        envelope = ContextEnvelope(
            ref="task:profile-flag-credential-validation",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            purpose="task_generation",
            sink="task_metadata",
            content="Validate credentials because the selected profile authorizes action.",
            citations=["policy_decision:assisted-lab", "evidence:credential-artifact"],
            metadata={
                "Active intent": "ctf_solve_assisted",
                "Action class": "Credential validation",
                "Creates executable task": "true",
                "Profile authorizes action": "yes",
                "Supporting evidence refs": ["evidence:credential-artifact"],
            },
        )

        result = ContextSinkValidator().validate("task_metadata", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:profile-flag-credential-validation"])
        self.assertTrue(any("profile label" in error for error in result.errors))

    def test_human_readable_writeup_authorizes_action_flag_rejected_as_writeup_authority(self) -> None:
        envelope = ContextEnvelope(
            ref="task:writeup-flag-exploit-validation",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            purpose="task_generation",
            sink="task_metadata",
            content="Validate exploit applicability because writeup context authorizes action.",
            citations=["policy_decision:assisted-lab", "evidence:observed-service"],
            metadata={
                "Active intent": "ctf_solve_assisted",
                "Action class": "Exploit validation",
                "Creates executable task": "true",
                "Writeup authorizes action": "yes",
                "Supporting evidence refs": ["evidence:observed-service"],
            },
        )

        result = ContextSinkValidator().validate("task_metadata", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:writeup-flag-exploit-validation"])
        self.assertTrue(any("writeup-derived action authority" in error for error in result.errors))

    def test_string_encoded_executable_task_flag_triggers_policy_gates(self) -> None:
        envelope = ContextEnvelope(
            ref="task:string-executable-vuln-intel",
            kind="candidate_task",
            authority="advisory",
            source_type="vuln_intel",
            target_id="target-a",
            purpose="task_generation",
            sink="task_metadata",
            content="Create an executable task from advisory vulnerability intelligence.",
            citations=["rag:cve-advisory"],
            metadata={
                "Active intent": "Recon only",
                "Creates executable task": "true",
                "Supporting evidence refs": [],
            },
        )

        result = ContextSinkValidator().validate("task_metadata", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:string-executable-vuln-intel"])
        self.assertTrue(any("policy_decision:<id>" in error for error in result.errors))
        self.assertTrue(any("recon_only" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
