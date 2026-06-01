from __future__ import annotations

from tests.test_context_assembler_source_boundaries_common import *


class ContextAssemblerSourceBoundaryTestsPart1(ContextAssemblerSourceBoundaryTestsBase):
    def test_assembler_omits_non_evidence_sources_from_evidence_and_findings(self) -> None:
        envelopes = [
            self._envelope("evidence:scan-1", "evidence", "observed", "tool_output", ["evidence:scan-1"]),
            self._envelope("finding:web-1", "finding", "reviewed", "runtime_state", ["evidence:scan-1"]),
            self._envelope(
                "evidence:notion-projection",
                "evidence",
                "observed",
                "notion",
                ["evidence:notion-projection"],
            ),
            self._envelope("evidence:vuln-intel", "evidence", "observed", "vuln_intel", ["evidence:vuln-intel"]),
            self._envelope("finding:github-issue", "finding", "reviewed", "github", ["evidence:scan-1"]),
            self._envelope("finding:ai-summary", "finding", "reviewed", "ai_output", ["evidence:scan-1"]),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["OBSERVED_EVIDENCE"]], ["evidence:scan-1"])
        self.assertEqual([item["ref"] for item in packet["sections"]["REVIEWED_FINDINGS"]], ["finding:web-1"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        for ref in (
            "evidence:notion-projection",
            "evidence:vuln-intel",
            "finding:github-issue",
            "finding:ai-summary",
        ):
            self.assertEqual(omitted_refs[ref], "non_evidence_source")
        self.assertNotIn("evidence:notion-projection", packet["rendered"])
        self.assertNotIn("finding:github-issue", packet["rendered"])

    def test_assembler_omits_malformed_evidence_proof_records(self) -> None:
        envelopes = [
            self._envelope("evidence:scan-1", "evidence", "observed", "tool_output", ["evidence:scan-1"]),
            self._envelope(
                "evidence:advisory-proof",
                "evidence",
                "advisory",
                "tool_output",
                ["evidence:advisory-proof"],
            ),
            self._envelope(
                "model:evidence-shaped",
                "evidence",
                "observed",
                "tool_output",
                ["evidence:scan-1"],
            ),
            self._envelope(
                "model:evidence-shaped-target-fact",
                "model_summary",
                "derived",
                "ai_output",
                ["model:evidence-shaped"],
                metadata={"contains_target_fact": True},
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["OBSERVED_EVIDENCE"]], ["evidence:scan-1"])
        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["evidence:advisory-proof"], "invalid_evidence_authority")
        self.assertEqual(omitted_refs["model:evidence-shaped"], "invalid_evidence_ref")
        self.assertEqual(omitted_refs["model:evidence-shaped-target-fact"], "invalid_citation")
        self.assertNotIn("evidence:advisory-proof", packet["rendered"])
        self.assertNotIn("model:evidence-shaped", packet["rendered"])
        self.assertNotIn("model:evidence-shaped-target-fact", packet["rendered"])

    def test_assembler_omits_malformed_finding_proof_records(self) -> None:
        envelopes = [
            self._envelope("evidence:scan-1", "evidence", "observed", "tool_output", ["evidence:scan-1"]),
            self._envelope("finding:web-1", "finding", "reviewed", "runtime_state", ["evidence:scan-1"]),
            self._envelope(
                "model:finding-shaped",
                "finding",
                "reviewed",
                "runtime_state",
                ["evidence:scan-1"],
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["REVIEWED_FINDINGS"]], ["finding:web-1"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["model:finding-shaped"], "invalid_finding_ref")
        self.assertNotIn("model:finding-shaped", packet["rendered"])

    def test_assembler_omits_github_engineering_context_as_target_truth(self) -> None:
        envelopes = [
            self._envelope(
                "evidence:engineering-ledger",
                "evidence",
                "observed",
                "engineering_context",
                ["evidence:engineering-ledger"],
            ),
            self._envelope(
                "finding:github-project-context",
                "finding",
                "reviewed",
                "github_project_context",
                ["evidence:scan-1"],
            ),
            self._envelope(
                "github:reviewed-engineering-note",
                "github_ref",
                "reviewed",
                "engineering_context",
                ["github:reviewed-engineering-note"],
            ),
            self._envelope(
                "github:asserted-engineering-note",
                "github_ref",
                "asserted",
                "engineering_context",
                ["github:asserted-engineering-note"],
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["OBSERVED_EVIDENCE"], [])
        self.assertEqual(packet["sections"]["REVIEWED_FINDINGS"], [])
        self.assertEqual(
            [item["ref"] for item in packet["sections"]["COLLABORATION_REFS"]],
            ["github:asserted-engineering-note"],
        )
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["evidence:engineering-ledger"], "non_evidence_source")
        self.assertEqual(omitted_refs["finding:github-project-context"], "non_evidence_source")
        self.assertEqual(omitted_refs["github:reviewed-engineering-note"], "collaboration_truth_like_authority")
        self.assertNotIn("evidence:engineering-ledger", packet["rendered"])
        self.assertNotIn("finding:github-project-context", packet["rendered"])
        self.assertNotIn("github:reviewed-engineering-note", packet["rendered"])
        self.assertIn("github:asserted-engineering-note", packet["rendered"])

    def test_assembler_omits_raw_chat_operator_notes_from_operational_prompts(self) -> None:
        envelopes = [
            self._envelope("note:operator", "operator_note", "asserted", "manual_artifact", ["note:operator"]),
            self._envelope("note:raw-chat", "operator_note", "asserted", "chat", ["note:raw-chat"]),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["OPERATOR_NOTES"]], ["note:operator"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["note:raw-chat"], "raw_chat_context")
        self.assertNotIn("note:raw-chat", packet["rendered"])

    def test_assembler_omits_model_context_backed_by_unresolved_note_source_refs(self) -> None:
        envelopes = [
            self._envelope("note:operator", "operator_note", "asserted", "manual_artifact", ["note:operator"]),
            self._envelope(
                "model:fabricated-note-summary",
                "model_summary",
                "derived",
                "ai_output",
                ["note:made-up"],
                metadata={"source_refs": ["note:made-up"]},
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["OPERATOR_NOTES"]], ["note:operator"])
        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["model:fabricated-note-summary"], "invalid_citation")
        self.assertNotIn("model:fabricated-note-summary", packet["rendered"])

    def test_assembler_omits_reviewed_findings_with_unresolved_evidence_support(self) -> None:
        envelopes = [
            self._envelope("evidence:scan-1", "evidence", "observed", "tool_output", ["evidence:scan-1"]),
            self._envelope("finding:web-1", "finding", "reviewed", "runtime_state", ["evidence:scan-1"]),
            self._envelope(
                "finding:fabricated-support",
                "finding",
                "reviewed",
                "runtime_state",
                ["evidence:made-up"],
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["REVIEWED_FINDINGS"]], ["finding:web-1"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["finding:fabricated-support"], "invalid_citation")
        self.assertNotIn("finding:fabricated-support", packet["rendered"])

__all__ = ["ContextAssemblerSourceBoundaryTestsPart1"]
