from __future__ import annotations

import unittest

from primordial.core.context import ContextAssembler, ContextEnvelope


class ContextAssemblerSourceBoundaryTests(unittest.TestCase):
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

    def test_assembler_omits_model_target_facts_backed_by_malformed_evidence(self) -> None:
        envelopes = [
            self._envelope("evidence:scan-1", "evidence", "observed", "tool_output", ["evidence:scan-1"]),
            self._envelope("evidence:rag-backed", "evidence", "observed", "tool_output", ["rag:service-claim"]),
            self._envelope(
                "model:valid-target-fact",
                "model_summary",
                "derived",
                "ai_output",
                ["evidence:scan-1"],
                metadata={"contains_target_fact": True},
            ),
            self._envelope(
                "model:rag-backed-evidence-target-fact",
                "model_summary",
                "derived",
                "ai_output",
                ["evidence:rag-backed"],
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
        self.assertEqual([item["ref"] for item in packet["sections"]["MODEL_DERIVED"]], ["model:valid-target-fact"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["evidence:rag-backed"], "invalid_citation")
        self.assertEqual(omitted_refs["model:rag-backed-evidence-target-fact"], "invalid_citation")
        self.assertNotIn("model:rag-backed-evidence-target-fact", packet["rendered"])

    def test_assembler_omits_malformed_rag_citations_from_operational_prompts(self) -> None:
        envelopes = [
            self._envelope("rag:self-cited", "rag", "advisory", "methodology_doc", ["rag:self-cited"]),
            self._envelope("rag:uncited", "rag", "advisory", "methodology_doc", []),
            self._envelope("rag:note-cited", "rag", "advisory", "methodology_doc", ["note:operator"]),
            self._envelope("rag:wrong-cited", "rag", "advisory", "methodology_doc", ["rag:other"]),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["RAG_ADVISORY"]], ["rag:self-cited"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:uncited"], "invalid_citation")
        self.assertEqual(omitted_refs["rag:note-cited"], "invalid_citation")
        self.assertEqual(omitted_refs["rag:wrong-cited"], "invalid_citation")
        self.assertNotIn("rag:uncited", packet["rendered"])
        self.assertNotIn("rag:note-cited", packet["rendered"])
        self.assertNotIn("rag:wrong-cited", packet["rendered"])

    def test_assembler_omits_model_advisory_claims_with_unresolved_rag_support(self) -> None:
        envelopes = [
            self._envelope("rag:methodology", "rag", "advisory", "methodology_doc", ["rag:methodology"]),
            self._envelope(
                "model:sourced-advisory",
                "model_summary",
                "derived",
                "ai_output",
                ["rag:methodology"],
                metadata={"advisory_claim": True},
            ),
            self._envelope(
                "model:fabricated-rag-advisory",
                "model_summary",
                "derived",
                "ai_output",
                ["rag:made-up"],
                metadata={"advisory_claim": True},
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["MODEL_DERIVED"]], ["model:sourced-advisory"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["model:fabricated-rag-advisory"], "invalid_citation")
        self.assertNotIn("model:fabricated-rag-advisory", packet["rendered"])

    def test_assembler_omits_model_advisory_claims_backed_by_malformed_rag(self) -> None:
        envelopes = [
            self._envelope("rag:methodology", "rag", "advisory", "methodology_doc", ["rag:methodology"]),
            self._envelope("rag:malformed", "rag", "advisory", "methodology_doc", ["note:operator"]),
            self._envelope(
                "model:valid-advisory",
                "model_summary",
                "derived",
                "ai_output",
                ["rag:methodology"],
                metadata={"advisory_claim": True},
            ),
            self._envelope(
                "model:malformed-rag-advisory",
                "model_summary",
                "derived",
                "ai_output",
                ["rag:malformed"],
                metadata={"advisory_claim": True},
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["RAG_ADVISORY"]], ["rag:methodology"])
        self.assertEqual([item["ref"] for item in packet["sections"]["MODEL_DERIVED"]], ["model:valid-advisory"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:malformed"], "invalid_citation")
        self.assertEqual(omitted_refs["model:malformed-rag-advisory"], "invalid_citation")
        self.assertNotIn("model:malformed-rag-advisory", packet["rendered"])

    def test_assembler_omits_model_advisory_claims_backed_by_wrong_target_or_stale_rag(self) -> None:
        envelopes = [
            self._envelope("rag:current-methodology", "rag", "advisory", "methodology_doc", ["rag:current-methodology"]),
            self._envelope(
                "rag:wrong-target-methodology",
                "rag",
                "advisory",
                "methodology_doc",
                ["rag:wrong-target-methodology"],
                target_id="target-b",
            ),
            self._envelope(
                "rag:stale-methodology",
                "rag",
                "advisory",
                "methodology_doc",
                ["rag:stale-methodology"],
                active_generation_id="generation:1",
            ),
            self._envelope(
                "model:current-advisory",
                "model_summary",
                "derived",
                "ai_output",
                ["rag:current-methodology"],
                metadata={"advisory_claim": True},
            ),
            self._envelope(
                "model:wrong-target-rag-advisory",
                "model_summary",
                "derived",
                "ai_output",
                ["rag:wrong-target-methodology"],
                metadata={"advisory_claim": True},
            ),
            self._envelope(
                "model:stale-rag-advisory",
                "model_summary",
                "derived",
                "ai_output",
                ["rag:stale-methodology"],
                metadata={"advisory_claim": True},
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["MODEL_DERIVED"]], ["model:current-advisory"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:wrong-target-methodology"], "wrong_target")
        self.assertEqual(omitted_refs["model:wrong-target-rag-advisory"], "invalid_citation")
        self.assertEqual(omitted_refs["model:stale-rag-advisory"], "invalid_citation")
        self.assertIn("rag:stale-methodology", [item["ref"] for item in packet["historical_context"]])
        self.assertNotIn("model:wrong-target-rag-advisory", packet["rendered"])
        self.assertNotIn("model:stale-rag-advisory", packet["rendered"])

    def test_assembler_omits_generated_export_rag_from_operational_prompts(self) -> None:
        envelopes = [
            self._envelope("rag:methodology", "rag", "advisory", "methodology_doc", ["rag:methodology"]),
            self._envelope(
                "rag:generated-export",
                "rag",
                "advisory",
                "generated_export",
                ["rag:generated-export"],
            ),
            self._envelope(
                "rag:export-origin",
                "rag",
                "advisory",
                "methodology_doc",
                ["rag:export-origin"],
                metadata={"Origin": "Generated export"},
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["RAG_ADVISORY"]], ["rag:methodology"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:generated-export"], "generated_export")
        self.assertEqual(omitted_refs["rag:export-origin"], "generated_export")
        self.assertNotIn("rag:generated-export", packet["rendered"])
        self.assertNotIn("rag:export-origin", packet["rendered"])

    def test_assembler_omits_operational_retrieval_disabled_rag_from_prompts(self) -> None:
        envelopes = [
            self._envelope("rag:methodology", "rag", "advisory", "methodology_doc", ["rag:methodology"]),
            self._envelope(
                "rag:retrieval-disabled",
                "rag",
                "advisory",
                "methodology_doc",
                ["rag:retrieval-disabled"],
                metadata={"operational_retrieval_allowed": False},
            ),
            self._envelope(
                "rag:display-retrieval-disabled",
                "rag",
                "advisory",
                "methodology_doc",
                ["rag:display-retrieval-disabled"],
                metadata={"Operational retrieval allowed": "No"},
            ),
            self._envelope(
                "rag:numeric-retrieval-disabled",
                "rag",
                "advisory",
                "methodology_doc",
                ["rag:numeric-retrieval-disabled"],
                metadata={"operational_retrieval_allowed": 0},
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["RAG_ADVISORY"]], ["rag:methodology"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:retrieval-disabled"], "operational_retrieval_disabled")
        self.assertEqual(omitted_refs["rag:display-retrieval-disabled"], "operational_retrieval_disabled")
        self.assertEqual(omitted_refs["rag:numeric-retrieval-disabled"], "operational_retrieval_disabled")
        self.assertNotIn("rag:retrieval-disabled", packet["rendered"])
        self.assertNotIn("rag:display-retrieval-disabled", packet["rendered"])
        self.assertNotIn("rag:numeric-retrieval-disabled", packet["rendered"])

    def test_assembler_omits_non_prompt_sink_records_from_operational_prompts(self) -> None:
        envelopes = [
            self._envelope("note:prompt", "operator_note", "asserted", "manual_artifact", ["note:prompt"]),
            self._envelope(
                "note:notion-export",
                "operator_note",
                "asserted",
                "manual_artifact",
                ["note:notion-export"],
                sink="notion_export",
            ),
            self._envelope(
                "task:metadata",
                "candidate_task",
                "asserted",
                "ai_output",
                ["task:metadata"],
                sink="task_metadata",
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["OPERATOR_NOTES"]], ["note:prompt"])
        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["note:notion-export"], "sink_mismatch")
        self.assertEqual(omitted_refs["task:metadata"], "sink_mismatch")
        self.assertNotIn("note:notion-export", packet["rendered"])
        self.assertNotIn("task:metadata", packet["rendered"])

    def test_assembler_omits_unsafe_executable_candidate_tasks_from_non_policy_prompts(self) -> None:
        envelopes = [
            self._envelope(
                "evidence:observed-service",
                "evidence",
                "observed",
                "tool_output",
                ["evidence:observed-service"],
            ),
            self._envelope(
                "task:advisory-exploit",
                "candidate_task",
                "advisory",
                "vuln_intel",
                ["rag:cve-advisory"],
                metadata={
                    "active_intent": "recon_only",
                    "action_class": "exploit_validation",
                    "creates_executable_task": True,
                },
            ),
            self._envelope(
                "model:safe-hypothesis",
                "hypothesis",
                "derived",
                "ai_output",
                ["evidence:observed-service"],
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

        self.assertEqual([item["ref"] for item in packet["sections"]["MODEL_DERIVED"]], ["model:safe-hypothesis"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["task:advisory-exploit"], "task_metadata_invalid")
        self.assertNotIn("task:advisory-exploit", packet["rendered"])

    def test_assembler_omits_model_target_facts_without_evidence_from_operational_prompts(self) -> None:
        envelopes = [
            self._envelope(
                "evidence:http-banner",
                "evidence",
                "observed",
                "tool_output",
                ["evidence:http-banner"],
            ),
            self._envelope(
                "model:rag-only-target-fact",
                "model_summary",
                "derived",
                "ai_output",
                ["rag:apache-249"],
                metadata={"contains_target_fact": True},
            ),
            self._envelope(
                "model:uncited-target-fact",
                "model_summary",
                "derived",
                "ai_output",
                [],
                metadata={"contains_target_fact": True},
            ),
            self._envelope(
                "model:evidence-backed-target-fact",
                "model_summary",
                "derived",
                "ai_output",
                ["evidence:http-banner"],
                metadata={"contains_target_fact": True},
            ),
            self._envelope(
                "model:fabricated-evidence-target-fact",
                "model_summary",
                "derived",
                "ai_output",
                ["evidence:made-up"],
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

        self.assertEqual(
            [item["ref"] for item in packet["sections"]["MODEL_DERIVED"]],
            ["model:evidence-backed-target-fact"],
        )
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["model:rag-only-target-fact"], "invalid_citation")
        self.assertEqual(omitted_refs["model:uncited-target-fact"], "invalid_citation")
        self.assertEqual(omitted_refs["model:fabricated-evidence-target-fact"], "invalid_citation")
        self.assertNotIn("model:rag-only-target-fact", packet["rendered"])
        self.assertNotIn("model:uncited-target-fact", packet["rendered"])
        self.assertNotIn("model:fabricated-evidence-target-fact", packet["rendered"])

    def _envelope(
        self,
        ref: str,
        kind: str,
        authority: str,
        source_type: str,
        citations: list[str],
        metadata: dict[str, object] | None = None,
        sink: str = "prompt",
        target_id: str = "target-a",
        active_generation_id: str = "generation:2",
    ) -> ContextEnvelope:
        return ContextEnvelope(
            ref=ref,
            kind=kind,
            authority=authority,
            source_type=source_type,
            target_id=target_id,
            active_generation_id=active_generation_id,
            purpose="planner",
            sink=sink,
            content=f"{ref} prompt context.",
            citations=citations,
            metadata=metadata or {},
        )


if __name__ == "__main__":
    unittest.main()
