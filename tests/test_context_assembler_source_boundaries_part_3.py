from __future__ import annotations

from tests.test_context_assembler_source_boundaries_common import *


class ContextAssemblerSourceBoundaryTestsPart3(ContextAssemblerSourceBoundaryTestsBase):
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

__all__ = ["ContextAssemblerSourceBoundaryTestsPart3"]
