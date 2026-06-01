from __future__ import annotations

from tests.test_context_assembler_source_boundaries_common import *


class ContextAssemblerSourceBoundaryTestsPart2(ContextAssemblerSourceBoundaryTestsBase):
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

__all__ = ["ContextAssemblerSourceBoundaryTestsPart2"]
