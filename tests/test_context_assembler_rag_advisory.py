from __future__ import annotations

import unittest

from primordial.core.context import ContextAssembler, ContextEnvelope


class ContextAssemblerRagAdvisoryTests(unittest.TestCase):
    def test_assembler_omits_non_advisory_rag_sources_from_operational_prompts(self) -> None:
        envelopes = [
            self._rag("rag:methodology", "methodology_doc"),
            self._rag("rag:vuln-intel", "vuln_intel"),
            self._rag("rag:validated-external", "validated_external"),
            self._rag("rag:ctf-manifest", "ctf_manifest"),
            self._rag("rag:writeup", "writeup"),
            self._rag("rag:runtime-state", "runtime_state"),
            self._rag("rag:tool-output", "tool_output"),
            self._rag("rag:manual-artifact", "manual_artifact"),
            self._rag("rag:notion-projection", "notion"),
            self._rag("rag:github-issue", "github"),
            self._rag("rag:ctfd-challenge", "ctfd"),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(
            [item["ref"] for item in packet["sections"]["RAG_ADVISORY"]],
            [
                "rag:methodology",
                "rag:vuln-intel",
                "rag:validated-external",
                "rag:ctf-manifest",
                "rag:writeup",
            ],
        )
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        for ref in (
            "rag:runtime-state",
            "rag:tool-output",
            "rag:manual-artifact",
            "rag:notion-projection",
            "rag:github-issue",
            "rag:ctfd-challenge",
        ):
            self.assertEqual(omitted_refs[ref], "non_advisory_rag_source")
            self.assertNotIn(ref, packet["rendered"])

    def test_assembler_rejects_model_advisory_claims_citing_non_advisory_rag_sources(self) -> None:
        envelopes = [
            self._rag("rag:methodology", "methodology_doc"),
            self._rag("rag:github-issue", "github"),
            self._model_advisory("model:methodology-backed", ["rag:methodology"]),
            self._model_advisory("model:github-backed", ["rag:github-issue"]),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["MODEL_DERIVED"]], ["model:methodology-backed"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:github-issue"], "non_advisory_rag_source")
        self.assertEqual(omitted_refs["model:github-backed"], "invalid_citation")
        self.assertNotIn("model:github-backed", packet["rendered"])

    def test_assembler_rejects_model_advisory_claims_citing_non_prompt_rag(self) -> None:
        envelopes = [
            self._rag("rag:prompt-methodology", "methodology_doc"),
            self._rag("rag:notion-export-methodology", "methodology_doc", sink="notion_export"),
            self._model_advisory("model:prompt-methodology-backed", ["rag:prompt-methodology"]),
            self._model_advisory("model:notion-export-methodology-backed", ["rag:notion-export-methodology"]),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["RAG_ADVISORY"]], ["rag:prompt-methodology"])
        self.assertEqual([item["ref"] for item in packet["sections"]["MODEL_DERIVED"]], ["model:prompt-methodology-backed"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:notion-export-methodology"], "sink_mismatch")
        self.assertEqual(omitted_refs["model:notion-export-methodology-backed"], "invalid_citation")
        self.assertNotIn("model:notion-export-methodology-backed", packet["rendered"])

    def test_assembler_omits_target_fact_marked_rag_from_operational_prompts(self) -> None:
        envelopes = [
            self._rag("rag:methodology", "methodology_doc"),
            self._rag(
                "rag:target-fact",
                "vuln_intel",
                citations=["rag:target-fact", "evidence:observed-service"],
                metadata={"advisory_claim": True, "contains_target_fact": True},
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
        self.assertEqual(omitted_refs["rag:target-fact"], "target_fact_rag")
        self.assertNotIn("rag:target-fact", packet["rendered"])

    def _rag(
        self,
        ref: str,
        source_type: str,
        *,
        sink: str = "prompt",
        citations: list[str] | None = None,
        metadata: dict[str, object] | None = None,
    ) -> ContextEnvelope:
        return ContextEnvelope(
            ref=ref,
            kind="rag",
            authority="advisory",
            source_type=source_type,
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink=sink,
            content=f"{ref} advisory text.",
            citations=[ref] if citations is None else citations,
            metadata={} if metadata is None else metadata,
        )

    def _model_advisory(self, ref: str, citations: list[str]) -> ContextEnvelope:
        return ContextEnvelope(
            ref=ref,
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content=f"{ref} derived advisory text.",
            citations=citations,
            metadata={"advisory_claim": True},
        )


if __name__ == "__main__":
    unittest.main()
