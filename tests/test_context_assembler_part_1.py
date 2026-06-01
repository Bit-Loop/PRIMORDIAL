from __future__ import annotations

from tests.test_context_assembler_common import *


class ContextAssemblerTestsPart1(ContextAssemblerTestsBase):
    def test_context_assembler_filters_wrong_target_and_labels_stale_generation(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="evidence:current",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="planner",
                sink="prompt",
                content="tcp/443 is open on the current active IP.",
                citations=["evidence:current"],
            ),
            ContextEnvelope(
                ref="evidence:wrong-target",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                target_id="target-b",
                active_generation_id="generation:2",
                purpose="planner",
                sink="prompt",
                content="tcp/80 is open on another target.",
                citations=["evidence:wrong-target"],
            ),
            ContextEnvelope(
                ref="evidence:stale",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                target_id="target-a",
                active_generation_id="generation:1",
                purpose="planner",
                sink="prompt",
                content="tcp/80 was open on the old active IP.",
                citations=["evidence:stale"],
            ),
            ContextEnvelope(
                ref="rag:method-1",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="planner",
                sink="prompt",
                content="If TCP evidence is sparse, verify routing and active IP generation.",
                citations=["rag:method-1"],
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        current_refs = [item["ref"] for item in packet["sections"]["OBSERVED_EVIDENCE"]]
        rag_refs = [item["ref"] for item in packet["sections"]["RAG_ADVISORY"]]
        historical_refs = [item["ref"] for item in packet["historical_context"]]
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}

        self.assertEqual(current_refs, ["evidence:current"])
        self.assertEqual(rag_refs, ["rag:method-1"])
        self.assertEqual(historical_refs, ["evidence:stale"])
        self.assertEqual(omitted_refs["evidence:wrong-target"], "wrong_target")
        self.assertIn("AUTHORITATIVE_RUNTIME_STATE", packet["rendered"])
        self.assertIn("OBSERVED_EVIDENCE", packet["rendered"])
        self.assertIn("RAG_ADVISORY", packet["rendered"])
        self.assertNotIn("tcp/80 is open on another target", packet["rendered"])

    def test_context_assembler_omits_unbound_current_evidence(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="evidence:no-target",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                active_generation_id="generation:2",
                purpose="planner",
                sink="prompt",
                content="Targetless evidence must not enter current target context.",
                citations=["evidence:no-target"],
            ),
            ContextEnvelope(
                ref="evidence:no-generation",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                target_id="target-a",
                purpose="planner",
                sink="prompt",
                content="Generationless evidence must not enter current target context.",
                citations=["evidence:no-generation"],
            ),
            ContextEnvelope(
                ref="rag:global-method",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                purpose="planner",
                sink="prompt",
                content="Global methodology can still advise without target proof.",
                citations=["rag:global-method"],
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
        self.assertEqual([item["ref"] for item in packet["sections"]["RAG_ADVISORY"]], ["rag:global-method"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["evidence:no-target"], "missing_target_binding")
        self.assertEqual(omitted_refs["evidence:no-generation"], "missing_generation_binding")
        self.assertNotIn("Targetless evidence", packet["rendered"])
        self.assertNotIn("Generationless evidence", packet["rendered"])

    def test_context_assembler_omits_placeholder_rag_refs(self) -> None:
        placeholder = ContextEnvelope.from_rag_chunk(
            {
                "text": "RAG payload without chunk identity must not become citable context.",
                "metadata": {"source_type": "methodology_doc"},
            },
            purpose="planner",
            sink="prompt",
        )
        indexed = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "indexed-method",
                "text": "Indexed methodology can enter advisory context.",
                "metadata": {"source_type": "methodology_doc"},
            },
            purpose="planner",
            sink="prompt",
        )

        packet = ContextAssembler().assemble(
            [placeholder, indexed],
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["RAG_ADVISORY"]], ["rag:indexed-method"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:unknown"], "placeholder_rag_ref")
        self.assertNotIn("without chunk identity", packet["rendered"])
        self.assertIn("Indexed methodology", packet["rendered"])

    def test_context_assembler_omits_rag_with_unsupported_source_refs_metadata(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "unsupported-source-ref-advisory",
                "text": "RAG advisory must not hide collaboration provenance.",
                "metadata": {
                    "source_type": "methodology_doc",
                    "source_refs": ["github:issue-42"],
                },
            },
            purpose="planner",
            sink="prompt",
        )

        packet = ContextAssembler().assemble(
            [envelope],
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["RAG_ADVISORY"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:unsupported-source-ref-advisory"], "invalid_citation")
        self.assertNotIn("hide collaboration provenance", packet["rendered"])

    def test_context_assembler_omits_rag_with_unresolved_source_refs_metadata(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "unresolved-source-ref-advisory",
                "text": "RAG advisory must not cite unresolved evidence provenance.",
                "metadata": {
                    "source_type": "methodology_doc",
                    "source_refs": ["evidence:missing-banner"],
                },
            },
            purpose="planner",
            sink="prompt",
        )
        envelope.citations.append("evidence:missing-banner")

        packet = ContextAssembler().assemble(
            [envelope],
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["RAG_ADVISORY"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:unresolved-source-ref-advisory"], "invalid_citation")
        self.assertNotIn("unresolved evidence provenance", packet["rendered"])

    def test_context_assembler_does_not_resolve_model_refs_against_invalid_rag(self) -> None:
        invalid_rag = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "invalid-rag-source-ref",
                "text": "Invalid RAG provenance must not satisfy downstream source refs.",
                "metadata": {
                    "source_type": "methodology_doc",
                    "source_refs": ["github:issue-42"],
                },
            },
            purpose="planner",
            sink="prompt",
        )
        model_summary = ContextEnvelope(
            ref="model:invalid-rag-backed-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model summary must not be accepted when backed by omitted RAG.",
            citations=["rag:invalid-rag-source-ref"],
            metadata={"source_refs": ["rag:invalid-rag-source-ref"]},
        )

        packet = ContextAssembler().assemble(
            [invalid_rag, model_summary],
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["RAG_ADVISORY"], [])
        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:invalid-rag-source-ref"], "invalid_citation")
        self.assertEqual(omitted_refs["model:invalid-rag-backed-summary"], "invalid_citation")
        self.assertNotIn("Model summary must not be accepted", packet["rendered"])

__all__ = [name for name in globals() if name.endswith("Part1")]
