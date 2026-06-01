from __future__ import annotations

from tests.test_context_assembler_common import *


class ContextAssemblerTestsPart2(ContextAssemblerTestsBase):
    def test_context_assembler_does_not_resolve_model_refs_against_unresolved_rag(self) -> None:
        invalid_rag = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "unresolved-rag-source-ref",
                "text": "Unresolved RAG provenance must not satisfy downstream source refs.",
                "metadata": {
                    "source_type": "methodology_doc",
                    "source_refs": ["evidence:missing-banner"],
                },
            },
            purpose="planner",
            sink="prompt",
        )
        invalid_rag.citations.append("evidence:missing-banner")
        model_summary = ContextEnvelope(
            ref="model:unresolved-rag-backed-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model summary must not be accepted when backed by unresolved RAG.",
            citations=["rag:unresolved-rag-source-ref"],
            metadata={"source_refs": ["rag:unresolved-rag-source-ref"]},
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
        self.assertEqual(omitted_refs["rag:unresolved-rag-source-ref"], "invalid_citation")
        self.assertEqual(omitted_refs["model:unresolved-rag-backed-summary"], "invalid_citation")
        self.assertNotIn("backed by unresolved RAG", packet["rendered"])

    def test_context_assembler_does_not_resolve_model_refs_against_rag_backed_by_invalid_rag(self) -> None:
        invalid_rag = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "invalid-root-rag-source-ref",
                "text": "Invalid root RAG provenance must not satisfy dependent RAG.",
                "metadata": {
                    "source_type": "methodology_doc",
                    "source_refs": ["github:issue-42"],
                },
            },
            purpose="planner",
            sink="prompt",
        )
        dependent_rag = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "dependent-on-invalid-rag",
                "text": "Dependent RAG backed by invalid RAG must be omitted.",
                "metadata": {
                    "source_type": "methodology_doc",
                    "source_refs": ["rag:invalid-root-rag-source-ref"],
                },
            },
            purpose="planner",
            sink="prompt",
        )
        dependent_rag.citations.append("rag:invalid-root-rag-source-ref")
        model_summary = ContextEnvelope(
            ref="model:dependent-rag-backed-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model summaries must not resolve against RAG omitted through transitive provenance.",
            citations=["rag:dependent-on-invalid-rag"],
            metadata={"source_refs": ["rag:dependent-on-invalid-rag"]},
        )

        packet = ContextAssembler().assemble(
            [invalid_rag, dependent_rag, model_summary],
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["RAG_ADVISORY"], [])
        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:invalid-root-rag-source-ref"], "invalid_citation")
        self.assertEqual(omitted_refs["rag:dependent-on-invalid-rag"], "invalid_citation")
        self.assertEqual(omitted_refs["model:dependent-rag-backed-summary"], "invalid_citation")
        self.assertNotIn("transitive provenance", packet["rendered"])

    def test_context_assembler_does_not_resolve_model_refs_against_generated_export_rag(self) -> None:
        generated_export_rag = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "generated-export-source-ref",
                "citation_id": "rag:generated-export-source-ref",
                "text": "Generated export advisory must not satisfy downstream source refs.",
                "metadata": {
                    "source_type": "methodology_doc",
                    "source_url": "https://example.invalid/findings/notion/rag.htb/notion-export.md",
                },
            },
            purpose="planner",
            sink="prompt",
        )
        model_summary = ContextEnvelope(
            ref="model:generated-export-backed-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model summary must not be accepted when backed by generated export RAG.",
            citations=["rag:generated-export-source-ref"],
            metadata={"source_refs": ["rag:generated-export-source-ref"]},
        )

        packet = ContextAssembler().assemble(
            [generated_export_rag, model_summary],
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["RAG_ADVISORY"], [])
        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:generated-export-source-ref"], "generated_export")
        self.assertEqual(omitted_refs["model:generated-export-backed-summary"], "invalid_citation")
        self.assertNotIn("backed by generated export RAG", packet["rendered"])

    def test_context_assembler_does_not_resolve_model_refs_against_invalid_evidence(self) -> None:
        invalid_evidence = ContextEnvelope(
            ref="evidence:invalid-source-ref",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Invalid evidence provenance must not satisfy downstream source refs.",
            citations=["evidence:invalid-source-ref"],
            metadata={"source_refs": ["evidence:invalid-source-ref", "github:issue-42"]},
        )
        model_summary = ContextEnvelope(
            ref="model:invalid-evidence-backed-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Model summary must not be accepted when backed by omitted evidence.",
            citations=["evidence:invalid-source-ref"],
            metadata={"source_refs": ["evidence:invalid-source-ref"]},
        )

        packet = ContextAssembler().assemble(
            [invalid_evidence, model_summary],
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["OBSERVED_EVIDENCE"], [])
        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["evidence:invalid-source-ref"], "invalid_citation")
        self.assertEqual(omitted_refs["model:invalid-evidence-backed-summary"], "invalid_citation")
        self.assertNotIn("backed by omitted evidence", packet["rendered"])

    def test_context_assembler_does_not_resolve_model_refs_against_unresolved_evidence(self) -> None:
        invalid_evidence = ContextEnvelope(
            ref="evidence:unresolved-source-ref",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Unresolved evidence provenance must not satisfy downstream source refs.",
            citations=["evidence:unresolved-source-ref", "evidence:missing-banner"],
            metadata={"source_refs": ["evidence:missing-banner"]},
        )
        model_summary = ContextEnvelope(
            ref="model:unresolved-evidence-backed-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Model summary must not be accepted when backed by unresolved evidence.",
            citations=["evidence:unresolved-source-ref"],
            metadata={"source_refs": ["evidence:unresolved-source-ref"]},
        )

        packet = ContextAssembler().assemble(
            [invalid_evidence, model_summary],
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["OBSERVED_EVIDENCE"], [])
        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["evidence:unresolved-source-ref"], "invalid_citation")
        self.assertEqual(omitted_refs["model:unresolved-evidence-backed-summary"], "invalid_citation")
        self.assertNotIn("backed by unresolved evidence", packet["rendered"])

__all__ = [name for name in globals() if name.endswith("Part2")]
