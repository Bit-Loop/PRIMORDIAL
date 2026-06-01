from __future__ import annotations

from tests.test_context_assembler_common import *


class ContextAssemblerTestsPart6(ContextAssemblerTestsBase):
    def test_context_assembler_omits_rag_chunk_from_generated_export_source_url(self) -> None:
        envelopes = [
            ContextEnvelope.from_rag_chunk(
                {
                    "chunk_id": "methodology",
                    "citation_id": "rag:methodology",
                    "text": "Methodology advisory material may enter operational prompts.",
                    "metadata": {
                        "source_type": "methodology_doc",
                        "corpus_type": "methodology_standards",
                        "domain": "methodology_standards",
                    },
                },
                purpose="planner",
                sink="prompt",
                target_id="target-a",
                active_generation_id="generation:2",
            ),
            ContextEnvelope.from_rag_chunk(
                {
                    "chunk_id": "generated-export-source-url",
                    "citation_id": "rag:generated-export-source-url",
                    "text": "Generated export prose from URL metadata must not enter operational prompts.",
                    "metadata": {
                        "source_type": "methodology_doc",
                        "source_url": "https://example.invalid/findings/notion/rag.htb/notion-export.md",
                        "corpus_type": "methodology_standards",
                        "domain": "methodology_standards",
                    },
                },
                purpose="planner",
                sink="prompt",
                target_id="target-a",
                active_generation_id="generation:2",
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
        self.assertEqual(omitted_refs["rag:generated-export-source-url"], "generated_export")
        self.assertNotIn("Generated export prose", packet["rendered"])

    def test_context_assembler_omits_rag_chunk_from_legacy_source_markdown_drop(self) -> None:
        envelopes = [
            ContextEnvelope.from_rag_chunk(
                {
                    "chunk_id": "methodology",
                    "citation_id": "rag:methodology",
                    "text": "Methodology advisory material may enter operational prompts.",
                    "metadata": {
                        "source_type": "methodology_doc",
                        "corpus_type": "methodology_standards",
                        "domain": "methodology_standards",
                    },
                },
                purpose="planner",
                sink="prompt",
                target_id="target-a",
                active_generation_id="generation:2",
            ),
            ContextEnvelope.from_rag_chunk(
                {
                    "chunk_id": "legacy-rag-src-api-top-10",
                    "citation_id": "rag:legacy-rag-src-api-top-10",
                    "text": "Raw docs/RAG_SRC Markdown must not enter operational prompts.",
                    "metadata": {
                        "source_type": "validated_external",
                        "source_file": "docs/RAG_SRC/0x11-t10.md",
                        "corpus_type": "api_security_standards",
                        "domain": "api_security",
                    },
                },
                purpose="planner",
                sink="prompt",
                target_id="target-a",
                active_generation_id="generation:2",
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
        self.assertEqual(omitted_refs["rag:legacy-rag-src-api-top-10"], "source_markdown")
        self.assertNotIn("Raw docs/RAG_SRC Markdown", packet["rendered"])

    def test_context_assembler_omits_rag_chunk_from_quarantined_markdown_drop(self) -> None:
        envelopes = [
            ContextEnvelope.from_rag_chunk(
                {
                    "chunk_id": "methodology",
                    "citation_id": "rag:methodology",
                    "text": "Methodology advisory material may enter operational prompts.",
                    "metadata": {
                        "source_type": "methodology_doc",
                        "corpus_type": "methodology_standards",
                        "domain": "methodology_standards",
                    },
                },
                purpose="planner",
                sink="prompt",
                target_id="target-a",
                active_generation_id="generation:2",
            ),
            ContextEnvelope.from_rag_chunk(
                {
                    "chunk_id": "quarantined-rag-src-api-top-10",
                    "citation_id": "rag:quarantined-rag-src-api-top-10",
                    "text": "Quarantined Markdown must not enter operational prompts.",
                    "metadata": {
                        "source_type": "validated_external",
                        "source_file": "runtime/quarantine/markdown/docs/RAG_SRC/0x11-t10.md",
                        "corpus_type": "api_security_standards",
                        "domain": "api_security",
                    },
                },
                purpose="planner",
                sink="prompt",
                target_id="target-a",
                active_generation_id="generation:2",
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
        self.assertEqual(omitted_refs["rag:quarantined-rag-src-api-top-10"], "source_markdown")
        self.assertNotIn("Quarantined Markdown must not enter", packet["rendered"])

    def test_context_assembler_omits_nested_operational_retrieval_disabled_rag(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "nested-retrieval-disabled",
                "citation_id": "rag:nested-retrieval-disabled",
                "text": "Nested retrieval deny metadata must not enter operational prompts.",
                "metadata": {
                    "source_type": "methodology_doc",
                    "metadata": {"operational_retrieval_allowed": False},
                    "corpus_type": "methodology_standards",
                    "domain": "methodology_standards",
                },
            },
            purpose="planner",
            sink="prompt",
            target_id="target-a",
            active_generation_id="generation:2",
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
        self.assertEqual(omitted_refs["rag:nested-retrieval-disabled"], "operational_retrieval_disabled")
        self.assertNotIn("Nested retrieval deny metadata", packet["rendered"])

    def test_context_assembler_omits_list_valued_operational_retrieval_disabled_rag(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "list-retrieval-disabled",
                "citation_id": "rag:list-retrieval-disabled",
                "text": "List-valued retrieval deny metadata must not enter operational prompts.",
                "metadata": {
                    "source_type": "methodology_doc",
                    "metadata": {"operational_retrieval_allowed": [True, False]},
                    "corpus_type": "methodology_standards",
                    "domain": "methodology_standards",
                },
            },
            purpose="planner",
            sink="prompt",
            target_id="target-a",
            active_generation_id="generation:2",
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
        self.assertEqual(omitted_refs["rag:list-retrieval-disabled"], "operational_retrieval_disabled")
        self.assertNotIn("List-valued retrieval deny metadata", packet["rendered"])

    def test_context_assembler_omits_model_refs_against_nested_retrieval_disabled_rag(self) -> None:
        disabled_rag = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "nested-disabled-model-source",
                "citation_id": "rag:nested-disabled-model-source",
                "text": "Nested retrieval deny metadata must not satisfy model provenance.",
                "metadata": {
                    "source_type": "methodology_doc",
                    "metadata": {"operational_retrieval_allowed": False},
                    "corpus_type": "methodology_standards",
                    "domain": "methodology_standards",
                },
            },
            purpose="planner",
            sink="prompt",
            target_id="target-a",
            active_generation_id="generation:2",
        )
        model_summary = ContextEnvelope(
            ref="model:nested-disabled-rag-backed",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model output must not resolve against retrieval-disabled RAG.",
            citations=["rag:nested-disabled-model-source"],
            metadata={"source_refs": ["rag:nested-disabled-model-source"]},
        )

        packet = ContextAssembler().assemble(
            [disabled_rag, model_summary],
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["RAG_ADVISORY"], [])
        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:nested-disabled-model-source"], "operational_retrieval_disabled")
        self.assertEqual(omitted_refs["model:nested-disabled-rag-backed"], "invalid_citation")
        self.assertNotIn("retrieval-disabled RAG", packet["rendered"])

    def test_context_assembler_report_writer_omits_uncited_ai_and_raw_chat(self) -> None:
        def envelope(ref: str, kind: str, authority: str, source_type: str, citations: list[str]) -> ContextEnvelope:
            return ContextEnvelope(
                ref=ref,
                kind=kind,
                authority=authority,
                source_type=source_type,
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="report_generation",
                sink="prompt",
                content=f"{ref} report context.",
                citations=citations,
            )

        envelopes = [
            envelope("evidence:banner", "evidence", "observed", "tool_output", ["evidence:banner"]),
            envelope("finding:web-1", "finding", "reviewed", "runtime_state", ["evidence:banner"]),
            envelope("note:operator-1", "operator_note", "asserted", "manual_artifact", ["note:operator-1"]),
            envelope("rag:method-1", "rag", "advisory", "methodology_doc", ["rag:method-1"]),
            envelope("model:summary-cited", "model_summary", "derived", "ai_output", ["evidence:banner"]),
            envelope("model:summary-uncited", "model_summary", "derived", "ai_output", []),
            envelope("chat:raw-1", "operator_note", "asserted", "chat", ["chat:raw-1"]),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="report_generation",
            role="report_writer",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["OBSERVED_EVIDENCE"]], ["evidence:banner"])
        self.assertEqual([item["ref"] for item in packet["sections"]["REVIEWED_FINDINGS"]], ["finding:web-1"])
        self.assertEqual([item["ref"] for item in packet["sections"]["OPERATOR_NOTES"]], ["note:operator-1"])
        self.assertEqual([item["ref"] for item in packet["sections"]["RAG_ADVISORY"]], ["rag:method-1"])
        self.assertEqual([item["ref"] for item in packet["sections"]["MODEL_DERIVED"]], ["model:summary-cited"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["model:summary-uncited"], "missing_citation")
        self.assertEqual(omitted_refs["chat:raw-1"], "raw_chat_context")
        self.assertNotIn("model:summary-uncited report context", packet["rendered"])
        self.assertNotIn("chat:raw-1 report context", packet["rendered"])

__all__ = [name for name in globals() if name.endswith("Part6")]
