from __future__ import annotations

from tests.test_context_sinks_common import *


class ContextSinkValidatorTestsPart3(ContextSinkValidatorTestsBase):
    def test_prompt_sink_rejects_model_refs_against_generated_export_rag(self) -> None:
        generated_export_rag = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "generated-export-model-source",
                "citation_id": "rag:generated-export-model-source",
                "text": "Generated export RAG must not satisfy prompt model context.",
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
        )
        model_summary = ContextEnvelope(
            ref="model:generated-export-rag-backed",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model output must not resolve against generated export RAG.",
            citations=["rag:generated-export-model-source"],
            metadata={"source_refs": ["rag:generated-export-model-source"]},
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [generated_export_rag, model_summary],
            known_rag_refs={"rag:generated-export-model-source"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(
            result.rejected_refs,
            ["model:generated-export-rag-backed", "rag:generated-export-model-source"],
        )
        self.assertTrue(any("generated_export" in error for error in result.errors))
        self.assertTrue(any("unresolved rag citation" in error for error in result.errors))

    def test_prompt_sink_rejects_nested_metadata_generated_export_path(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "nested-generated-export-path",
                "citation_id": "rag:nested-generated-export-path",
                "text": "Nested generated export metadata must not enter prompts.",
                "metadata": {
                    "source_type": "methodology_doc",
                    "metadata": {
                        "source_file": "findings/notion/rag.htb/generated-export.md",
                    },
                    "corpus_type": "methodology_standards",
                    "domain": "methodology_standards",
                },
            },
            purpose="planner",
            sink="prompt",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [envelope],
            known_rag_refs={"rag:nested-generated-export-path"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:nested-generated-export-path"])
        self.assertTrue(any("generated_export" in error for error in result.errors))

    def test_prompt_sink_rejects_nested_metadata_generated_export_origin(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "nested-generated-export-origin",
                "citation_id": "rag:nested-generated-export-origin",
                "text": "Nested generated export origin metadata must not enter prompts.",
                "metadata": {
                    "source_type": "methodology_doc",
                    "metadata": {
                        "origin": "generated_export",
                    },
                    "corpus_type": "methodology_standards",
                    "domain": "methodology_standards",
                },
            },
            purpose="planner",
            sink="prompt",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [envelope],
            known_rag_refs={"rag:nested-generated-export-origin"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:nested-generated-export-origin"])
        self.assertTrue(any("generated_export" in error for error in result.errors))

    def test_prompt_sink_rejects_double_nested_generated_export_origin(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "double-nested-generated-export-origin",
                "citation_id": "rag:double-nested-generated-export-origin",
                "text": "Double-nested generated export origin metadata must not enter prompts.",
                "metadata": {
                    "source_type": "methodology_doc",
                    "layers": [[{"origin": "generated_export"}]],
                    "corpus_type": "methodology_standards",
                    "domain": "methodology_standards",
                },
            },
            purpose="planner",
            sink="prompt",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [envelope],
            known_rag_refs={"rag:double-nested-generated-export-origin"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:double-nested-generated-export-origin"])
        self.assertTrue(any("generated_export" in error for error in result.errors))

    def test_prompt_sink_rejects_rag_chunk_from_human_readable_generated_export_source_type(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "display-generated-export-source-type",
                "citation_id": "rag:display-generated-export-source-type",
                "text": "Generated export prose with display source-type metadata must not enter prompts.",
                "metadata": {
                    "Source type": "generated_export",
                    "corpus_type": "methodology_standards",
                    "domain": "methodology_standards",
                },
            },
            purpose="planner",
            sink="prompt",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [envelope],
            known_rag_refs={"rag:display-generated-export-source-type"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:display-generated-export-source-type"])
        self.assertTrue(any("generated_export" in error for error in result.errors))

    def test_prompt_sink_rejects_ai_output_disguised_as_operator_note(self) -> None:
        operator_note = ContextEnvelope(
            ref="note:operator-1",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            purpose="planner",
            sink="prompt",
            content="Human-authored operator note.",
            citations=["note:operator-1"],
        )
        model_note = ContextEnvelope(
            ref="note:model-generated",
            kind="operator_note",
            authority="asserted",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="AI output must not enter the operator note lane.",
            citations=["note:model-generated"],
        )

        result = ContextSinkValidator().validate("prompt", [operator_note, model_note])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["note:operator-1"])
        self.assertEqual(result.rejected_refs, ["note:model-generated"])
        self.assertTrue(any("non_operator_note_source" in error for error in result.errors))

    def test_prompt_sink_rejects_model_refs_against_masked_non_operator_note_source(self) -> None:
        note = ContextEnvelope(
            ref="note:masked-model-note",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            purpose="planner",
            sink="prompt",
            content="Top-level note source type must not mask nested model provenance.",
            citations=["note:masked-model-note"],
            metadata={
                "metadata": {
                    "source_type": "ai_output",
                },
            },
        )
        model_summary = ContextEnvelope(
            ref="model:masked-note-backed",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model output must not resolve against masked non-operator note sources.",
            citations=["note:masked-model-note"],
            metadata={"source_refs": ["note:masked-model-note"]},
        )

        result = ContextSinkValidator().validate("prompt", [note, model_summary])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:masked-note-backed", "note:masked-model-note"])
        self.assertTrue(any("non_operator_note_source" in error for error in result.errors))
        self.assertTrue(any("unresolved note citation" in error for error in result.errors))

__all__ = ["ContextSinkValidatorTestsPart3"]
