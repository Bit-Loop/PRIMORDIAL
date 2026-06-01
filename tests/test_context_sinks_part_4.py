from __future__ import annotations

from tests.test_context_sinks_common import *


class ContextSinkValidatorTestsPart4(ContextSinkValidatorTestsBase):
    def test_prompt_sink_rejects_model_refs_against_plural_masked_non_operator_note_source(self) -> None:
        note = ContextEnvelope(
            ref="note:plural-masked-model-note",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            purpose="planner",
            sink="prompt",
            content="Top-level note source type must not mask plural nested model provenance.",
            citations=["note:plural-masked-model-note"],
            metadata={
                "metadata": {
                    "source_types": ["ai_output"],
                },
            },
        )
        model_summary = ContextEnvelope(
            ref="model:plural-masked-note-backed",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model output must not resolve against plural masked non-operator note sources.",
            citations=["note:plural-masked-model-note"],
            metadata={"source_refs": ["note:plural-masked-model-note"]},
        )

        result = ContextSinkValidator().validate("prompt", [note, model_summary])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:plural-masked-note-backed", "note:plural-masked-model-note"])
        self.assertTrue(any("non_operator_note_source" in error for error in result.errors))
        self.assertTrue(any("unresolved note citation" in error for error in result.errors))

    def test_prompt_sink_rejects_operator_note_with_unsupported_source_refs(self) -> None:
        note = ContextEnvelope(
            ref="note:unsupported-source-ref",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            purpose="planner",
            sink="prompt",
            content="Operator note provenance must not hide collaboration refs.",
            citations=["note:unsupported-source-ref"],
            metadata={"source_refs": ["github:issue-42"]},
        )

        result = ContextSinkValidator().validate("prompt", [note])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["note:unsupported-source-ref"])
        self.assertTrue(any("unsupported source_refs" in error for error in result.errors))

    def test_prompt_sink_rejects_placeholder_ai_summary_citation(self) -> None:
        envelope = ContextEnvelope(
            ref="model:placeholder-prompt-citation-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Placeholder citations must not satisfy prompt provenance.",
            citations=["note:null"],
        )

        result = ContextSinkValidator().validate("prompt", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:placeholder-prompt-citation-summary"])
        self.assertTrue(any("placeholder" in error for error in result.errors))
        self.assertTrue(any("note:null" in error for error in result.errors))

    def test_prompt_sink_rejects_model_refs_against_generated_export_operator_note(self) -> None:
        generated_export_note = ContextEnvelope(
            ref="note:generated-export-prompt-source",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            purpose="planner",
            sink="prompt",
            content="Generated export notes must not satisfy prompt model context.",
            citations=["note:generated-export-prompt-source"],
            metadata={"origin": "generated_export"},
        )
        model_summary = ContextEnvelope(
            ref="model:generated-export-note-backed",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model output must not resolve against generated export operator notes.",
            citations=["note:generated-export-prompt-source"],
            metadata={"source_refs": ["note:generated-export-prompt-source"]},
        )

        result = ContextSinkValidator().validate("prompt", [generated_export_note, model_summary])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(
            result.rejected_refs,
            ["model:generated-export-note-backed", "note:generated-export-prompt-source"],
        )
        self.assertTrue(any("generated_export" in error for error in result.errors))
        self.assertTrue(any("unresolved note citation" in error for error in result.errors))

    def test_prompt_sink_rejects_operator_note_with_unresolved_source_refs(self) -> None:
        note = ContextEnvelope(
            ref="note:unresolved-source-ref",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            purpose="planner",
            sink="prompt",
            content="Operator note provenance must not cite unresolved evidence.",
            citations=["note:unresolved-source-ref", "evidence:missing-banner"],
            metadata={"source_refs": ["evidence:missing-banner"]},
        )

        result = ContextSinkValidator().validate("prompt", [note], known_evidence_refs=set())

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["note:unresolved-source-ref"])
        self.assertTrue(any("unresolved evidence citation" in error for error in result.errors))

    def test_prompt_sink_rejects_model_refs_against_rejected_operator_note(self) -> None:
        note = ContextEnvelope(
            ref="note:bad-provenance",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            purpose="planner",
            sink="prompt",
            content="Operator note provenance must not cite unresolved evidence.",
            citations=["note:bad-provenance", "evidence:missing-banner"],
            metadata={"source_refs": ["evidence:missing-banner"]},
        )
        model_summary = ContextEnvelope(
            ref="model:bad-note-backed",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model output must not resolve against a rejected operator note.",
            citations=["note:bad-provenance"],
            metadata={"source_refs": ["note:bad-provenance"]},
        )

        result = ContextSinkValidator().validate("prompt", [note, model_summary], known_evidence_refs=set())

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:bad-note-backed", "note:bad-provenance"])
        self.assertTrue(any("unresolved evidence citation" in error for error in result.errors))
        self.assertTrue(any("unresolved note citation" in error for error in result.errors))

    def test_prompt_sink_rejects_model_refs_against_display_case_rejected_operator_note(self) -> None:
        note = ContextEnvelope(
            ref="note:display-case-bad-provenance",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            purpose="planner",
            sink="prompt",
            content="Operator note provenance must not cite unresolved evidence.",
            citations=["note:display-case-bad-provenance", "evidence:missing-banner"],
            metadata={"source_refs": ["evidence:missing-banner"]},
        )
        model_summary = ContextEnvelope(
            ref="model:display-case-bad-note-backed",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model output must not resolve against a rejected operator note with a display-case ref.",
            citations=["Note:display-case-bad-provenance"],
            metadata={"source_refs": ["Note:display-case-bad-provenance "]},
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [note, model_summary],
            known_evidence_refs=set(),
            known_note_refs={"Note:display-case-bad-provenance "},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(
            result.rejected_refs,
            ["model:display-case-bad-note-backed", "note:display-case-bad-provenance"],
        )
        self.assertTrue(any("unresolved evidence citation" in error for error in result.errors))
        self.assertTrue(any("unresolved note citation" in error for error in result.errors))

    def test_prompt_sink_rejects_model_refs_against_note_backed_by_rejected_rag(self) -> None:
        invalid_rag = ContextEnvelope(
            ref="rag:bad-note-source",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="planner",
            sink="prompt",
            content="Invalid RAG provenance must not satisfy dependent operator notes.",
            citations=["rag:bad-note-source"],
            metadata={"source_refs": ["github:issue-42"]},
        )
        dependent_note = ContextEnvelope(
            ref="note:bad-rag-backed",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            purpose="planner",
            sink="prompt",
            content="Operator notes must not resolve against rejected RAG.",
            citations=["note:bad-rag-backed", "rag:bad-note-source"],
            metadata={"source_refs": ["rag:bad-note-source"]},
        )
        model_summary = ContextEnvelope(
            ref="model:bad-rag-backed-note-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model output must not resolve against a note backed by rejected RAG.",
            citations=["note:bad-rag-backed"],
            metadata={"source_refs": ["note:bad-rag-backed"]},
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [invalid_rag, dependent_note, model_summary],
            known_rag_refs={"rag:bad-note-source"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(
            result.rejected_refs,
            ["model:bad-rag-backed-note-summary", "note:bad-rag-backed", "rag:bad-note-source"],
        )
        self.assertTrue(any("unsupported source_refs" in error for error in result.errors))
        self.assertTrue(any("unresolved rag citation" in error for error in result.errors))
        self.assertTrue(any("unresolved note citation" in error for error in result.errors))

__all__ = ["ContextSinkValidatorTestsPart4"]
