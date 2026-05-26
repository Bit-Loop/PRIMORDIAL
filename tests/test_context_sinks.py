from __future__ import annotations

import unittest

from primordial.core.context import ContextEnvelope, ContextSinkValidator
from primordial.core.context.collaboration import validate_collaboration_sink
from primordial.core.context.metadata_flags import metadata_value_is_false, raw_metadata_value
from primordial.core.context.notion_export import validate_notion_export_envelope
from primordial.core.context.report import validate_report_sink


class ContextSinkValidatorTests(unittest.TestCase):
    def test_shared_metadata_false_helper_handles_nested_list_values(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:nested-false-helper",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="rag_index",
            sink="rag_index",
            content="Nested false metadata should be recognized by the shared helper.",
            citations=["rag:nested-false-helper"],
            metadata={
                "policy": {
                    "retrieval": {
                        "operational_retrieval_allowed": ["true", "false"],
                    }
                }
            },
        )

        self.assertTrue(metadata_value_is_false(envelope, "operational_retrieval_allowed"))

    def test_shared_raw_metadata_helper_handles_nested_values(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:nested-raw-metadata-helper",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="rag_index",
            sink="rag_index",
            content="Nested raw metadata should be found by the shared helper.",
            citations=["rag:nested-raw-metadata-helper"],
            metadata={"audit": [{"source_url": "https://example.invalid/provenance.md"}]},
        )

        self.assertEqual(raw_metadata_value(envelope, "source_url"), "https://example.invalid/provenance.md")

    def test_evidence_sink_rejects_evidence_shaped_non_proof_sources(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="evidence:ctfd-challenge-text",
                kind="evidence",
                authority="observed",
                source_type="ctfd",
                purpose="evidence_review",
                sink="evidence",
                content="CTFd challenge text says the target has a web login.",
                citations=["evidence:ctfd-challenge-text"],
            ),
            ContextEnvelope(
                ref="evidence:github-issue",
                kind="evidence",
                authority="observed",
                source_type="github",
                purpose="evidence_review",
                sink="evidence",
                content="A GitHub issue claims the scanner proved exploitability.",
                citations=["evidence:github-issue"],
            ),
            ContextEnvelope(
                ref="evidence:generated-export",
                kind="evidence",
                authority="observed",
                source_type="generated_export",
                purpose="evidence_review",
                sink="evidence",
                content="Generated Notion export prose repeats an AI strategy summary.",
                citations=["evidence:generated-export"],
            ),
        ]

        result = ContextSinkValidator().validate("evidence", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(
            result.rejected_refs,
            ["evidence:ctfd-challenge-text", "evidence:generated-export", "evidence:github-issue"],
        )
        self.assertEqual(result.accepted_refs, [])
        for source_type in ("ctfd", "github", "generated_export"):
            self.assertTrue(any(f"source_type={source_type}" in error for error in result.errors))

    def test_evidence_sink_rejects_generated_export_origin_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="evidence:export-origin-service",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="evidence_review",
            sink="evidence",
            content="Generated export provenance must not be laundered into observed evidence.",
            citations=["evidence:export-origin-service"],
            metadata={"origin": "generated_export"},
        )

        result = ContextSinkValidator().validate("evidence", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["evidence:export-origin-service"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_evidence_sink_rejects_generated_export_source_url(self) -> None:
        envelope = ContextEnvelope(
            ref="evidence:export-url-service",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="evidence_review",
            sink="evidence",
            content="Generated export URLs must not be laundered into observed evidence.",
            citations=["evidence:export-url-service"],
            metadata={"source_url": "https://example.invalid/findings/notion/target-a/notion-export.md"},
        )

        result = ContextSinkValidator().validate("evidence", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["evidence:export-url-service"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_evidence_sink_rejects_unsupported_source_refs_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="evidence:github-provenance-service",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="evidence_review",
            sink="evidence",
            content="Observed evidence must not hide collaboration provenance in source_refs metadata.",
            citations=["evidence:observed-service"],
            metadata={"source_refs": ["evidence:observed-service", "github:issue-42"]},
        )

        result = ContextSinkValidator().validate(
            "evidence",
            [envelope],
            known_evidence_refs={"evidence:observed-service"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["evidence:github-provenance-service"])
        self.assertTrue(any("unsupported source_refs" in error for error in result.errors))

    def test_evidence_sink_rejects_operator_note_as_proof_support(self) -> None:
        envelope = ContextEnvelope(
            ref="evidence:note-supported-service",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="evidence_review",
            sink="evidence",
            content="Operator notes must not become proof support for observed evidence.",
            citations=["evidence:observed-service", "note:operator-context"],
        )

        result = ContextSinkValidator().validate(
            "evidence",
            [envelope],
            known_evidence_refs={"evidence:observed-service"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["evidence:note-supported-service"])
        self.assertTrue(any("non-evidence citation support" in error for error in result.errors))

    def test_evidence_sink_rejects_context_restrictions_that_exclude_evidence(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="evidence:prompt-only-proof",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                purpose="evidence_review",
                sink="evidence",
                content="Prompt-only proof records must not enter the evidence sink.",
                citations=["evidence:prompt-only-proof"],
                valid_for=["prompt"],
                metadata={"valid_for": ["prompt"]},
            ),
            ContextEnvelope(
                ref="evidence:evidence-denied-proof",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                purpose="evidence_review",
                sink="evidence",
                content="Evidence-denied proof records must not enter the evidence sink.",
                citations=["evidence:evidence-denied-proof"],
                invalid_for=["evidence"],
                metadata={"invalid_for": ["evidence"]},
            ),
        ]

        result = ContextSinkValidator().validate("evidence", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["evidence:evidence-denied-proof", "evidence:prompt-only-proof"])
        self.assertTrue(any("valid_for excludes evidence" in error for error in result.errors))
        self.assertTrue(any("invalid_for excludes evidence" in error for error in result.errors))

    def test_finding_sink_rejects_generated_export_origin_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="finding:export-origin-service",
            kind="finding",
            authority="reviewed",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="finding_review",
            sink="finding",
            content="Generated export provenance must not be laundered into a reviewed finding.",
            citations=["evidence:observed-service"],
            metadata={"origin": "generated_export"},
        )

        result = ContextSinkValidator().validate(
            "finding",
            [envelope],
            known_evidence_refs={"evidence:observed-service"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["finding:export-origin-service"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_finding_sink_rejects_generated_export_source_url(self) -> None:
        envelope = ContextEnvelope(
            ref="finding:export-url-service",
            kind="finding",
            authority="reviewed",
            source_type="runtime_state",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="finding_review",
            sink="finding",
            content="Generated export URLs must not be laundered into a reviewed finding.",
            citations=["evidence:observed-service"],
            metadata={"source_url": "https://example.invalid/findings/notion/target-a/notion-export.md"},
        )

        result = ContextSinkValidator().validate(
            "finding",
            [envelope],
            known_evidence_refs={"evidence:observed-service"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["finding:export-url-service"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_finding_sink_rejects_unsupported_source_refs_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="finding:github-provenance-service",
            kind="finding",
            authority="reviewed",
            source_type="runtime_state",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="finding_review",
            sink="finding",
            content="Reviewed findings must not hide collaboration provenance in source_refs metadata.",
            citations=["evidence:observed-service"],
            metadata={"source_refs": ["evidence:observed-service", "github:issue-42"]},
        )

        result = ContextSinkValidator().validate(
            "finding",
            [envelope],
            known_evidence_refs={"evidence:observed-service"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["finding:github-provenance-service"])
        self.assertTrue(any("unsupported source_refs" in error for error in result.errors))

    def test_finding_sink_rejects_operator_note_as_proof_support(self) -> None:
        envelope = ContextEnvelope(
            ref="finding:note-supported-service",
            kind="finding",
            authority="reviewed",
            source_type="runtime_state",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="finding_review",
            sink="finding",
            content="Operator notes must not become proof support for reviewed findings.",
            citations=["evidence:observed-service", "note:operator-context"],
        )

        result = ContextSinkValidator().validate(
            "finding",
            [envelope],
            known_evidence_refs={"evidence:observed-service"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["finding:note-supported-service"])
        self.assertTrue(any("non-evidence citation support" in error for error in result.errors))

    def test_finding_sink_rejects_context_restrictions_that_exclude_finding(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="finding:prompt-only-finding",
                kind="finding",
                authority="reviewed",
                source_type="runtime_state",
                purpose="finding_review",
                sink="finding",
                content="Prompt-only reviewed findings must not enter the finding sink.",
                citations=["evidence:observed-service"],
                valid_for=["prompt"],
                metadata={"valid_for": ["prompt"]},
            ),
            ContextEnvelope(
                ref="finding:finding-denied",
                kind="finding",
                authority="reviewed",
                source_type="runtime_state",
                purpose="finding_review",
                sink="finding",
                content="Finding-denied reviewed findings must not enter the finding sink.",
                citations=["evidence:observed-service"],
                invalid_for=["finding"],
                metadata={"invalid_for": ["finding"]},
            ),
        ]

        result = ContextSinkValidator().validate(
            "finding",
            envelopes,
            known_evidence_refs={"evidence:observed-service"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["finding:finding-denied", "finding:prompt-only-finding"])
        self.assertTrue(any("valid_for excludes finding" in error for error in result.errors))
        self.assertTrue(any("invalid_for excludes finding" in error for error in result.errors))

    def test_finding_sink_rejects_masked_nested_non_evidence_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="finding:masked-model-source",
            kind="finding",
            authority="reviewed",
            source_type="runtime_state",
            purpose="finding_review",
            sink="finding",
            content="Top-level finding source type must not mask nested model provenance.",
            citations=["evidence:observed-service"],
            metadata={
                "metadata": {
                    "source_type": "ai_output",
                },
            },
        )

        result = ContextSinkValidator().validate(
            "finding",
            [envelope],
            known_evidence_refs={"evidence:observed-service"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["finding:masked-model-source"])
        self.assertTrue(any("source_type=ai_output" in error for error in result.errors))

    def test_prompt_sink_rejects_rag_chunk_from_generated_export_path(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "legacy-generated-export-path",
                "citation_id": "rag:legacy-generated-export-path",
                "text": "Generated export prose must not enter operational prompts.",
                "metadata": {
                    "source_type": "methodology_doc",
                    "source_file": "findings/notion/rag.htb/notion-export.md",
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
            known_rag_refs={"rag:legacy-generated-export-path"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:legacy-generated-export-path"])
        self.assertTrue(any("generated_export" in error for error in result.errors))

    def test_prompt_sink_rejects_rag_chunk_from_human_readable_generated_export_path(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "display-generated-export-path",
                "citation_id": "rag:display-generated-export-path",
                "text": "Generated export prose with display metadata must not enter prompts.",
                "metadata": {
                    "source_type": "methodology_doc",
                    "Source file": "findings/notion/rag.htb/notion-export.md",
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
            known_rag_refs={"rag:display-generated-export-path"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:display-generated-export-path"])
        self.assertTrue(any("generated_export" in error for error in result.errors))

    def test_prompt_sink_rejects_rag_chunk_from_generated_export_source_url(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "generated-export-source-url",
                "citation_id": "rag:generated-export-source-url",
                "text": "Generated export source URLs must not enter prompts.",
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

        result = ContextSinkValidator().validate(
            "prompt",
            [envelope],
            known_rag_refs={"rag:generated-export-source-url"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:generated-export-source-url"])
        self.assertTrue(any("generated_export" in error for error in result.errors))

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

    def test_prompt_sink_rejects_model_refs_against_nested_retrieval_disabled_rag(self) -> None:
        disabled_rag = ContextEnvelope(
            ref="rag:nested-disabled-prompt-source",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="planner",
            sink="prompt",
            content="Retrieval-disabled RAG must not satisfy prompt model context.",
            citations=["rag:nested-disabled-prompt-source"],
            metadata={"metadata": {"operational_retrieval_allowed": False}},
        )
        model_summary = ContextEnvelope(
            ref="model:nested-disabled-rag-backed",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model output must not resolve against retrieval-disabled RAG.",
            citations=["rag:nested-disabled-prompt-source"],
            metadata={"source_refs": ["rag:nested-disabled-prompt-source"]},
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [disabled_rag, model_summary],
            known_rag_refs={"rag:nested-disabled-prompt-source"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(
            result.rejected_refs,
            ["model:nested-disabled-rag-backed", "rag:nested-disabled-prompt-source"],
        )
        self.assertTrue(any("operational_retrieval_allowed=false" in error for error in result.errors))
        self.assertTrue(any("unresolved rag citation" in error for error in result.errors))

    def test_prompt_sink_rejects_model_refs_against_list_valued_retrieval_disabled_rag(self) -> None:
        disabled_rag = ContextEnvelope(
            ref="rag:list-disabled-prompt-source",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="planner",
            sink="prompt",
            content="List-valued retrieval-disabled RAG must not satisfy prompt model context.",
            citations=["rag:list-disabled-prompt-source"],
            metadata={"metadata": {"operational_retrieval_allowed": [True, False]}},
        )
        model_summary = ContextEnvelope(
            ref="model:list-disabled-rag-backed",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model output must not resolve against list-valued retrieval-disabled RAG.",
            citations=["rag:list-disabled-prompt-source"],
            metadata={"source_refs": ["rag:list-disabled-prompt-source"]},
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [disabled_rag, model_summary],
            known_rag_refs={"rag:list-disabled-prompt-source"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(
            result.rejected_refs,
            ["model:list-disabled-rag-backed", "rag:list-disabled-prompt-source"],
        )
        self.assertTrue(any("operational_retrieval_allowed=false" in error for error in result.errors))
        self.assertTrue(any("unresolved rag citation" in error for error in result.errors))

    def test_prompt_sink_rejects_model_refs_against_nested_writeups_disabled_rag(self) -> None:
        disabled_writeup = ContextEnvelope(
            ref="rag:nested-writeups-disabled-prompt-source",
            kind="rag",
            authority="advisory",
            source_type="writeup",
            purpose="ctf_solver_context",
            sink="prompt",
            content="Nested writeup deny metadata must not satisfy prompt model context.",
            citations=["rag:nested-writeups-disabled-prompt-source"],
            metadata={"metadata": {"writeups_allowed": False}},
        )
        model_summary = ContextEnvelope(
            ref="model:nested-writeup-backed",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="ctf_solver_context",
            sink="prompt",
            content="Model output must not resolve against writeup-disabled RAG.",
            citations=["rag:nested-writeups-disabled-prompt-source"],
            metadata={"source_refs": ["rag:nested-writeups-disabled-prompt-source"]},
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [disabled_writeup, model_summary],
            known_rag_refs={"rag:nested-writeups-disabled-prompt-source"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(
            result.rejected_refs,
            ["model:nested-writeup-backed", "rag:nested-writeups-disabled-prompt-source"],
        )
        self.assertTrue(any("writeups_forbidden" in error for error in result.errors))
        self.assertTrue(any("unresolved rag citation" in error for error in result.errors))

    def test_prompt_sink_rejects_model_refs_against_masked_non_advisory_rag_source(self) -> None:
        invalid_rag = ContextEnvelope(
            ref="rag:masked-model-prompt-source",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="planner",
            sink="prompt",
            content="Top-level advisory source type must not mask nested model provenance.",
            citations=["rag:masked-model-prompt-source"],
            metadata={
                "metadata": {
                    "source_type": "ai_output",
                },
            },
        )
        model_summary = ContextEnvelope(
            ref="model:masked-rag-backed",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model output must not resolve against masked non-advisory RAG sources.",
            citations=["rag:masked-model-prompt-source"],
            metadata={"source_refs": ["rag:masked-model-prompt-source"]},
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [invalid_rag, model_summary],
            known_rag_refs={"rag:masked-model-prompt-source"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:masked-rag-backed", "rag:masked-model-prompt-source"])
        self.assertTrue(any("source_type=ai_output" in error for error in result.errors))
        self.assertTrue(any("unresolved rag citation" in error for error in result.errors))

    def test_prompt_sink_rejects_model_refs_against_rejected_evidence_source_refs(self) -> None:
        invalid_evidence = ContextEnvelope(
            ref="evidence:bad-prompt-source",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            purpose="planner",
            sink="prompt",
            content="Evidence with unsupported source refs must not satisfy prompt model context.",
            citations=["evidence:bad-prompt-source"],
            metadata={"source_refs": ["github:issue-42"]},
        )
        model_summary = ContextEnvelope(
            ref="model:bad-evidence-backed",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model output must not resolve against rejected evidence source refs.",
            citations=["evidence:bad-prompt-source"],
            metadata={"source_refs": ["evidence:bad-prompt-source"]},
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [invalid_evidence, model_summary],
            known_evidence_refs={"evidence:bad-prompt-source"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["evidence:bad-prompt-source", "model:bad-evidence-backed"])
        self.assertTrue(any("unsupported source_refs" in error for error in result.errors))
        self.assertTrue(any("unresolved evidence citation" in error for error in result.errors))

    def test_prompt_sink_rejects_model_refs_against_non_proof_evidence_source(self) -> None:
        invalid_evidence = ContextEnvelope(
            ref="evidence:github-prompt-source",
            kind="evidence",
            authority="observed",
            source_type="github",
            purpose="planner",
            sink="prompt",
            content="GitHub engineering context must not satisfy prompt evidence refs.",
            citations=["evidence:github-prompt-source"],
        )
        model_summary = ContextEnvelope(
            ref="model:github-evidence-backed",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model output must not resolve against non-proof evidence sources.",
            citations=["evidence:github-prompt-source"],
            metadata={"source_refs": ["evidence:github-prompt-source"]},
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [invalid_evidence, model_summary],
            known_evidence_refs={"evidence:github-prompt-source"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["evidence:github-prompt-source", "model:github-evidence-backed"])
        self.assertTrue(any("source_type=github" in error for error in result.errors))
        self.assertTrue(any("unresolved evidence citation" in error for error in result.errors))

    def test_prompt_sink_rejects_model_refs_against_masked_non_proof_evidence_source(self) -> None:
        invalid_evidence = ContextEnvelope(
            ref="evidence:masked-model-prompt-source",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            purpose="planner",
            sink="prompt",
            content="Top-level evidence source type must not mask nested model provenance.",
            citations=["evidence:masked-model-prompt-source"],
            metadata={
                "metadata": {
                    "source_type": "ai_output",
                },
            },
        )
        model_summary = ContextEnvelope(
            ref="model:masked-evidence-backed",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model output must not resolve against masked non-proof evidence sources.",
            citations=["evidence:masked-model-prompt-source"],
            metadata={"source_refs": ["evidence:masked-model-prompt-source"]},
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [invalid_evidence, model_summary],
            known_evidence_refs={"evidence:masked-model-prompt-source"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["evidence:masked-model-prompt-source", "model:masked-evidence-backed"])
        self.assertTrue(any("source_type=ai_output" in error for error in result.errors))
        self.assertTrue(any("unresolved evidence citation" in error for error in result.errors))

    def test_prompt_sink_rejects_model_refs_against_invalid_evidence_authority(self) -> None:
        invalid_evidence = ContextEnvelope(
            ref="evidence:advisory-prompt-source",
            kind="evidence",
            authority="advisory",
            source_type="tool_output",
            purpose="planner",
            sink="prompt",
            content="Advisory evidence authority must not satisfy prompt model context.",
            citations=["evidence:advisory-prompt-source"],
        )
        model_summary = ContextEnvelope(
            ref="model:advisory-evidence-backed",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model output must not resolve against invalid evidence authority.",
            citations=["evidence:advisory-prompt-source"],
            metadata={"source_refs": ["evidence:advisory-prompt-source"]},
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [invalid_evidence, model_summary],
            known_evidence_refs={"evidence:advisory-prompt-source"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["evidence:advisory-prompt-source", "model:advisory-evidence-backed"])
        self.assertTrue(any("authority=advisory" in error for error in result.errors))
        self.assertTrue(any("unresolved evidence citation" in error for error in result.errors))

    def test_prompt_sink_rejects_model_refs_against_rag_cited_evidence(self) -> None:
        invalid_evidence = ContextEnvelope(
            ref="evidence:rag-backed-prompt-source",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            purpose="planner",
            sink="prompt",
            content="RAG advisory material must not satisfy prompt evidence refs.",
            citations=["rag:service-claim"],
        )
        model_summary = ContextEnvelope(
            ref="model:rag-backed-evidence-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model output must not resolve against RAG-cited evidence.",
            citations=["evidence:rag-backed-prompt-source"],
            metadata={"source_refs": ["evidence:rag-backed-prompt-source"]},
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [invalid_evidence, model_summary],
            known_evidence_refs={"evidence:rag-backed-prompt-source"},
            known_rag_refs={"rag:service-claim"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(
            result.rejected_refs,
            ["evidence:rag-backed-prompt-source", "model:rag-backed-evidence-summary"],
        )
        self.assertTrue(any("non-evidence citation support" in error for error in result.errors))
        self.assertTrue(any("unresolved evidence citation" in error for error in result.errors))

    def test_prompt_sink_rejects_model_refs_against_generated_export_evidence(self) -> None:
        generated_export_evidence = ContextEnvelope(
            ref="evidence:generated-export-prompt-source",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            purpose="planner",
            sink="prompt",
            content="Generated export evidence must not satisfy prompt model context.",
            citations=["evidence:generated-export-prompt-source"],
            metadata={"origin": "generated_export"},
        )
        model_summary = ContextEnvelope(
            ref="model:generated-export-evidence-backed",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model output must not resolve against generated export evidence.",
            citations=["evidence:generated-export-prompt-source"],
            metadata={"source_refs": ["evidence:generated-export-prompt-source"]},
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [generated_export_evidence, model_summary],
            known_evidence_refs={"evidence:generated-export-prompt-source"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(
            result.rejected_refs,
            ["evidence:generated-export-prompt-source", "model:generated-export-evidence-backed"],
        )
        self.assertTrue(any("generated_export" in error for error in result.errors))
        self.assertTrue(any("unresolved evidence citation" in error for error in result.errors))

    def test_prompt_sink_rejects_finding_with_unsupported_source_refs(self) -> None:
        finding = ContextEnvelope(
            ref="finding:bad-prompt-source",
            kind="finding",
            authority="reviewed",
            source_type="runtime_state",
            purpose="planner",
            sink="prompt",
            content="Reviewed findings with unsupported source refs must not enter prompts.",
            citations=["evidence:http-banner"],
            metadata={"source_refs": ["evidence:http-banner", "github:issue-42"]},
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [finding],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["finding:bad-prompt-source"])
        self.assertTrue(any("unsupported source_refs" in error for error in result.errors))

    def test_discord_notification_rejects_ai_output_disguised_as_operator_note(self) -> None:
        operator_note = ContextEnvelope(
            ref="note:operator-1",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            purpose="discord_notification",
            sink="discord_notification",
            content="Human-authored operator note may be included in operator notification context.",
            citations=["note:operator-1"],
        )
        model_note = ContextEnvelope(
            ref="note:model-generated",
            kind="operator_note",
            authority="asserted",
            source_type="ai_output",
            purpose="discord_notification",
            sink="discord_notification",
            content="AI output must not enter the operator-note lane for notifications.",
            citations=["note:model-generated"],
            metadata={"labels": ["advisory"]},
        )

        result = ContextSinkValidator().validate("discord_notification", [operator_note, model_note])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["note:operator-1"])
        self.assertEqual(result.rejected_refs, ["note:model-generated"])
        self.assertTrue(any("non_operator_note_source" in error for error in result.errors))

    def test_discord_notification_rejects_model_refs_against_rejected_operator_note(self) -> None:
        note = ContextEnvelope(
            ref="note:bad-discord-provenance",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            purpose="discord_notification",
            sink="discord_notification",
            content="Discord note provenance must not cite unresolved evidence.",
            citations=["note:bad-discord-provenance", "evidence:missing-banner"],
            metadata={"source_refs": ["evidence:missing-banner"]},
        )
        model_summary = ContextEnvelope(
            ref="model:bad-discord-note-backed",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="discord_notification",
            sink="discord_notification",
            content="Discord model output must not resolve against a rejected operator note.",
            citations=["note:bad-discord-provenance"],
            metadata={"labels": ["advisory"], "source_refs": ["note:bad-discord-provenance"]},
        )

        result = ContextSinkValidator().validate(
            "discord_notification",
            [note, model_summary],
            known_evidence_refs=set(),
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:bad-discord-note-backed", "note:bad-discord-provenance"])
        self.assertTrue(any("unresolved evidence citation" in error for error in result.errors))
        self.assertTrue(any("unresolved note citation" in error for error in result.errors))

    def test_direct_discord_notification_rejects_operator_note_with_unsupported_source_refs(self) -> None:
        note = ContextEnvelope(
            ref="note:direct-discord-unsupported-source-refs",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            purpose="discord_notification",
            sink="discord_notification",
            content="Direct Discord validation must not let operator notes hide unsupported provenance.",
            citations=["note:direct-discord-unsupported-source-refs"],
            metadata={"source_refs": ["github:issue-42"]},
        )

        decision = validate_collaboration_sink("discord_notification", note)

        self.assertEqual(decision.action, "reject")
        self.assertIn("unsupported source_refs", decision.message)
        self.assertIn("github:issue-42", decision.message)

    def test_direct_discord_notification_rejects_rag_with_unsupported_source_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:direct-discord-unsupported-source-refs",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="discord_notification",
            sink="discord_notification",
            content="Direct Discord validation must not let RAG hide unsupported provenance.",
            citations=["rag:direct-discord-unsupported-source-refs"],
            metadata={"labels": ["advisory"], "source_refs": ["github:issue-42"]},
        )

        decision = validate_collaboration_sink("discord_notification", envelope)

        self.assertEqual(decision.action, "reject")
        self.assertIn("unsupported source_refs", decision.message)
        self.assertIn("github:issue-42", decision.message)

    def test_discord_notification_rejects_nested_writeups_disabled_writeup(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:discord-writeups-disabled",
            kind="rag",
            authority="advisory",
            source_type="writeup",
            purpose="discord_notification",
            sink="discord_notification",
            content="Discord notifications must not publish writeup-denied material.",
            citations=["rag:discord-writeups-disabled"],
            metadata={
                "labels": ["advisory"],
                "metadata": {"writeups_allowed": False},
            },
        )

        result = ContextSinkValidator().validate(
            "discord_notification",
            [envelope],
            known_rag_refs={"rag:discord-writeups-disabled"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:discord-writeups-disabled"])
        self.assertTrue(any("writeups_forbidden" in error for error in result.errors))

    def test_discord_notification_rejects_nested_truth_like_authority_on_model_summary(self) -> None:
        envelope = ContextEnvelope(
            ref="model:nested-confirmed-discord-notice",
            kind="model_summary",
            authority="derived",
            source_type="runtime_state",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="discord_notification",
            sink="discord_notification",
            content="Nested model summary authority must not notify as confirmed target truth.",
            citations=["evidence:http-banner"],
            metadata={
                "labels": ["advisory"],
                "source_refs": ["evidence:http-banner"],
                "metadata": {"authority": "confirmed"},
            },
        )

        result = ContextSinkValidator().validate(
            "discord_notification",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:nested-confirmed-discord-notice"])
        self.assertTrue(any("truth-like authority" in error for error in result.errors))

    def test_discord_notification_rejects_plural_nested_truth_like_authorities_on_model_summary(self) -> None:
        envelope = ContextEnvelope(
            ref="model:nested-confirmed-authorities-discord-notice",
            kind="model_summary",
            authority="derived",
            source_type="runtime_state",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="discord_notification",
            sink="discord_notification",
            content="Nested plural model summary authorities must not notify as confirmed target truth.",
            citations=["evidence:http-banner"],
            metadata={
                "labels": ["advisory"],
                "source_refs": ["evidence:http-banner"],
                "metadata": {"authorities": ["confirmed"]},
            },
        )

        result = ContextSinkValidator().validate(
            "discord_notification",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:nested-confirmed-authorities-discord-notice"])
        self.assertTrue(any("truth-like authority" in error for error in result.errors))

    def test_discord_notification_rejects_nested_non_authority_source_authority_record(self) -> None:
        envelope = ContextEnvelope(
            ref="model:nested-chat-approval-notice",
            kind="model_summary",
            authority="derived",
            source_type="runtime_state",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="discord_notification",
            sink="discord_notification",
            content="Nested chat approval metadata must not notify as an authority record.",
            citations=["evidence:http-banner"],
            metadata={
                "labels": ["advisory"],
                "source_refs": ["evidence:http-banner"],
                "metadata": {"kind": "approval", "source_type": "chat"},
            },
        )

        result = ContextSinkValidator().validate(
            "discord_notification",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:nested-chat-approval-notice"])
        self.assertTrue(any("non-authority source authority record" in error for error in result.errors))

    def test_discord_notification_rejects_plural_nested_non_authority_source_authorities(self) -> None:
        envelope = ContextEnvelope(
            ref="status:nested-chat-confirmed-authorities-notice",
            kind="test_status",
            authority="asserted",
            source_type="runtime_state",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="discord_notification",
            sink="discord_notification",
            content="Nested plural chat authorities must not notify as confirmed target truth.",
            citations=["evidence:http-banner"],
            metadata={
                "labels": ["advisory"],
                "source_refs": ["evidence:http-banner"],
                "metadata": {"source_types": ["chat"], "authorities": ["confirmed"]},
            },
        )

        result = ContextSinkValidator().validate(
            "discord_notification",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["status:nested-chat-confirmed-authorities-notice"])
        self.assertTrue(any("non-authority source authority record" in error for error in result.errors))

    def test_discord_notification_rejects_plural_nested_non_authority_source_authority_kinds(self) -> None:
        envelope = ContextEnvelope(
            ref="status:nested-chat-approval-kinds-notice",
            kind="test_status",
            authority="asserted",
            source_type="runtime_state",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="discord_notification",
            sink="discord_notification",
            content="Nested plural chat authority kinds must not notify as approval records.",
            citations=["evidence:http-banner"],
            metadata={
                "labels": ["advisory"],
                "source_refs": ["evidence:http-banner"],
                "metadata": {"source_types": ["chat"], "kinds": ["approval"]},
            },
        )

        result = ContextSinkValidator().validate(
            "discord_notification",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["status:nested-chat-approval-kinds-notice"])
        self.assertTrue(any("non-authority source authority record" in error for error in result.errors))

    def test_discord_notification_quarantines_nested_external_collaboration_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="model:nested-github-notice",
            kind="model_summary",
            authority="derived",
            source_type="runtime_state",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="discord_notification",
            sink="discord_notification",
            content="Nested GitHub source metadata must still require an external collaboration label.",
            citations=["evidence:http-banner"],
            metadata={
                "labels": ["derived"],
                "source_refs": ["evidence:http-banner"],
                "metadata": {"source_type": "github"},
            },
        )

        result = ContextSinkValidator().validate(
            "discord_notification",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["model:nested-github-notice"])
        self.assertTrue(any("requires external collaboration label" in error for error in result.errors))

    def test_discord_notification_quarantines_nested_advisory_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="status:nested-ai-output-notice",
            kind="test_status",
            authority="asserted",
            source_type="runtime_state",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="discord_notification",
            sink="discord_notification",
            content="Nested AI-output source metadata must still require an advisory notification label.",
            citations=["evidence:http-banner"],
            metadata={
                "source_refs": ["evidence:http-banner"],
                "metadata": {"source_type": "ai_output"},
            },
        )

        result = ContextSinkValidator().validate(
            "discord_notification",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["status:nested-ai-output-notice"])
        self.assertTrue(any("requires advisory or unverified label" in error for error in result.errors))

    def test_discord_notification_quarantines_plural_nested_derived_authorities(self) -> None:
        envelope = ContextEnvelope(
            ref="status:nested-derived-authorities-notice",
            kind="test_status",
            authority="asserted",
            source_type="runtime_state",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="discord_notification",
            sink="discord_notification",
            content="Nested plural derived authorities must still require an advisory notification label.",
            citations=["evidence:http-banner"],
            metadata={
                "source_refs": ["evidence:http-banner"],
                "metadata": {"authorities": ["derived"]},
            },
        )

        result = ContextSinkValidator().validate(
            "discord_notification",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["status:nested-derived-authorities-notice"])
        self.assertTrue(any("requires advisory or unverified label" in error for error in result.errors))

    def test_discord_notification_quarantines_plural_nested_advisory_kinds(self) -> None:
        envelope = ContextEnvelope(
            ref="status:nested-rag-kinds-notice",
            kind="test_status",
            authority="asserted",
            source_type="runtime_state",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="discord_notification",
            sink="discord_notification",
            content="Nested plural advisory kinds must still require an advisory notification label.",
            citations=["evidence:http-banner"],
            metadata={
                "source_refs": ["evidence:http-banner"],
                "metadata": {"kinds": ["rag"]},
            },
        )

        result = ContextSinkValidator().validate(
            "discord_notification",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["status:nested-rag-kinds-notice"])
        self.assertTrue(any("requires advisory or unverified label" in error for error in result.errors))

    def test_direct_discord_notification_quarantines_plural_nested_advisory_source_types(self) -> None:
        envelope = ContextEnvelope(
            ref="status:direct-nested-ai-output-notice",
            kind="test_status",
            authority="asserted",
            source_type="runtime_state",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="discord_notification",
            sink="discord_notification",
            content="Nested plural AI-output source metadata must still require an advisory notification label.",
            citations=["evidence:http-banner"],
            metadata={
                "source_refs": ["evidence:http-banner"],
                "metadata": {"source_types": ["ai_output"]},
            },
        )

        decision = validate_collaboration_sink(
            "discord_notification",
            envelope,
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertEqual(decision.action, "quarantine")
        self.assertIn("requires advisory or unverified label", decision.message)

    def test_discord_notification_rejects_generated_export_source_path(self) -> None:
        envelope = ContextEnvelope(
            ref="model:discord-export-path-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="discord_notification",
            sink="discord_notification",
            content="Generated export text must not loop into operator notification context.",
            citations=["evidence:http-banner"],
            metadata={
                "labels": ["advisory"],
                "source_file": "findings/notion/target-a/notion-export.md",
                "source_refs": ["evidence:http-banner"],
            },
        )

        result = ContextSinkValidator().validate(
            "discord_notification",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:discord-export-path-summary"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_discord_notification_rejects_generated_export_source_url(self) -> None:
        envelope = ContextEnvelope(
            ref="model:discord-export-url-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="discord_notification",
            sink="discord_notification",
            content="Generated export URLs must not loop into operator notification context.",
            citations=["evidence:http-banner"],
            metadata={
                "labels": ["advisory"],
                "source_url": "https://example.invalid/findings/notion/target-a/notion-export.md",
                "source_refs": ["evidence:http-banner"],
            },
        )

        result = ContextSinkValidator().validate(
            "discord_notification",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:discord-export-url-summary"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_discord_notification_rejects_context_restrictions_that_exclude_discord(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="note:prompt-only-discord-note",
                kind="operator_note",
                authority="asserted",
                source_type="manual_artifact",
                purpose="discord_notification",
                sink="discord_notification",
                content="Prompt-only operator notes must not be projected into Discord notifications.",
                citations=["note:prompt-only-discord-note"],
                valid_for=["prompt"],
                metadata={"valid_for": ["prompt"]},
            ),
            ContextEnvelope(
                ref="note:discord-denied-note",
                kind="operator_note",
                authority="asserted",
                source_type="manual_artifact",
                purpose="discord_notification",
                sink="discord_notification",
                content="Discord-denied operator notes must not be projected into Discord notifications.",
                citations=["note:discord-denied-note"],
                invalid_for=["discord_notification"],
                metadata={"invalid_for": ["discord_notification"]},
            ),
        ]

        result = ContextSinkValidator().validate("discord_notification", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["note:discord-denied-note", "note:prompt-only-discord-note"])
        self.assertTrue(any("valid_for excludes discord_notification" in error for error in result.errors))
        self.assertTrue(any("invalid_for excludes discord_notification" in error for error in result.errors))

    def test_github_issue_rejects_generated_export_source_path(self) -> None:
        envelope = ContextEnvelope(
            ref="github:export-path-failure-analysis",
            kind="failure_analysis",
            authority="advisory",
            source_type="failure_analysis",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="patch_planning",
            sink="github_issue",
            content="Generated export text must not become engineering ledger context.",
            citations=[],
            metadata={
                "context_type": "failure_analysis",
                "redacted": True,
                "source_file": "findings/notion/target-a/notion-export.md",
            },
        )

        result = ContextSinkValidator().validate("github_issue", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:export-path-failure-analysis"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_github_issue_rejects_nested_truth_like_authority(self) -> None:
        envelope = ContextEnvelope(
            ref="github:nested-confirmed-issue-projection",
            kind="github_ref",
            authority="asserted",
            source_type="github",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="patch_planning",
            sink="github_issue",
            content="Nested GitHub issue metadata must not project confirmed target-truth authority.",
            citations=["github:nested-confirmed-issue-projection"],
            metadata={
                "context_type": "failure_analysis",
                "metadata": {"authority": "confirmed"},
            },
        )

        result = ContextSinkValidator().validate("github_issue", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:nested-confirmed-issue-projection"])
        self.assertTrue(any("target authority" in error for error in result.errors))

    def test_github_issue_rejects_nested_unredacted_evidence_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="github:nested-evidence-leak",
            kind="github_ref",
            authority="asserted",
            source_type="github",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="patch_planning",
            sink="github_issue",
            content="Nested evidence refs must still require redaction before GitHub projection.",
            citations=["github:nested-evidence-leak"],
            metadata={
                "context_type": "failure_analysis",
                "metadata": {"evidence_refs": ["evidence:raw-request-response"]},
            },
        )

        result = ContextSinkValidator().validate("github_issue", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:nested-evidence-leak"])
        self.assertTrue(any("requires redacted evidence refs" in error for error in result.errors))

    def test_github_issue_rejects_nested_unredacted_evidence_ids(self) -> None:
        envelope = ContextEnvelope(
            ref="github:nested-evidence-id-leak",
            kind="github_ref",
            authority="asserted",
            source_type="github",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="patch_planning",
            sink="github_issue",
            content="Nested evidence ids must still require redaction before GitHub projection.",
            citations=["github:nested-evidence-id-leak"],
            metadata={
                "context_type": "failure_analysis",
                "metadata": {"evidence_ids": ["evidence:raw-request-response"]},
            },
        )

        result = ContextSinkValidator().validate("github_issue", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:nested-evidence-id-leak"])
        self.assertTrue(any("requires redacted evidence refs" in error for error in result.errors))

    def test_github_issue_rejects_nested_unsupported_context_type(self) -> None:
        envelope = ContextEnvelope(
            ref="github:nested-operator-intent-context",
            kind="github_ref",
            authority="asserted",
            source_type="github",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="patch_planning",
            sink="github_issue",
            content="Nested context type must not turn GitHub issue projection into authority context.",
            citations=["github:nested-operator-intent-context"],
            metadata={
                "context_type": "failure_analysis",
                "metadata": {"context_type": "operator_intent"},
            },
        )

        result = ContextSinkValidator().validate("github_issue", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:nested-operator-intent-context"])
        self.assertTrue(any("unsupported engineering issue context_type=operator_intent" in error for error in result.errors))

    def test_github_issue_rejects_plural_nested_unsupported_context_types(self) -> None:
        envelope = ContextEnvelope(
            ref="github:nested-operator-intent-context-types",
            kind="github_ref",
            authority="asserted",
            source_type="github",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="patch_planning",
            sink="github_issue",
            content="Nested plural context types must not turn GitHub issue projection into authority context.",
            citations=["github:nested-operator-intent-context-types"],
            metadata={
                "context_type": "failure_analysis",
                "metadata": {"context_types": ["operator_intent"]},
            },
        )

        result = ContextSinkValidator().validate("github_issue", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:nested-operator-intent-context-types"])
        self.assertTrue(any("unsupported engineering issue context_type=operator_intent" in error for error in result.errors))

    def test_github_issue_rejects_nested_unsupported_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="github:nested-ai-output-source",
            kind="github_ref",
            authority="asserted",
            source_type="github",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="patch_planning",
            sink="github_issue",
            content="Nested source type must not disguise raw model output as GitHub issue material.",
            citations=["github:nested-ai-output-source"],
            metadata={
                "context_type": "failure_analysis",
                "metadata": {"source_type": "ai_output"},
            },
        )

        result = ContextSinkValidator().validate("github_issue", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:nested-ai-output-source"])
        self.assertTrue(any("unsupported engineering issue source_type=ai_output" in error for error in result.errors))

    def test_github_issue_rejects_nested_evidence_kind(self) -> None:
        envelope = ContextEnvelope(
            ref="github:nested-evidence-kind",
            kind="github_ref",
            authority="asserted",
            source_type="github",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="patch_planning",
            sink="github_issue",
            content="Nested kind must not turn GitHub issue projection into evidence.",
            citations=["github:nested-evidence-kind"],
            metadata={
                "context_type": "failure_analysis",
                "metadata": {"kind": "evidence"},
            },
        )

        result = ContextSinkValidator().validate("github_issue", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:nested-evidence-kind"])
        self.assertTrue(any("target authority" in error for error in result.errors))

    def test_github_issue_rejects_plural_nested_evidence_kinds(self) -> None:
        envelope = ContextEnvelope(
            ref="github:nested-evidence-kinds",
            kind="github_ref",
            authority="asserted",
            source_type="github",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="patch_planning",
            sink="github_issue",
            content="Nested plural kinds must not turn GitHub issue projection into evidence.",
            citations=["github:nested-evidence-kinds"],
            metadata={
                "context_type": "failure_analysis",
                "metadata": {"kinds": ["evidence"]},
            },
        )

        result = ContextSinkValidator().validate("github_issue", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:nested-evidence-kinds"])
        self.assertTrue(any("target authority" in error for error in result.errors))

    def test_github_ledger_rejects_context_restrictions_that_exclude_ledger(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="github:prompt-only-ledger",
                kind="github_ref",
                authority="advisory",
                source_type="github",
                purpose="github_ledger",
                sink="github_ledger",
                content="Prompt-only GitHub context must not enter the durable GitHub ledger sink.",
                citations=[],
                valid_for=["prompt"],
                metadata={"valid_for": ["prompt"], "context_type": "engineering_context"},
            ),
            ContextEnvelope(
                ref="github:ledger-denied",
                kind="github_ref",
                authority="advisory",
                source_type="github",
                purpose="github_ledger",
                sink="github_ledger",
                content="GitHub-ledger-denied context must not enter the durable GitHub ledger sink.",
                citations=[],
                invalid_for=["github_ledger"],
                metadata={"invalid_for": ["github_ledger"], "context_type": "engineering_context"},
            ),
        ]

        result = ContextSinkValidator().validate("github_ledger", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:ledger-denied", "github:prompt-only-ledger"])
        self.assertTrue(any("valid_for excludes github_ledger" in error for error in result.errors))
        self.assertTrue(any("invalid_for excludes github_ledger" in error for error in result.errors))

    def test_github_ledger_rejects_generated_export_source_url(self) -> None:
        envelope = ContextEnvelope(
            ref="github:export-url-ledger",
            kind="github_ref",
            authority="advisory",
            source_type="github",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="github_ledger",
            sink="github_ledger",
            content="Generated export URLs must not enter the durable GitHub ledger.",
            citations=[],
            metadata={
                "context_type": "engineering_context",
                "source_url": "https://example.invalid/findings/notion/target-a/notion-export.md",
            },
        )

        result = ContextSinkValidator().validate("github_ledger", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:export-url-ledger"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_github_ledger_rejects_nested_generated_export_source_url(self) -> None:
        envelope = ContextEnvelope(
            ref="github:nested-export-url-ledger",
            kind="github_ref",
            authority="advisory",
            source_type="github",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="github_ledger",
            sink="github_ledger",
            content="Nested generated export URLs must not enter the durable GitHub ledger.",
            citations=[],
            metadata={
                "context_type": "engineering_context",
                "metadata": {
                    "source_url": "https://example.invalid/findings/notion/target-a/notion-export.md",
                },
            },
        )

        result = ContextSinkValidator().validate("github_ledger", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:nested-export-url-ledger"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_github_ledger_rejects_nested_sensitive_metadata_without_redaction(self) -> None:
        envelope = ContextEnvelope(
            ref="github:nested-sensitive-ledger",
            kind="github_ref",
            authority="advisory",
            source_type="github",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="github_ledger",
            sink="github_ledger",
            content="Nested sensitive flags must not enter the durable GitHub ledger unredacted.",
            citations=[],
            metadata={
                "context_type": "engineering_context",
                "metadata": {"contains_secret": True},
            },
        )

        result = ContextSinkValidator().validate("github_ledger", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:nested-sensitive-ledger"])
        self.assertTrue(any("sensitive target material requires redaction" in error for error in result.errors))

    def test_github_ledger_rejects_nested_evidence_refs_without_redaction(self) -> None:
        envelope = ContextEnvelope(
            ref="github:nested-evidence-refs-ledger",
            kind="github_ref",
            authority="advisory",
            source_type="github",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="github_ledger",
            sink="github_ledger",
            content="Nested evidence refs must not enter the durable GitHub ledger unredacted.",
            citations=[],
            metadata={
                "context_type": "engineering_context",
                "metadata": {"evidence_refs": ["evidence:http-banner"]},
            },
        )

        result = ContextSinkValidator().validate("github_ledger", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:nested-evidence-refs-ledger"])
        self.assertTrue(any("evidence refs require redaction" in error for error in result.errors))

    def test_github_ledger_rejects_masked_nested_evidence_refs_without_redaction(self) -> None:
        envelope = ContextEnvelope(
            ref="github:masked-nested-evidence-refs-ledger",
            kind="github_ref",
            authority="advisory",
            source_type="github",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="github_ledger",
            sink="github_ledger",
            content="Top-level empty evidence refs must not mask nested evidence refs.",
            citations=[],
            metadata={
                "context_type": "engineering_context",
                "evidence_refs": [],
                "metadata": {"evidence_refs": ["evidence:http-banner"]},
            },
        )

        result = ContextSinkValidator().validate("github_ledger", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:masked-nested-evidence-refs-ledger"])
        self.assertTrue(any("evidence refs require redaction" in error for error in result.errors))

    def test_github_ledger_rejects_masked_nested_confirmed_finding_status(self) -> None:
        envelope = ContextEnvelope(
            ref="github:masked-nested-confirmed-finding",
            kind="github_ref",
            authority="advisory",
            source_type="github",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="github_ledger",
            sink="github_ledger",
            content="Top-level draft status must not mask nested confirmed finding status.",
            citations=[],
            metadata={
                "context_type": "engineering_context",
                "finding_status": "draft",
                "metadata": {"finding_status": "confirmed"},
            },
        )

        result = ContextSinkValidator().validate("github_ledger", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:masked-nested-confirmed-finding"])
        self.assertTrue(any("confirmed finding" in error for error in result.errors))

    def test_ctfd_registry_rejects_context_restrictions_that_exclude_registry(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="ctfd:prompt-only-challenge",
                kind="challenge_metadata",
                authority="advisory",
                source_type="ctfd",
                purpose="ctfd_registry",
                sink="ctfd_registry",
                content="Prompt-only challenge metadata must not enter the durable CTFd registry sink.",
                citations=["ctfd:challenge-1"],
                valid_for=["prompt"],
                metadata={"valid_for": ["prompt"], "record_type": "challenge_metadata"},
            ),
            ContextEnvelope(
                ref="ctfd:registry-denied-challenge",
                kind="challenge_metadata",
                authority="advisory",
                source_type="ctfd",
                purpose="ctfd_registry",
                sink="ctfd_registry",
                content="CTFd-registry-denied metadata must not enter the durable CTFd registry sink.",
                citations=["ctfd:challenge-2"],
                invalid_for=["ctfd_registry"],
                metadata={"invalid_for": ["ctfd_registry"], "record_type": "challenge_metadata"},
            ),
        ]

        result = ContextSinkValidator().validate("ctfd_registry", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:prompt-only-challenge", "ctfd:registry-denied-challenge"])
        self.assertTrue(any("valid_for excludes ctfd_registry" in error for error in result.errors))
        self.assertTrue(any("invalid_for excludes ctfd_registry" in error for error in result.errors))

    def test_ctfd_registry_rejects_generated_export_source_url(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:registry-export-url",
            kind="challenge_metadata",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_registry",
            sink="ctfd_registry",
            content="Generated export URLs must not enter the durable CTFd registry.",
            citations=["ctfd:challenge-1"],
            metadata={
                "record_type": "challenge_metadata",
                "source_url": "https://example.invalid/findings/notion/target-a/notion-export.md",
            },
        )

        result = ContextSinkValidator().validate("ctfd_registry", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:registry-export-url"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_ctfd_registry_rejects_nested_generated_export_source_url(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:registry-nested-export-url",
            kind="challenge_metadata",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_registry",
            sink="ctfd_registry",
            content="Nested generated export URLs must not enter the durable CTFd registry.",
            citations=["ctfd:challenge-1"],
            metadata={
                "record_type": "challenge_metadata",
                "metadata": {
                    "source_url": "https://example.invalid/findings/notion/target-a/notion-export.md",
                },
            },
        )

        result = ContextSinkValidator().validate("ctfd_registry", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:registry-nested-export-url"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_ctfd_registry_rejects_nested_truth_like_authority(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:registry-nested-confirmed-authority",
            kind="challenge_metadata",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_registry",
            sink="ctfd_registry",
            content="Nested metadata authority must not turn CTFd challenge text into target truth.",
            citations=["ctfd:challenge-1"],
            metadata={
                "record_type": "challenge_metadata",
                "metadata": {"authority": "confirmed"},
            },
        )

        result = ContextSinkValidator().validate("ctfd_registry", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:registry-nested-confirmed-authority"])
        self.assertTrue(any("truth-like authority" in error for error in result.errors))

    def test_ctfd_registry_rejects_nested_plural_truth_like_authorities(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:registry-nested-confirmed-authorities",
            kind="challenge_metadata",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_registry",
            sink="ctfd_registry",
            content="Nested plural metadata authorities must not turn CTFd challenge text into target truth.",
            citations=["ctfd:challenge-1"],
            metadata={
                "record_type": "challenge_metadata",
                "metadata": {"authorities": ["confirmed"]},
            },
        )

        result = ContextSinkValidator().validate("ctfd_registry", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:registry-nested-confirmed-authorities"])
        self.assertTrue(any("truth-like authority" in error for error in result.errors))

    def test_ctfd_registry_rejects_nested_authority_kind(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:registry-nested-evidence-kind",
            kind="challenge_metadata",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_registry",
            sink="ctfd_registry",
            content="Nested metadata kind must not turn CTFd challenge text into evidence.",
            citations=["ctfd:challenge-1"],
            metadata={
                "record_type": "challenge_metadata",
                "metadata": {"kind": "evidence"},
            },
        )

        result = ContextSinkValidator().validate("ctfd_registry", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:registry-nested-evidence-kind"])
        self.assertTrue(any("must not create evidence" in error for error in result.errors))

    def test_ctfd_registry_rejects_nested_plural_authority_kinds(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:registry-nested-evidence-kinds",
            kind="challenge_metadata",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_registry",
            sink="ctfd_registry",
            content="Nested plural metadata kinds must not turn CTFd challenge text into evidence.",
            citations=["ctfd:challenge-1"],
            metadata={
                "record_type": "challenge_metadata",
                "metadata": {"kinds": ["evidence"]},
            },
        )

        result = ContextSinkValidator().validate("ctfd_registry", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:registry-nested-evidence-kinds"])
        self.assertTrue(any("must not create evidence" in error for error in result.errors))

    def test_ctfd_registry_rejects_masked_nested_unsupported_record_type(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:registry-nested-unsupported-record-type",
            kind="challenge_metadata",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_registry",
            sink="ctfd_registry",
            content="Top-level challenge metadata must not mask a nested unsupported CTFd record type.",
            citations=["ctfd:challenge-1"],
            metadata={
                "record_type": "challenge_metadata",
                "metadata": {"record_type": "operator_intent"},
            },
        )

        result = ContextSinkValidator().validate("ctfd_registry", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:registry-nested-unsupported-record-type"])
        self.assertTrue(any("requires challenge or scoreboard record_type" in error for error in result.errors))

    def test_ctfd_registry_rejects_plural_nested_unsupported_record_types(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:registry-nested-unsupported-record-types",
            kind="challenge_metadata",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_registry",
            sink="ctfd_registry",
            content="Top-level challenge metadata must not mask nested plural unsupported CTFd record types.",
            citations=["ctfd:challenge-1"],
            metadata={
                "record_type": "challenge_metadata",
                "metadata": {"record_types": ["operator_intent"]},
            },
        )

        result = ContextSinkValidator().validate("ctfd_registry", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:registry-nested-unsupported-record-types"])
        self.assertTrue(any("requires challenge or scoreboard record_type" in error for error in result.errors))

    def test_ctfd_sinks_reject_masked_nested_non_ctfd_source_type(self) -> None:
        registry_envelope = ContextEnvelope(
            ref="ctfd:registry-nested-github-source-type",
            kind="challenge_metadata",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_registry",
            sink="ctfd_registry",
            content="Top-level CTFd source type must not mask nested GitHub challenge metadata.",
            citations=["ctfd:challenge-1"],
            metadata={
                "record_type": "challenge_metadata",
                "source_type": "ctfd",
                "metadata": {"source_type": "github"},
            },
        )
        submission_envelope = ContextEnvelope(
            ref="ctfd:submission-nested-github-source-type",
            kind="ctfd_submission",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_submission",
            sink="ctfd_submission",
            content="Top-level CTFd source type must not mask nested GitHub submission metadata.",
            citations=["ctfd:submission-1"],
            metadata={
                "record_type": "submission_result",
                "source_type": "ctfd",
                "metadata": {"source_type": "github"},
            },
        )

        registry_result = ContextSinkValidator().validate("ctfd_registry", [registry_envelope])
        submission_result = ContextSinkValidator().validate("ctfd_submission", [submission_envelope])

        self.assertFalse(registry_result.valid)
        self.assertEqual(registry_result.accepted_refs, [])
        self.assertEqual(registry_result.rejected_refs, ["ctfd:registry-nested-github-source-type"])
        self.assertTrue(any("accepts only CTFd source material" in error for error in registry_result.errors))

        self.assertFalse(submission_result.valid)
        self.assertEqual(submission_result.accepted_refs, [])
        self.assertEqual(submission_result.rejected_refs, ["ctfd:submission-nested-github-source-type"])
        self.assertTrue(any("accepts only CTFd source material" in error for error in submission_result.errors))

    def test_ctfd_sinks_reject_nested_non_ctfd_citation_metadata(self) -> None:
        registry_envelope = ContextEnvelope(
            ref="ctfd:registry-nested-github-citation",
            kind="challenge_metadata",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_registry",
            sink="ctfd_registry",
            content="Nested GitHub citations must not support CTFd registry metadata.",
            citations=["ctfd:challenge-1"],
            metadata={
                "record_type": "challenge_metadata",
                "metadata": {"citations": ["github:issue-1"]},
            },
        )
        submission_envelope = ContextEnvelope(
            ref="ctfd:submission-nested-github-citation",
            kind="ctfd_submission",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_submission",
            sink="ctfd_submission",
            content="Nested GitHub citations must not support CTFd submission metadata.",
            citations=["ctfd:submission-1"],
            metadata={
                "record_type": "submission_result",
                "metadata": {"citations": ["github:issue-1"]},
            },
        )

        registry_result = ContextSinkValidator().validate("ctfd_registry", [registry_envelope])
        submission_result = ContextSinkValidator().validate("ctfd_submission", [submission_envelope])

        self.assertFalse(registry_result.valid)
        self.assertEqual(registry_result.accepted_refs, [])
        self.assertEqual(registry_result.rejected_refs, ["ctfd:registry-nested-github-citation"])
        self.assertTrue(any("non-CTFd citation support" in error for error in registry_result.errors))

        self.assertFalse(submission_result.valid)
        self.assertEqual(submission_result.accepted_refs, [])
        self.assertEqual(submission_result.rejected_refs, ["ctfd:submission-nested-github-citation"])
        self.assertTrue(any("non-CTFd citation support" in error for error in submission_result.errors))

    def test_ctfd_sinks_reject_nested_non_ctfd_citation_ref_metadata(self) -> None:
        registry_envelope = ContextEnvelope(
            ref="ctfd:registry-nested-github-citation-ref",
            kind="challenge_metadata",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_registry",
            sink="ctfd_registry",
            content="Nested GitHub citation refs must not support CTFd registry metadata.",
            citations=["ctfd:challenge-1"],
            metadata={
                "record_type": "challenge_metadata",
                "metadata": {"citation_ref": "github:issue-1"},
            },
        )
        submission_envelope = ContextEnvelope(
            ref="ctfd:submission-nested-github-citation-ref",
            kind="ctfd_submission",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_submission",
            sink="ctfd_submission",
            content="Nested GitHub citation refs must not support CTFd submission metadata.",
            citations=["ctfd:submission-1"],
            metadata={
                "record_type": "submission_result",
                "metadata": {"citation_ref": "github:issue-1"},
            },
        )

        registry_result = ContextSinkValidator().validate("ctfd_registry", [registry_envelope])
        submission_result = ContextSinkValidator().validate("ctfd_submission", [submission_envelope])

        self.assertFalse(registry_result.valid)
        self.assertEqual(registry_result.accepted_refs, [])
        self.assertEqual(registry_result.rejected_refs, ["ctfd:registry-nested-github-citation-ref"])
        self.assertTrue(any("non-CTFd citation support" in error for error in registry_result.errors))

        self.assertFalse(submission_result.valid)
        self.assertEqual(submission_result.accepted_refs, [])
        self.assertEqual(submission_result.rejected_refs, ["ctfd:submission-nested-github-citation-ref"])
        self.assertTrue(any("non-CTFd citation support" in error for error in submission_result.errors))

    def test_ctfd_submission_rejects_context_restrictions_that_exclude_submission(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="ctfd:prompt-only-submission",
                kind="submission_result",
                authority="advisory",
                source_type="ctfd",
                purpose="ctfd_submission",
                sink="ctfd_submission",
                content="Prompt-only submission metadata must not enter the durable CTFd submission sink.",
                citations=["ctfd:submission-1"],
                valid_for=["prompt"],
                metadata={"valid_for": ["prompt"], "record_type": "submission_result"},
            ),
            ContextEnvelope(
                ref="ctfd:submission-denied-result",
                kind="submission_result",
                authority="advisory",
                source_type="ctfd",
                purpose="ctfd_submission",
                sink="ctfd_submission",
                content="CTFd-submission-denied metadata must not enter the durable CTFd submission sink.",
                citations=["ctfd:submission-2"],
                invalid_for=["ctfd_submission"],
                metadata={"invalid_for": ["ctfd_submission"], "record_type": "submission_result"},
            ),
        ]

        result = ContextSinkValidator().validate("ctfd_submission", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:prompt-only-submission", "ctfd:submission-denied-result"])
        self.assertTrue(any("valid_for excludes ctfd_submission" in error for error in result.errors))
        self.assertTrue(any("invalid_for excludes ctfd_submission" in error for error in result.errors))

    def test_ctfd_submission_rejects_generated_export_source_url(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:submission-export-url",
            kind="submission_result",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_submission",
            sink="ctfd_submission",
            content="Generated export URLs must not enter the durable CTFd submission sink.",
            citations=["ctfd:submission-1"],
            metadata={
                "record_type": "submission_result",
                "source_url": "https://example.invalid/findings/notion/target-a/notion-export.md",
            },
        )

        result = ContextSinkValidator().validate("ctfd_submission", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:submission-export-url"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_ctfd_submission_rejects_nested_generated_export_source_url(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:submission-nested-export-url",
            kind="submission_result",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_submission",
            sink="ctfd_submission",
            content="Nested generated export URLs must not enter the durable CTFd submission sink.",
            citations=["ctfd:submission-1"],
            metadata={
                "record_type": "submission_result",
                "metadata": {
                    "source_url": "https://example.invalid/findings/notion/target-a/notion-export.md",
                },
            },
        )

        result = ContextSinkValidator().validate("ctfd_submission", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:submission-nested-export-url"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_ctfd_submission_rejects_nested_flag_submission_without_solve_intent(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:submission-nested-flag",
            kind="submission_result",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_submission",
            sink="ctfd_submission",
            content="Nested CTFd flag submission markers must still require solve intent.",
            citations=["ctfd:submission-1"],
            metadata={
                "record_type": "submission_result",
                "metadata": {"submission_type": "flag"},
            },
        )

        result = ContextSinkValidator().validate("ctfd_submission", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:submission-nested-flag"])
        self.assertTrue(any("requires ctf solve intent" in error for error in result.errors))

    def test_ctfd_submission_rejects_masked_nested_flag_submission_without_solve_intent(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:submission-masked-nested-flag",
            kind="submission_result",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_submission",
            sink="ctfd_submission",
            content="Top-level submission type must not mask a nested flag submission marker.",
            citations=["ctfd:submission-1"],
            metadata={
                "record_type": "submission_result",
                "submission_type": "submission_result",
                "metadata": {"submission_type": "flag"},
            },
        )

        result = ContextSinkValidator().validate("ctfd_submission", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:submission-masked-nested-flag"])
        self.assertTrue(any("requires ctf solve intent" in error for error in result.errors))

    def test_ctfd_submission_rejects_plural_nested_flag_submission_without_solve_intent(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:submission-nested-flag-types",
            kind="submission_result",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_submission",
            sink="ctfd_submission",
            content="Nested plural CTFd flag submission markers must still require solve intent.",
            citations=["ctfd:submission-1"],
            metadata={
                "record_type": "submission_result",
                "submission_type": "submission_result",
                "metadata": {"submission_types": ["flag_submission"]},
            },
        )

        result = ContextSinkValidator().validate("ctfd_submission", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:submission-nested-flag-types"])
        self.assertTrue(any("requires ctf solve intent" in error for error in result.errors))

    def test_ctfd_submission_rejects_masked_nested_recon_only_intent_for_flag_submission(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:submission-masked-nested-recon-only-intent",
            kind="submission_result",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_submission",
            sink="ctfd_submission",
            content="Top-level solve intent must not mask a nested recon-only flag submission intent.",
            citations=["ctfd:submission-1"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "record_type": "submission_result",
                "submission_type": "flag",
                "metadata": {"active_intent": "recon_only"},
            },
        )

        result = ContextSinkValidator().validate("ctfd_submission", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:submission-masked-nested-recon-only-intent"])
        self.assertTrue(any("requires ctf solve intent" in error for error in result.errors))

    def test_ctfd_submission_rejects_plural_nested_recon_only_intents_for_flag_submission(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:submission-masked-nested-recon-only-intents",
            kind="submission_result",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_submission",
            sink="ctfd_submission",
            content="Top-level solve intent must not mask nested plural recon-only flag submission intents.",
            citations=["ctfd:submission-1"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "record_type": "submission_result",
                "submission_type": "flag",
                "metadata": {"active_intents": ["recon_only"]},
            },
        )

        result = ContextSinkValidator().validate("ctfd_submission", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:submission-masked-nested-recon-only-intents"])
        self.assertTrue(any("requires ctf solve intent" in error for error in result.errors))

    def test_prompt_sink_rejects_nested_ai_summary_source_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="model:nested-source-ref-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Nested provenance must not hide unsupported source references.",
            citations=["evidence:http-banner"],
            metadata={
                "metadata": {
                    "source_refs": ["evidence:http-banner", "github:issue-42"],
                },
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
            },
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:nested-source-ref-summary"])
        self.assertTrue(any("unsupported source_refs" in error for error in result.errors))

    def test_prompt_sink_rejects_rag_with_unsupported_source_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:prompt-unsupported-source-refs",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="planner",
            sink="prompt",
            content="RAG advisory prompt context must not hide unsupported provenance.",
            citations=["rag:prompt-unsupported-source-refs"],
            metadata={"source_refs": ["github:issue-42"]},
        )

        result = ContextSinkValidator().validate("prompt", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:prompt-unsupported-source-refs"])
        self.assertTrue(any("unsupported source_refs" in error for error in result.errors))

    def test_prompt_sink_rejects_masked_nested_non_advisory_rag_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:prompt-masked-model-source",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="planner",
            sink="prompt",
            content="Top-level advisory source type must not mask nested model provenance.",
            citations=["rag:prompt-masked-model-source"],
            metadata={
                "metadata": {
                    "source_type": "ai_output",
                },
            },
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [envelope],
            known_rag_refs={"rag:prompt-masked-model-source"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:prompt-masked-model-source"])
        self.assertTrue(any("non_advisory_rag_source" in error for error in result.errors))
        self.assertTrue(any("source_type=ai_output" in error for error in result.errors))

    def test_prompt_sink_rejects_plural_nested_non_advisory_rag_source_types(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:prompt-plural-masked-model-source",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="planner",
            sink="prompt",
            content="Top-level advisory source type must not mask plural nested model provenance.",
            citations=["rag:prompt-plural-masked-model-source"],
            metadata={
                "metadata": {
                    "source_types": ["ai_output"],
                },
            },
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [envelope],
            known_rag_refs={"rag:prompt-plural-masked-model-source"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:prompt-plural-masked-model-source"])
        self.assertTrue(any("non_advisory_rag_source" in error for error in result.errors))
        self.assertTrue(any("source_type=ai_output" in error for error in result.errors))

    def test_prompt_sink_rejects_rag_with_unresolved_source_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:prompt-unresolved-source-refs",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="operator_answer",
            sink="prompt",
            content="Prompt RAG context must not cite unresolved evidence provenance.",
            citations=["rag:prompt-unresolved-source-refs", "evidence:missing-banner"],
            metadata={"source_refs": ["evidence:missing-banner"]},
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [envelope],
            known_evidence_refs=set(),
            known_rag_refs={"rag:prompt-unresolved-source-refs"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:prompt-unresolved-source-refs"])
        self.assertTrue(any("unresolved evidence citation" in error for error in result.errors))

    def test_prompt_sink_rejects_masked_nested_non_evidence_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="evidence:masked-model-prompt-proof",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            purpose="planner",
            sink="prompt",
            content="Top-level evidence source type must not mask nested model provenance.",
            citations=["evidence:masked-model-prompt-proof"],
            metadata={
                "metadata": {
                    "source_type": "ai_output",
                },
            },
        )

        result = ContextSinkValidator().validate("prompt", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["evidence:masked-model-prompt-proof"])
        self.assertTrue(any("source_type=ai_output" in error for error in result.errors))

    def test_evidence_sink_rejects_rag_cited_evidence_records(self) -> None:
        envelope = ContextEnvelope(
            ref="evidence:rag-backed-service",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            purpose="evidence_review",
            sink="evidence",
            content="A RAG-only service claim must not become observed evidence.",
            citations=["rag:service-claim"],
        )

        result = ContextSinkValidator().validate("evidence", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["evidence:rag-backed-service"])
        self.assertTrue(any("rag citation" in error for error in result.errors))

    def test_evidence_sink_rejects_masked_nested_non_evidence_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="evidence:masked-model-source",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            purpose="evidence_review",
            sink="evidence",
            content="Top-level evidence source type must not mask nested model provenance.",
            citations=["evidence:masked-model-source"],
            metadata={
                "metadata": {
                    "source_type": "ai_output",
                },
            },
        )

        result = ContextSinkValidator().validate("evidence", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["evidence:masked-model-source"])
        self.assertTrue(any("source_type=ai_output" in error for error in result.errors))

    def test_evidence_sink_rejects_non_evidence_citation_support(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="evidence:model-backed",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                purpose="evidence_review",
                sink="evidence",
                content="Model summary support must not become observed evidence.",
                citations=["model:summary"],
            ),
            ContextEnvelope(
                ref="evidence:github-backed",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                purpose="evidence_review",
                sink="evidence",
                content="GitHub issue support must not become observed evidence.",
                citations=["github:issue-1"],
            ),
            ContextEnvelope(
                ref="evidence:notion-backed",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                purpose="evidence_review",
                sink="evidence",
                content="Notion note support must not become observed evidence.",
                citations=["notion:note-1"],
            ),
            ContextEnvelope(
                ref="evidence:ctfd-backed",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                purpose="evidence_review",
                sink="evidence",
                content="CTFd challenge prose support must not become observed evidence.",
                citations=["ctfd:challenge-1"],
            ),
            ContextEnvelope(
                ref="evidence:chat-backed",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                purpose="evidence_review",
                sink="evidence",
                content="Chat support must not become observed evidence.",
                citations=["chat:operator-context"],
            ),
            ContextEnvelope(
                ref="evidence:self-backed",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                purpose="evidence_review",
                sink="evidence",
                content="Evidence-supported evidence remains acceptable.",
                citations=["evidence:self-backed"],
            ),
        ]

        result = ContextSinkValidator().validate("evidence", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["evidence:self-backed"])
        self.assertEqual(
            result.rejected_refs,
            [
                "evidence:chat-backed",
                "evidence:ctfd-backed",
                "evidence:github-backed",
                "evidence:model-backed",
                "evidence:notion-backed",
            ],
        )
        self.assertTrue(any("non-evidence citation support" in error for error in result.errors))

    def test_evidence_sink_resolves_human_readable_known_evidence_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="evidence:service-summary",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            purpose="evidence_review",
            sink="evidence",
            content="Evidence records may cite prior observed evidence records by canonical ref.",
            citations=["evidence:http-banner"],
        )

        result = ContextSinkValidator().validate(
            "evidence",
            [envelope],
            known_evidence_refs={"Evidence:http-banner"},
        )

        self.assertTrue(result.valid)
        self.assertEqual(result.accepted_refs, ["evidence:service-summary"])
        self.assertEqual(result.rejected_refs, [])

    def test_task_metadata_sink_rejects_profile_label_as_executable_permission(self) -> None:
        envelope = ContextEnvelope(
            ref="task:credential-validation",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            purpose="task_generation",
            sink="task_metadata",
            content="Validate captured credentials because the profile is hack_the_box.",
            citations=["policy_decision:profile-label", "evidence:credential-artifact"],
            metadata={
                "active_intent": "recon_only",
                "engagement_profile": "hack_the_box",
                "action_class": "credential_validation",
                "creates_executable_task": True,
                "permission_source": "profile_label",
                "supporting_evidence_refs": ["evidence:credential-artifact"],
            },
        )

        result = ContextSinkValidator().validate("task_metadata", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.rejected_refs, ["task:credential-validation"])
        self.assertTrue(any("profile label" in error for error in result.errors))

    def test_task_metadata_sink_rejects_nested_executable_action_under_recon_only(self) -> None:
        envelope = ContextEnvelope(
            ref="task:nested-recon-only-exploit",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Executable action metadata must not be hidden from recon-only task gates.",
            citations=["policy_decision:recon-only", "evidence:service-banner"],
            metadata={
                "metadata": {
                    "active_intent": "recon_only",
                    "action_class": "exploit_execution",
                    "current_target_id": "target-a",
                    "current_active_generation_id": "generation:2",
                    "supporting_evidence_refs": ["evidence:service-banner"],
                },
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:service-banner"},
            known_policy_decision_refs={"policy_decision:recon-only"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:nested-recon-only-exploit"])
        self.assertTrue(any("exploit_execution under recon_only" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_executable_action_under_recon_only(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-recon-only-exploit",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level action metadata must not mask a nested exploit action under recon-only intent.",
            citations=["policy_decision:recon-only", "evidence:service-banner"],
            metadata={
                "active_intent": "recon_only",
                "action_class": "tool_execution",
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:service-banner"],
                "metadata": {"action_class": "exploit_execution"},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:service-banner"},
            known_policy_decision_refs={"policy_decision:recon-only"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-recon-only-exploit"])
        self.assertTrue(any("exploit_execution under recon_only" in error for error in result.errors))

    def test_task_metadata_sink_rejects_plural_nested_executable_actions_under_recon_only(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-recon-only-action-classes",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level action metadata must not mask nested plural exploit actions under recon-only intent.",
            citations=["policy_decision:recon-only", "evidence:service-banner"],
            metadata={
                "active_intent": "recon_only",
                "action_class": "tool_execution",
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:service-banner"],
                "metadata": {"action_classes": ["exploit_execution"]},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:service-banner"},
            known_policy_decision_refs={"policy_decision:recon-only"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-recon-only-action-classes"])
        self.assertTrue(any("exploit_execution under recon_only" in error for error in result.errors))

    def test_task_metadata_sink_rejects_plural_nested_recon_only_intents_for_executable_action(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-recon-only-intents-exploit",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level assisted intent must not mask nested plural recon-only task intent.",
            citations=["policy_decision:recon-only", "evidence:service-banner"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "exploit_execution",
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:service-banner"],
                "metadata": {"active_intents": ["recon_only"]},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:service-banner"},
            known_policy_decision_refs={"policy_decision:recon-only"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-recon-only-intents-exploit"])
        self.assertTrue(any("exploit_execution under recon_only" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_unresolved_supporting_evidence(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-unresolved-supporting-evidence",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level supporting evidence must not mask a nested fabricated evidence ref.",
            citations=["policy_decision:assisted-lab", "evidence:service-banner"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:service-banner"],
                "metadata": {"supporting_evidence_refs": ["evidence:made-up"]},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:service-banner"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-unresolved-supporting-evidence"])
        self.assertTrue(any("unresolved supporting evidence refs" in error for error in result.errors))
        self.assertTrue(any("evidence:made-up" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_singular_unresolved_supporting_evidence(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-singular-unresolved-supporting-evidence",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level supporting evidence must not mask a nested singular fabricated evidence ref.",
            citations=["policy_decision:assisted-lab", "evidence:service-banner"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:service-banner"],
                "metadata": {"supporting_evidence_ref": "evidence:made-up"},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:service-banner"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-singular-unresolved-supporting-evidence"])
        self.assertTrue(any("unresolved supporting evidence refs" in error for error in result.errors))
        self.assertTrue(any("evidence:made-up" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_out_of_scope_task(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-out-of-scope",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level scope metadata must not mask a nested out-of-scope executable task.",
            citations=["policy_decision:assisted-lab", "evidence:service-banner"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:service-banner"],
                "in_scope": True,
                "metadata": {"in_scope": False},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:service-banner"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-out-of-scope"])
        self.assertTrue(any("out-of-scope executable task" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_plural_falsey_scope(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-plural-falsey-scope",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level scope metadata must not mask nested plural falsey in-scope values.",
            citations=["policy_decision:assisted-lab", "evidence:service-banner"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:service-banner"],
                "in_scope": True,
                "metadata": {"in_scopes": [False]},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:service-banner"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-plural-falsey-scope"])
        self.assertTrue(any("out-of-scope executable task" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_plural_scope_status(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-plural-scope-status",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level scope metadata must not mask nested plural out-of-scope statuses.",
            citations=["policy_decision:assisted-lab", "evidence:service-banner"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:service-banner"],
                "in_scope": True,
                "metadata": {"scope_statuses": ["out_of_scope"]},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:service-banner"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-plural-scope-status"])
        self.assertTrue(any("out-of-scope executable task" in error for error in result.errors))

    def test_task_metadata_sink_rejects_writeup_derived_executable_authority(self) -> None:
        envelope = ContextEnvelope(
            ref="task:writeup-exploit-step",
            kind="candidate_task",
            authority="asserted",
            source_type="writeup",
            target_id="target-a",
            purpose="task_generation",
            sink="task_metadata",
            content="Run the exploit step because the writeup says it is the path forward.",
            citations=["policy_decision:assisted-lab", "evidence:observed-service"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "exploit_validation",
                "creates_executable_task": True,
                "permission_basis": "writeup",
                "supporting_evidence_refs": ["evidence:observed-service"],
            },
        )

        result = ContextSinkValidator().validate("task_metadata", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.rejected_refs, ["task:writeup-exploit-step"])
        self.assertTrue(any("writeup-derived action authority" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_writeup_action_authority(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-writeup-authority",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level permission basis must not mask nested writeup action authority.",
            citations=["policy_decision:assisted-lab", "evidence:observed-service"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "exploit_validation",
                "creates_executable_task": True,
                "permission_basis": "tool_output",
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:observed-service"],
                "metadata": {"permission_basis": "writeup"},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:observed-service"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-writeup-authority"])
        self.assertTrue(any("writeup-derived action authority" in error for error in result.errors))

    def test_task_metadata_sink_rejects_plural_nested_writeup_action_authorities(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-writeup-authorities",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level permission basis must not mask plural nested writeup action authority.",
            citations=["policy_decision:assisted-lab", "evidence:observed-service"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "exploit_validation",
                "creates_executable_task": True,
                "permission_basis": "tool_output",
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:observed-service"],
                "metadata": {"permission_bases": ["writeup"]},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:observed-service"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-writeup-authorities"])
        self.assertTrue(any("writeup-derived action authority" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_writeup_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-writeup-source-type",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level source type must not mask nested writeup-derived task authority.",
            citations=["policy_decision:assisted-lab", "evidence:observed-service"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "exploit_validation",
                "creates_executable_task": True,
                "source_type": "tool_output",
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:observed-service"],
                "metadata": {"source_type": "writeup"},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:observed-service"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-writeup-source-type"])
        self.assertTrue(any("writeup-derived action authority" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_ctfd_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-ctfd-source-type",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level source type must not mask nested CTFd task authority.",
            citations=["policy_decision:assisted-lab", "evidence:observed-service"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "creates_executable_task": True,
                "source_type": "tool_output",
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:observed-service"],
                "metadata": {"source_type": "ctfd"},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:observed-service"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-ctfd-source-type"])
        self.assertTrue(any("ctfd executable task authority" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_collaboration_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-collaboration-source-type",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level source type must not mask nested collaboration task authority.",
            citations=["policy_decision:assisted-lab", "evidence:observed-service"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "creates_executable_task": True,
                "source_type": "tool_output",
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:observed-service"],
                "metadata": {"source_type": "github"},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:observed-service"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-collaboration-source-type"])
        self.assertTrue(any("collaboration executable task authority" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_advisory_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-advisory-source-type",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level source type must not mask nested advisory task permission.",
            citations=["policy_decision:assisted-lab", "evidence:observed-service"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "creates_executable_task": True,
                "source_type": "tool_output",
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:observed-service"],
                "metadata": {"source_type": "ai_output"},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:observed-service"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-advisory-source-type"])
        self.assertTrue(any("advisory executable permission source" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_profile_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-profile-source-type",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level source type must not mask nested scope profile task permission.",
            citations=["policy_decision:assisted-lab", "evidence:observed-service"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "creates_executable_task": True,
                "source_type": "tool_output",
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:observed-service"],
                "metadata": {"source_type": "scope_profile"},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:observed-service"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-profile-source-type"])
        self.assertTrue(any("profile label as executable permission" in error for error in result.errors))

    def test_task_metadata_sink_rejects_nested_vuln_intel_source_type_under_recon_only(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-vuln-intel-recon-only",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level tool output must not mask nested vuln intel task source under recon-only.",
            citations=["policy_decision:recon-block", "evidence:observed-service"],
            metadata={
                "active_intent": "recon_only",
                "action_class": "tool_execution",
                "creates_executable_task": True,
                "source_type": "tool_output",
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:observed-service"],
                "metadata": {"source_type": "vuln_intel"},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:observed-service"},
            known_policy_decision_refs={"policy_decision:recon-block"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-vuln-intel-recon-only"])
        self.assertTrue(any("vuln_intel executable action under recon_only" in error for error in result.errors))

    def test_task_metadata_sink_rejects_stale_generation_executable_task(self) -> None:
        envelope = ContextEnvelope(
            ref="task:old-generation-service-check",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:1",
            purpose="task_generation",
            sink="task_metadata",
            content="Probe a service observed only during an old active-IP generation.",
            citations=["policy_decision:assisted-lab", "evidence:old-service"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "creates_executable_task": True,
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:old-service"],
            },
        )

        result = ContextSinkValidator().validate("task_metadata", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.rejected_refs, ["task:old-generation-service-check"])
        self.assertTrue(any("stale generation" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_stale_generation(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-stale-generation",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level generation metadata must not mask a nested stale generation marker.",
            citations=["policy_decision:assisted-lab", "evidence:service-banner"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "creates_executable_task": True,
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:service-banner"],
                "metadata": {"current_active_generation_id": "generation:1"},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:service-banner"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-stale-generation"])
        self.assertTrue(any("stale generation" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_plural_current_generation(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-plural-current-generation",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level generation metadata must not mask nested plural stale current generations.",
            citations=["policy_decision:assisted-lab", "evidence:service-banner"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "creates_executable_task": True,
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:service-banner"],
                "metadata": {"current_active_generation_ids": ["generation:1"]},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:service-banner"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-plural-current-generation"])
        self.assertTrue(any("stale generation" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_task_generation_binding(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-task-generation-binding",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Envelope generation metadata must not mask a nested stale task generation binding.",
            citations=["policy_decision:assisted-lab", "evidence:service-banner"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "creates_executable_task": True,
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:service-banner"],
                "metadata": {"generation_id": "generation:1"},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:service-banner"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-task-generation-binding"])
        self.assertTrue(any("stale generation" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_plural_task_generation_binding(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-plural-task-generation-binding",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Envelope generation metadata must not mask nested plural stale task generation bindings.",
            citations=["policy_decision:assisted-lab", "evidence:service-banner"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "creates_executable_task": True,
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:service-banner"],
                "metadata": {"generation_ids": ["generation:1"]},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:service-banner"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-plural-task-generation-binding"])
        self.assertTrue(any("stale generation" in error for error in result.errors))

    def test_task_metadata_sink_rejects_wrong_target_executable_task(self) -> None:
        envelope = ContextEnvelope(
            ref="task:wrong-target-service-check",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Probe a service observed for a different current target.",
            citations=["policy_decision:assisted-lab", "evidence:target-a-service"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "creates_executable_task": True,
                "current_target_id": "target-b",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:target-a-service"],
            },
        )

        result = ContextSinkValidator().validate("task_metadata", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.rejected_refs, ["task:wrong-target-service-check"])
        self.assertTrue(any("wrong target" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_wrong_target(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-wrong-target",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level target metadata must not mask a nested wrong target marker.",
            citations=["policy_decision:assisted-lab", "evidence:target-a-service"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "creates_executable_task": True,
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:target-a-service"],
                "metadata": {"current_target_id": "target-b"},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:target-a-service"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-wrong-target"])
        self.assertTrue(any("wrong target" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_plural_current_target(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-plural-current-target",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Top-level target metadata must not mask nested plural wrong target markers.",
            citations=["policy_decision:assisted-lab", "evidence:target-a-service"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "creates_executable_task": True,
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:target-a-service"],
                "metadata": {"current_target_ids": ["target-b"]},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:target-a-service"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-plural-current-target"])
        self.assertTrue(any("wrong target" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_task_target_binding(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-task-target-binding",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Envelope target metadata must not mask a nested conflicting task target binding.",
            citations=["policy_decision:assisted-lab", "evidence:target-a-service"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "creates_executable_task": True,
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:target-a-service"],
                "metadata": {"task_target_id": "target-b"},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:target-a-service"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-task-target-binding"])
        self.assertTrue(any("wrong target" in error for error in result.errors))

    def test_task_metadata_sink_rejects_masked_nested_plural_task_target_binding(self) -> None:
        envelope = ContextEnvelope(
            ref="task:masked-nested-plural-task-target-binding",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Envelope target metadata must not mask nested plural conflicting task target bindings.",
            citations=["policy_decision:assisted-lab", "evidence:target-a-service"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "creates_executable_task": True,
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:target-a-service"],
                "metadata": {"task_target_ids": ["target-b"]},
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:target-a-service"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:masked-nested-plural-task-target-binding"])
        self.assertTrue(any("wrong target" in error for error in result.errors))

    def test_task_metadata_sink_rejects_context_restrictions_that_exclude_task_metadata(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="task:prompt-only-task",
                kind="candidate_task",
                authority="asserted",
                source_type="tool_output",
                target_id="target-a",
                purpose="task_generation",
                sink="task_metadata",
                content="Prompt-only task metadata must not enter the durable task metadata sink.",
                citations=["policy:manual-review"],
                valid_for=["prompt"],
                metadata={
                    "valid_for": ["prompt"],
                    "active_intent": "recon_only",
                    "action_class": "documentation",
                    "creates_executable_task": False,
                },
            ),
            ContextEnvelope(
                ref="task:task-metadata-denied",
                kind="candidate_task",
                authority="asserted",
                source_type="tool_output",
                target_id="target-a",
                purpose="task_generation",
                sink="task_metadata",
                content="Task-metadata-denied records must not enter the durable task metadata sink.",
                citations=["policy:manual-review"],
                invalid_for=["task_metadata"],
                metadata={
                    "invalid_for": ["task_metadata"],
                    "active_intent": "recon_only",
                    "action_class": "documentation",
                    "creates_executable_task": False,
                },
            ),
        ]

        result = ContextSinkValidator().validate(
            "task_metadata",
            envelopes,
            known_policy_decision_refs={"policy:manual-review"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:prompt-only-task", "task:task-metadata-denied"])
        self.assertTrue(any("valid_for excludes task_metadata" in error for error in result.errors))
        self.assertTrue(any("invalid_for excludes task_metadata" in error for error in result.errors))

    def test_notion_export_quarantines_uncited_rag_advisory(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:uncited-methodology",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            target_id="target-a",
            purpose="export",
            sink="notion_export",
            content="Advisory RAG material must preserve its rag citation in exports.",
            citations=[],
        )

        result = ContextSinkValidator().validate("notion_export", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.quarantined_refs, ["rag:uncited-methodology"])
        self.assertTrue(any("missing rag citation" in error for error in result.errors))

    def test_notion_export_quarantines_ai_output_disguised_as_operator_note(self) -> None:
        operator_note = ContextEnvelope(
            ref="note:operator-1",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            target_id="target-a",
            purpose="export",
            sink="notion_export",
            content="Human-authored operator note may be projected to Notion as a note.",
            citations=["note:operator-1"],
        )
        model_note = ContextEnvelope(
            ref="note:model-generated",
            kind="operator_note",
            authority="asserted",
            source_type="ai_output",
            target_id="target-a",
            purpose="export",
            sink="notion_export",
            content="AI output must not be projected as a human operator note.",
            citations=["note:model-generated"],
        )

        result = ContextSinkValidator().validate("notion_export", [operator_note, model_note])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["note:operator-1"])
        self.assertEqual(result.quarantined_refs, ["note:model-generated"])
        self.assertTrue(any("non_operator_note_source" in error for error in result.errors))

    def test_notion_export_quarantines_masked_nested_non_evidence_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="evidence:masked-model-export-proof",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            target_id="target-a",
            purpose="export",
            sink="notion_export",
            content="Top-level evidence source type must not mask nested model provenance.",
            citations=["evidence:masked-model-export-proof"],
            metadata={
                "metadata": {
                    "source_type": "ai_output",
                },
            },
        )

        result = ContextSinkValidator().validate("notion_export", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["evidence:masked-model-export-proof"])
        self.assertTrue(any("source_type=ai_output" in error for error in result.errors))

    def test_notion_export_quarantines_nested_raw_chat_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:export-nested-chat-source",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="export",
            sink="notion_export",
            content="Top-level methodology metadata must not mask nested chat provenance.",
            citations=["rag:export-nested-chat-source"],
            metadata={
                "metadata": {
                    "source_type": "chat",
                },
            },
        )

        result = ContextSinkValidator().validate(
            "notion_export",
            [envelope],
            known_rag_refs={"rag:export-nested-chat-source"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["rag:export-nested-chat-source"])
        self.assertTrue(any("raw chat context" in error for error in result.errors))

    def test_direct_notion_export_quarantines_plural_nested_raw_chat_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:direct-export-plural-chat-source",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="export",
            sink="notion_export",
            content="Top-level methodology source type must not mask plural nested chat provenance.",
            citations=["rag:direct-export-plural-chat-source"],
            metadata={
                "metadata": {
                    "source_types": ["chat"],
                },
            },
        )

        decision = validate_notion_export_envelope(
            envelope,
            set(),
            known_rag_refs={"rag:direct-export-plural-chat-source"},
        )

        self.assertEqual(decision.action, "quarantine")
        self.assertIn("raw chat context", decision.message)

    def test_notion_export_quarantines_generated_export_source_path(self) -> None:
        envelope = ContextEnvelope(
            ref="model:export-path-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="export",
            sink="notion_export",
            content="A model summary sourced from a prior Notion export must not feed a fresh export.",
            citations=["evidence:scan-1"],
            metadata={
                "source_file": "findings/notion/target-a/notion-export.md",
                "source_refs": ["evidence:scan-1"],
            },
        )

        result = ContextSinkValidator().validate(
            "notion_export",
            [envelope],
            known_evidence_refs={"evidence:scan-1"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["model:export-path-summary"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_notion_export_quarantines_generated_export_source_url(self) -> None:
        envelope = ContextEnvelope(
            ref="model:export-url-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="export",
            sink="notion_export",
            content="A model summary sourced from a prior export URL must not feed a fresh export.",
            citations=["evidence:scan-1"],
            metadata={
                "source_url": "https://example.invalid/findings/notion/target-a/notion-export.md",
                "source_refs": ["evidence:scan-1"],
            },
        )

        result = ContextSinkValidator().validate(
            "notion_export",
            [envelope],
            known_evidence_refs={"evidence:scan-1"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["model:export-url-summary"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_notion_export_quarantines_nested_ai_summary_source_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="model:nested-export-source-ref-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="export",
            sink="notion_export",
            content="Nested export provenance must not hide unsupported source references.",
            citations=["evidence:http-banner"],
            metadata={
                "metadata": {
                    "source_refs": ["evidence:http-banner", "github:issue-42"],
                }
            },
        )

        result = ContextSinkValidator().validate(
            "notion_export",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["model:nested-export-source-ref-summary"])
        self.assertTrue(any("unsupported source_refs" in error for error in result.errors))

    def test_notion_export_quarantines_nested_truth_like_authority_on_ai_summary(self) -> None:
        envelope = ContextEnvelope(
            ref="model:nested-export-confirmed-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="export",
            sink="notion_export",
            content="Nested metadata must not let AI-derived export context claim confirmed target truth.",
            citations=["evidence:http-banner"],
            metadata={
                "source_refs": ["evidence:http-banner"],
                "metadata": {"authority": "confirmed"},
            },
        )

        result = ContextSinkValidator().validate(
            "notion_export",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["model:nested-export-confirmed-summary"])
        self.assertTrue(any("truth-like authority" in error for error in result.errors))

    def test_notion_export_quarantines_plural_nested_truth_like_authorities_on_ai_summary(self) -> None:
        envelope = ContextEnvelope(
            ref="model:nested-export-confirmed-authorities-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="export",
            sink="notion_export",
            content="Nested plural metadata must not let AI-derived export context claim confirmed target truth.",
            citations=["evidence:http-banner"],
            metadata={
                "source_refs": ["evidence:http-banner"],
                "metadata": {"authorities": ["confirmed"]},
            },
        )

        result = ContextSinkValidator().validate(
            "notion_export",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["model:nested-export-confirmed-authorities-summary"])
        self.assertTrue(any("truth-like authority" in error for error in result.errors))

    def test_notion_export_quarantines_rag_with_unsupported_source_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:export-unsupported-source-refs",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="export",
            sink="notion_export",
            content="Export RAG context must not hide unsupported provenance.",
            citations=["rag:export-unsupported-source-refs"],
            metadata={"source_refs": ["github:issue-42"]},
        )

        result = ContextSinkValidator().validate("notion_export", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["rag:export-unsupported-source-refs"])
        self.assertTrue(any("unsupported source_refs" in error for error in result.errors))

    def test_notion_export_quarantines_nested_writeups_disabled_writeup(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:export-writeups-disabled",
            kind="rag",
            authority="advisory",
            source_type="writeup",
            purpose="export",
            sink="notion_export",
            content="Notion export must not project writeup-denied material.",
            citations=["rag:export-writeups-disabled"],
            metadata={"metadata": {"writeups_allowed": False}},
        )

        result = ContextSinkValidator().validate(
            "notion_export",
            [envelope],
            known_rag_refs={"rag:export-writeups-disabled"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["rag:export-writeups-disabled"])
        self.assertTrue(any("writeups_forbidden" in error for error in result.errors))

    def test_notion_export_quarantines_model_refs_against_quarantined_operator_note(self) -> None:
        note = ContextEnvelope(
            ref="note:bad-export-provenance",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            purpose="export",
            sink="notion_export",
            content="Export note provenance must not cite unresolved evidence.",
            citations=["note:bad-export-provenance", "evidence:missing-banner"],
            metadata={"source_refs": ["evidence:missing-banner"]},
        )
        model_summary = ContextEnvelope(
            ref="model:bad-export-note-backed",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="export",
            sink="notion_export",
            content="Export model output must not resolve against a quarantined operator note.",
            citations=["note:bad-export-provenance"],
            metadata={"source_refs": ["note:bad-export-provenance"]},
        )

        result = ContextSinkValidator().validate("notion_export", [note, model_summary], known_evidence_refs=set())

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["model:bad-export-note-backed", "note:bad-export-provenance"])
        self.assertTrue(any("unresolved evidence citation" in error for error in result.errors))
        self.assertTrue(any("unresolved note citation" in error for error in result.errors))

    def test_direct_notion_export_quarantines_operator_note_with_unsupported_source_refs(self) -> None:
        note = ContextEnvelope(
            ref="note:direct-export-unsupported-source-refs",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            purpose="export",
            sink="notion_export",
            content="Direct Notion export validation must not let operator notes hide unsupported provenance.",
            citations=["note:direct-export-unsupported-source-refs"],
            metadata={"source_refs": ["github:issue-42"]},
        )

        decision = validate_notion_export_envelope(note, set())

        self.assertEqual(decision.action, "quarantine")
        self.assertIn("unsupported source_refs", decision.message)
        self.assertIn("github:issue-42", decision.message)

    def test_notion_export_quarantines_context_restrictions_that_exclude_export(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="note:prompt-only-export-note",
                kind="operator_note",
                authority="asserted",
                source_type="manual_artifact",
                purpose="cleanup",
                sink="notion_export",
                content="Prompt-only operator notes must not be projected into Notion export.",
                citations=["note:prompt-only-export-note"],
                valid_for=["prompt"],
                metadata={"valid_for": ["prompt"]},
            ),
            ContextEnvelope(
                ref="note:notion-export-denied-note",
                kind="operator_note",
                authority="asserted",
                source_type="manual_artifact",
                purpose="cleanup",
                sink="notion_export",
                content="Notion-export-denied operator notes must not be projected into Notion export.",
                citations=["note:notion-export-denied-note"],
                invalid_for=["notion_export"],
                metadata={"invalid_for": ["notion_export"]},
            ),
        ]

        result = ContextSinkValidator().validate("notion_export", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["note:notion-export-denied-note", "note:prompt-only-export-note"])
        self.assertTrue(any("valid_for excludes notion_export" in error for error in result.errors))
        self.assertTrue(any("invalid_for excludes notion_export" in error for error in result.errors))

    def test_notion_inbox_rejects_context_restrictions_that_exclude_inbox(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="note:prompt-only-inbox-note",
                kind="operator_note",
                authority="asserted",
                source_type="notion",
                purpose="notion_inbox",
                sink="notion_inbox",
                content="Prompt-only Notion edits must not enter the Notion inbox sink.",
                citations=["note:prompt-only-inbox-note"],
                valid_for=["prompt"],
                metadata={"valid_for": ["prompt"], "edit_source": "user"},
            ),
            ContextEnvelope(
                ref="note:inbox-denied-note",
                kind="operator_note",
                authority="asserted",
                source_type="notion",
                purpose="notion_inbox",
                sink="notion_inbox",
                content="Notion-inbox-denied edits must not enter the Notion inbox sink.",
                citations=["note:inbox-denied-note"],
                invalid_for=["notion_inbox"],
                metadata={"invalid_for": ["notion_inbox"], "edit_source": "user"},
            ),
        ]

        result = ContextSinkValidator().validate("notion_inbox", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["note:inbox-denied-note", "note:prompt-only-inbox-note"])
        self.assertTrue(any("valid_for excludes notion_inbox" in error for error in result.errors))
        self.assertTrue(any("invalid_for excludes notion_inbox" in error for error in result.errors))

    def test_notion_inbox_rejects_generated_export_source_url(self) -> None:
        envelope = ContextEnvelope(
            ref="note:inbox-export-url",
            kind="external_reference",
            authority="advisory",
            source_type="notion",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="notion_inbox",
            sink="notion_inbox",
            content="Inbound Notion references must not reintroduce generated export URLs.",
            citations=["note:inbox-export-url"],
            metadata={
                "edit_source": "user",
                "source_url": "https://example.invalid/findings/notion/target-a/notion-export.md",
            },
        )

        result = ContextSinkValidator().validate("notion_inbox", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["note:inbox-export-url"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_notion_inbox_rejects_nested_generated_export_source_url(self) -> None:
        envelope = ContextEnvelope(
            ref="note:inbox-nested-export-url",
            kind="external_reference",
            authority="advisory",
            source_type="notion",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="notion_inbox",
            sink="notion_inbox",
            content="Inbound Notion references must not hide generated export URLs in nested metadata.",
            citations=["note:inbox-nested-export-url"],
            metadata={
                "edit_source": "user",
                "metadata": {
                    "source_url": "https://example.invalid/findings/notion/target-a/notion-export.md",
                },
            },
        )

        result = ContextSinkValidator().validate("notion_inbox", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["note:inbox-nested-export-url"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_notion_inbox_rejects_nested_confirmed_finding_status(self) -> None:
        envelope = ContextEnvelope(
            ref="note:inbox-nested-confirmed-finding",
            kind="finding_draft_delta",
            authority="advisory",
            source_type="notion",
            target_id="target-a",
            purpose="notion_inbox",
            sink="notion_inbox",
            content="Inbound Notion edits must not hide confirmed finding status in nested metadata.",
            citations=["note:inbox-nested-confirmed-finding"],
            metadata={
                "edit_source": "user",
                "metadata": {"finding_status": "confirmed"},
            },
        )

        result = ContextSinkValidator().validate("notion_inbox", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["note:inbox-nested-confirmed-finding"])
        self.assertTrue(any("confirmed finding" in error for error in result.errors))

    def test_notion_inbox_rejects_nested_truth_like_authority(self) -> None:
        envelope = ContextEnvelope(
            ref="note:inbox-nested-confirmed-authority",
            kind="external_reference",
            authority="advisory",
            source_type="notion",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="notion_inbox",
            sink="notion_inbox",
            content="Nested Notion authority must not turn an inbox proposal into target truth.",
            citations=["note:inbox-nested-confirmed-authority"],
            metadata={
                "edit_source": "user",
                "metadata": {"authority": "confirmed"},
            },
        )

        result = ContextSinkValidator().validate("notion_inbox", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["note:inbox-nested-confirmed-authority"])
        self.assertTrue(any("truth-like authority" in error for error in result.errors))

    def test_notion_inbox_rejects_plural_nested_unsupported_source_types(self) -> None:
        envelope = ContextEnvelope(
            ref="note:inbox-nested-ai-output-source",
            kind="external_reference",
            authority="advisory",
            source_type="notion",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="notion_inbox",
            sink="notion_inbox",
            content="Inbound Notion source metadata must not mask nested model output provenance.",
            citations=["note:inbox-nested-ai-output-source"],
            metadata={
                "edit_source": "user",
                "metadata": {"source_types": ["ai_output"]},
            },
        )

        result = ContextSinkValidator().validate("notion_inbox", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["note:inbox-nested-ai-output-source"])
        self.assertTrue(any("unsupported source_type=ai_output" in error for error in result.errors))

    def test_notion_inbox_rejects_masked_nested_confirmed_finding_status(self) -> None:
        envelope = ContextEnvelope(
            ref="note:inbox-masked-confirmed-finding",
            kind="finding_draft_delta",
            authority="advisory",
            source_type="notion",
            target_id="target-a",
            purpose="notion_inbox",
            sink="notion_inbox",
            content="Top-level draft status must not mask nested confirmed finding status.",
            citations=["note:inbox-masked-confirmed-finding"],
            metadata={
                "edit_source": "user",
                "finding_status": "draft",
                "metadata": {"finding_status": "confirmed"},
            },
        )

        result = ContextSinkValidator().validate("notion_inbox", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["note:inbox-masked-confirmed-finding"])
        self.assertTrue(any("confirmed finding" in error for error in result.errors))

    def test_rag_index_rejects_closed_book_writeups_and_hidden_solution_material(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="rag:cve-advisory",
                kind="rag",
                authority="advisory",
                source_type="vuln_intel",
                purpose="vuln_hint",
                sink="rag_index",
                content="Advisory CVE context may be indexed as advisory material.",
                citations=["rag:cve-advisory"],
            ),
            ContextEnvelope(
                ref="rag:hidden-solution",
                kind="rag",
                authority="advisory",
                source_type="ctf_manifest",
                purpose="ctf_benchmark",
                sink="rag_index",
                content="Hidden solution material must not enter the active RAG index.",
                citations=["rag:hidden-solution"],
                metadata={"benchmark_mode": "closed_book", "hidden_solution_material": True},
            ),
            ContextEnvelope(
                ref="rag:closed-book-writeup",
                kind="rag",
                authority="advisory",
                source_type="writeup",
                purpose="ctf_benchmark",
                sink="rag_index",
                content="Target-specific writeups are disallowed in closed-book mode.",
                citations=["rag:closed-book-writeup"],
                metadata={"benchmark_mode": "closed_book", "writeup_access_policy": "forbidden"},
            ),
        ]

        result = ContextSinkValidator().validate("rag_index", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["rag:cve-advisory"])
        self.assertEqual(result.rejected_refs, ["rag:closed-book-writeup", "rag:hidden-solution"])
        self.assertTrue(any("hidden solution material" in error for error in result.errors))
        self.assertTrue(any("writeup" in error and "closed_book" in error for error in result.errors))

    def test_rag_index_rejects_list_valued_hidden_solution_metadata_flag(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:list-hidden-solution",
            kind="rag",
            authority="advisory",
            source_type="ctf_manifest",
            purpose="ctf_benchmark",
            sink="rag_index",
            content="List-valued hidden solution markers must not enter active operational RAG.",
            citations=["rag:list-hidden-solution"],
            metadata={"hidden_solution_material": [False, True]},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:list-hidden-solution"])
        self.assertTrue(any("hidden solution material" in error for error in result.errors))

    def test_rag_index_rejects_metadata_poison_flags_list_values(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:metadata-poison-flags-hidden-solution",
            kind="rag",
            authority="advisory",
            source_type="ctf_manifest",
            purpose="ctf_benchmark",
            sink="rag_index",
            content="Metadata poison_flags values must not hide hidden solution material from RAG.",
            citations=["rag:metadata-poison-flags-hidden-solution"],
            metadata={"poison_flags": ["hidden_solution_material"]},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:metadata-poison-flags-hidden-solution"])
        self.assertTrue(any("hidden solution material" in error for error in result.errors))

    def test_rag_index_rejects_human_readable_metadata_poison_flag_value(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:human-readable-poison-flag-hidden-solution",
            kind="rag",
            authority="advisory",
            source_type="ctf_manifest",
            purpose="ctf_benchmark",
            sink="rag_index",
            content="Human-readable poison flag metadata must not hide hidden solution material from RAG.",
            citations=["rag:human-readable-poison-flag-hidden-solution"],
            metadata={"Poison flag": "hidden_solution_material"},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:human-readable-poison-flag-hidden-solution"])
        self.assertTrue(any("hidden solution material" in error for error in result.errors))

    def test_rag_index_normalizes_human_readable_closed_book_mode(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:display-closed-book-writeup",
            kind="rag",
            authority="advisory",
            source_type="writeup",
            purpose="ctf_benchmark",
            sink="rag_index",
            content="Display-mode closed-book writeups must not enter the active RAG index.",
            citations=["rag:display-closed-book-writeup"],
            metadata={"benchmark_mode": "Closed book"},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:display-closed-book-writeup"])
        self.assertTrue(any("writeup" in error and "closed_book" in error for error in result.errors))

    def test_rag_index_rejects_context_restrictions_that_exclude_rag_index(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="rag:prompt-only-advisory",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                purpose="cleanup",
                sink="rag_index",
                content="Prompt-only advisory context must not be indexed into active RAG.",
                citations=["rag:prompt-only-advisory"],
                valid_for=["prompt"],
                metadata={"valid_for": ["prompt"]},
            ),
            ContextEnvelope(
                ref="rag:rag-index-denied-advisory",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                purpose="cleanup",
                sink="rag_index",
                content="RAG-index-denied advisory context must not be indexed into active RAG.",
                citations=["rag:rag-index-denied-advisory"],
                invalid_for=["rag_index"],
                metadata={"invalid_for": ["rag_index"]},
            ),
        ]

        result = ContextSinkValidator().validate("rag_index", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:prompt-only-advisory", "rag:rag-index-denied-advisory"])
        self.assertTrue(any("valid_for excludes rag_index" in error for error in result.errors))
        self.assertTrue(any("invalid_for excludes rag_index" in error for error in result.errors))

    def test_rag_index_honors_purpose_context_restrictions(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="rag:cleanup-denied-advisory",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                purpose="cleanup",
                sink="rag_index",
                content="Cleanup-denied advisory context must not enter the cleanup RAG index context.",
                citations=["rag:cleanup-denied-advisory"],
                invalid_for=["cleanup"],
                metadata={"invalid_for": ["cleanup"]},
            ),
            ContextEnvelope(
                ref="rag:cleanup-only-advisory",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                purpose="cleanup",
                sink="rag_index",
                content="Cleanup-only advisory context may enter the cleanup RAG index context.",
                citations=["rag:cleanup-only-advisory"],
                valid_for=["cleanup"],
                metadata={"valid_for": ["cleanup"]},
            ),
        ]

        result = ContextSinkValidator().validate("rag_index", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["rag:cleanup-only-advisory"])
        self.assertEqual(result.rejected_refs, ["rag:cleanup-denied-advisory"])
        self.assertTrue(any("invalid_for excludes rag_index" in error for error in result.errors))

    def test_prompt_sink_rejects_context_restrictions_that_exclude_prompt(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="rag:report-only-advisory",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                purpose="planner",
                sink="prompt",
                content="Report-only advisory context must not enter prompt sinks.",
                citations=["rag:report-only-advisory"],
                valid_for=["report"],
                metadata={"valid_for": ["report"]},
            ),
            ContextEnvelope(
                ref="rag:prompt-denied-advisory",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                purpose="planner",
                sink="prompt",
                content="Prompt-denied advisory context must not enter prompt sinks.",
                citations=["rag:prompt-denied-advisory"],
                invalid_for=["prompt"],
                metadata={"invalid_for": ["prompt"]},
            ),
        ]

        result = ContextSinkValidator().validate("prompt", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:prompt-denied-advisory", "rag:report-only-advisory"])
        self.assertTrue(any("valid_for excludes prompt" in error for error in result.errors))
        self.assertTrue(any("invalid_for excludes prompt" in error for error in result.errors))

    def test_report_sink_rejects_context_restrictions_that_exclude_report(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="rag:prompt-only-report-advisory",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                purpose="cleanup",
                sink="report",
                content="Prompt-only advisory context must not enter report sinks.",
                citations=["rag:prompt-only-report-advisory"],
                valid_for=["prompt"],
                metadata={"valid_for": ["prompt"]},
            ),
            ContextEnvelope(
                ref="rag:report-denied-advisory",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                purpose="cleanup",
                sink="report",
                content="Report-denied advisory context must not enter report sinks.",
                citations=["rag:report-denied-advisory"],
                invalid_for=["report"],
                metadata={"invalid_for": ["report"]},
            ),
        ]

        result = ContextSinkValidator().validate(
            "report",
            envelopes,
            known_rag_refs={"rag:prompt-only-report-advisory", "rag:report-denied-advisory"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:prompt-only-report-advisory", "rag:report-denied-advisory"])
        self.assertTrue(any("valid_for excludes report" in error for error in result.errors))
        self.assertTrue(any("invalid_for excludes report" in error for error in result.errors))

    def test_rag_index_rejects_string_encoded_generated_export_deny_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="model:string-denied-export-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="cleanup",
            sink="rag_index",
            content="String-encoded deny metadata must not let generated exports enter active RAG.",
            citations=["evidence:current"],
            metadata={
                "Origin": "generated export",
                "Ingest allowed": "false",
                "Operational retrieval allowed": "no",
            },
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:string-denied-export-summary"])
        self.assertTrue(any("ingest_allowed=false" in error for error in result.errors))

    def test_rag_index_rejects_nested_operational_retrieval_deny_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:nested-operational-retrieval-denied",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Nested retrieval deny metadata must keep this chunk out of active RAG.",
            citations=["rag:nested-operational-retrieval-denied"],
            metadata={
                "metadata": {
                    "operational_retrieval_allowed": False,
                },
            },
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:nested-operational-retrieval-denied"])
        self.assertTrue(any("operational_retrieval_allowed=false" in error for error in result.errors))

    def test_rag_index_rejects_generated_export_origin_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="model:export-origin-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="cleanup",
            sink="rag_index",
            content="Generated export origin metadata must keep summaries out of active RAG.",
            citations=["evidence:current"],
            metadata={"Origin": "generated export"},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:export-origin-summary"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_rag_index_rejects_plural_generated_export_kinds_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:plural-generated-export-kinds",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Plural generated export kind markers must not become active operational RAG.",
            citations=["rag:plural-generated-export-kinds"],
            metadata={"kinds": ["generated_export"]},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:plural-generated-export-kinds"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_rag_index_rejects_generated_export_source_path(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="rag:export-path-advisory",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                purpose="cleanup",
                sink="rag_index",
                content="Generated Notion export text must not become active operational RAG.",
                citations=["rag:export-path-advisory"],
                metadata={"source_file": "findings/notion/target-a/notion-export.md"},
            ),
            ContextEnvelope(
                ref="rag:nested-export-path-advisory",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                purpose="cleanup",
                sink="rag_index",
                content="Nested generated export paths must not become active operational RAG.",
                citations=["rag:nested-export-path-advisory"],
                metadata={"source_file": ["advisory/context.md", "generated-export.md"]},
            ),
        ]

        result = ContextSinkValidator().validate("rag_index", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:export-path-advisory", "rag:nested-export-path-advisory"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_rag_index_rejects_generated_export_source_url(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:export-url-advisory",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Generated export URLs must not become active operational RAG.",
            citations=["rag:export-url-advisory"],
            metadata={"source_url": "https://example.invalid/findings/notion/target-a/notion-export.md"},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:export-url-advisory"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_rag_index_rejects_nested_generated_export_source_url(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:nested-export-url-advisory",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Nested generated export URLs must not become active operational RAG.",
            citations=["rag:nested-export-url-advisory"],
            metadata={
                "provenance": {
                    "source_url": "https://example.invalid/findings/notion/target-a/notion-export.md"
                }
            },
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:nested-export-url-advisory"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_rag_index_rejects_generated_export_path_in_unknown_scalar_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:unknown-key-export-path-advisory",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Generated export paths must not be hidden under arbitrary scalar metadata.",
            citations=["rag:unknown-key-export-path-advisory"],
            metadata={"provenance_url": "https://example.invalid/findings/notion/target-a/notion-export.md"},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:unknown-key-export-path-advisory"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_rag_index_rejects_malformed_source_refs_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:malformed-source-refs",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Malformed source refs must not be normalized into supported-looking provenance.",
            citations=["rag:malformed-source-refs"],
            metadata={"source_refs": ["rag:valid-source", 42]},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:malformed-source-refs"])
        self.assertTrue(any("malformed source_refs" in error for error in result.errors))

    def test_rag_index_rejects_display_source_reference_alias_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:display-source-reference-alias",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Display source-reference aliases must not bypass provenance checks.",
            citations=["rag:display-source-reference-alias", "github:issue-42"],
            metadata={"Source reference": "github:issue-42"},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:display-source-reference-alias"])
        self.assertTrue(any("unsupported source_refs" in error for error in result.errors))

    def test_rag_index_rejects_display_source_ref_alias_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:display-source-ref-alias",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Short display source-ref aliases must not bypass provenance checks.",
            citations=["rag:display-source-ref-alias", "github:issue-42"],
            metadata={"Source ref": "github:issue-42"},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:display-source-ref-alias"])
        self.assertTrue(any("unsupported source_refs" in error for error in result.errors))

    def test_rag_index_rejects_display_source_references_alias_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:display-source-references-alias",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Plural display source-reference aliases must not bypass provenance checks.",
            citations=["rag:display-source-references-alias", "github:issue-42"],
            metadata={"Source references": ["github:issue-42"]},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:display-source-references-alias"])
        self.assertTrue(any("unsupported source_refs" in error for error in result.errors))

    def test_rag_index_rejects_double_nested_source_refs_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:double-nested-source-refs",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Double-nested source refs must not bypass provenance checks.",
            citations=["rag:double-nested-source-refs", "github:issue-42"],
            metadata={"layers": [[{"source_refs": ["github:issue-42"]}]]},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:double-nested-source-refs"])
        self.assertTrue(any("unsupported source_refs" in error for error in result.errors))

    def test_rag_index_rejects_placeholder_source_refs_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:placeholder-source-ref-owner",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Placeholder source refs must not become active provenance.",
            citations=["rag:placeholder-source-ref-owner"],
            metadata={"source_refs": ["rag:unknown"]},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:placeholder-source-ref-owner"])
        self.assertTrue(any("placeholder source_refs" in error for error in result.errors))

    def test_rag_index_rejects_non_rag_placeholder_source_refs_metadata(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="rag:placeholder-evidence-source-ref-owner",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                purpose="cleanup",
                sink="rag_index",
                content="Placeholder evidence refs must not become active provenance.",
                citations=["rag:placeholder-evidence-source-ref-owner", "evidence:unknown"],
                metadata={"source_refs": ["evidence:unknown"]},
            ),
            ContextEnvelope(
                ref="rag:placeholder-note-source-ref-owner",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                purpose="cleanup",
                sink="rag_index",
                content="Placeholder note refs must not become active provenance.",
                citations=["rag:placeholder-note-source-ref-owner", "note:null"],
                metadata={"source_refs": ["note:null"]},
            ),
        ]

        result = ContextSinkValidator().validate("rag_index", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(
            result.rejected_refs,
            ["rag:placeholder-evidence-source-ref-owner", "rag:placeholder-note-source-ref-owner"],
        )
        self.assertTrue(any("placeholder source_refs" in error for error in result.errors))

    def test_rag_index_rejects_uncited_source_refs_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:uncited-source-ref-owner",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Source refs must be cited before entering active RAG provenance.",
            citations=["rag:uncited-source-ref-owner"],
            metadata={"source_refs": ["rag:curated-source"]},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:uncited-source-ref-owner"])
        self.assertTrue(any("uncited source_refs" in error for error in result.errors))

    def test_rag_index_rejects_unresolved_evidence_source_refs_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:unresolved-evidence-source-ref-owner",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="RAG provenance must not cite evidence that is not in the evidence ledger.",
            citations=["rag:unresolved-evidence-source-ref-owner", "evidence:missing-banner"],
            metadata={"source_refs": ["evidence:missing-banner"]},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope], known_evidence_refs=set())

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:unresolved-evidence-source-ref-owner"])
        self.assertTrue(any("unresolved evidence citation" in error for error in result.errors))

    def test_rag_index_rejects_source_refs_against_rejected_operator_note(self) -> None:
        note = ContextEnvelope(
            ref="note:bad-rag-index-provenance",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            purpose="cleanup",
            sink="rag_index",
            content="Operator note provenance must not cite unresolved evidence before indexing.",
            citations=["note:bad-rag-index-provenance", "evidence:missing-banner"],
            metadata={"source_refs": ["evidence:missing-banner"]},
        )
        envelope = ContextEnvelope(
            ref="rag:bad-note-backed-source-ref",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="RAG provenance must not cite operator notes rejected from the same index batch.",
            citations=["rag:bad-note-backed-source-ref", "note:bad-rag-index-provenance"],
            metadata={"source_refs": ["note:bad-rag-index-provenance"]},
        )

        result = ContextSinkValidator().validate("rag_index", [note, envelope], known_evidence_refs=set())

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["note:bad-rag-index-provenance", "rag:bad-note-backed-source-ref"])
        self.assertTrue(any("unresolved note citation" in error for error in result.errors))

    def test_rag_index_rejects_model_and_chat_generated_material(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="model:summary-to-rag",
                kind="model_summary",
                authority="derived",
                source_type="ai_output",
                purpose="cleanup",
                sink="rag_index",
                content="AI-derived summaries must not become active operational RAG.",
                citations=["evidence:current"],
            ),
            ContextEnvelope(
                ref="chat:operator-context",
                kind="operator_note",
                authority="asserted",
                source_type="chat",
                purpose="cleanup",
                sink="rag_index",
                content="Chat context is advisory conversation, not active operational RAG.",
                citations=["note:operator"],
            ),
        ]

        result = ContextSinkValidator().validate("rag_index", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["chat:operator-context", "model:summary-to-rag"])
        self.assertTrue(any("generated model or chat material" in error for error in result.errors))

    def test_rag_index_rejects_plural_nested_generated_model_source_types(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:nested-ai-output-source-types",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Nested plural source type metadata must not let generated model output become active RAG.",
            citations=["rag:nested-ai-output-source-types"],
            metadata={"metadata": {"source_types": ["ai_output"]}},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:nested-ai-output-source-types"])
        self.assertTrue(any("generated model or chat material" in error for error in result.errors))

    def test_rag_index_rejects_evidence_and_authority_lane_material(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="evidence:scan-result-to-rag",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                purpose="cleanup",
                sink="rag_index",
                content="Observed scan results belong in evidence, not active advisory RAG.",
                citations=["evidence:scan-result-to-rag"],
            ),
            ContextEnvelope(
                ref="state:scope-to-rag",
                kind="authority",
                authority="authoritative",
                source_type="runtime_state",
                purpose="cleanup",
                sink="rag_index",
                content="Runtime authority state must not become active advisory RAG.",
                citations=["policy_decision:scope"],
            ),
        ]

        result = ContextSinkValidator().validate("rag_index", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["evidence:scan-result-to-rag", "state:scope-to-rag"])
        self.assertTrue(any("evidence or authority lane material" in error for error in result.errors))

    def test_rag_index_rejects_plural_nested_evidence_kinds(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:nested-evidence-kinds",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Nested plural kind metadata must not let evidence lane material become active RAG.",
            citations=["rag:nested-evidence-kinds"],
            metadata={"metadata": {"kinds": ["evidence"]}},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:nested-evidence-kinds"])
        self.assertTrue(any("evidence or authority lane material" in error for error in result.errors))

    def test_rag_index_rejects_reviewed_findings_and_operator_notes(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="finding:reviewed-to-rag",
                kind="finding",
                authority="reviewed",
                source_type="runtime_state",
                purpose="cleanup",
                sink="rag_index",
                content="Reviewed findings belong in the finding lane, not active advisory RAG.",
                citations=["evidence:banner"],
            ),
            ContextEnvelope(
                ref="note:operator-to-rag",
                kind="operator_note",
                authority="asserted",
                source_type="manual_artifact",
                purpose="cleanup",
                sink="rag_index",
                content="Operator assertions belong in the notes lane, not active advisory RAG.",
                citations=["note:operator-to-rag"],
            ),
        ]

        result = ContextSinkValidator().validate("rag_index", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["finding:reviewed-to-rag", "note:operator-to-rag"])
        self.assertTrue(any("target context lane material" in error for error in result.errors))

    def test_rag_index_rejects_plural_nested_target_context_kinds(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:nested-finding-kinds",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Nested plural kind metadata must not let target findings become active RAG.",
            citations=["rag:nested-finding-kinds"],
            metadata={"metadata": {"kinds": ["finding"]}},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:nested-finding-kinds"])
        self.assertTrue(any("target context lane material" in error for error in result.errors))

    def test_rag_index_rejects_derived_planning_state(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="hypothesis:service-path-to-rag",
                kind="hypothesis",
                authority="asserted",
                source_type="manual_artifact",
                purpose="cleanup",
                sink="rag_index",
                content="Unverified hypotheses belong in derived planning state, not active advisory RAG.",
                citations=["note:operator-hypothesis"],
            ),
            ContextEnvelope(
                ref="task:candidate-to-rag",
                kind="candidate_task",
                authority="asserted",
                source_type="manual_artifact",
                purpose="cleanup",
                sink="rag_index",
                content="Candidate tasks must remain policy-gated planning state, not retrievable RAG.",
                citations=["policy_decision:pending"],
            ),
        ]

        result = ContextSinkValidator().validate("rag_index", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["hypothesis:service-path-to-rag", "task:candidate-to-rag"])
        self.assertTrue(any("derived planning state" in error for error in result.errors))

    def test_rag_index_rejects_plural_nested_derived_planning_kinds(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:nested-hypothesis-kinds",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Nested plural kind metadata must not let derived planning state become active RAG.",
            citations=["rag:nested-hypothesis-kinds"],
            metadata={"metadata": {"kinds": ["hypothesis"]}},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:nested-hypothesis-kinds"])
        self.assertTrue(any("derived planning state" in error for error in result.errors))

    def test_rag_index_rejects_collaboration_reference_lanes(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="rag:methodology",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                purpose="methodology_hint",
                sink="rag_index",
                content="General methodology remains valid advisory RAG material.",
                citations=["rag:methodology"],
            ),
            ContextEnvelope(
                ref="github:issue-to-rag",
                kind="github_ref",
                authority="asserted",
                source_type="github",
                purpose="cleanup",
                sink="rag_index",
                content="GitHub issue prose is an engineering ledger projection, not active operational RAG.",
                citations=["github:issue-to-rag"],
            ),
            ContextEnvelope(
                ref="notion:page-to-rag",
                kind="notion_ref",
                authority="asserted",
                source_type="notion",
                purpose="cleanup",
                sink="rag_index",
                content="Notion page prose is collaborative projection material, not active operational RAG.",
                citations=["notion:page-to-rag"],
            ),
            ContextEnvelope(
                ref="ctfd:challenge-to-rag",
                kind="ctfd_ref",
                authority="asserted",
                source_type="ctfd",
                purpose="cleanup",
                sink="rag_index",
                content="CTFd challenge metadata is scoreboard projection, not active operational RAG.",
                citations=["ctfd:challenge-to-rag"],
            ),
        ]

        result = ContextSinkValidator().validate("rag_index", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["rag:methodology"])
        self.assertEqual(
            result.rejected_refs,
            ["ctfd:challenge-to-rag", "github:issue-to-rag", "notion:page-to-rag"],
        )
        self.assertTrue(any("collaboration reference lane material" in error for error in result.errors))

    def test_rag_index_rejects_plural_nested_collaboration_reference_kinds(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:nested-github-ref-kinds",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Nested plural kind metadata must not let collaboration references become active RAG.",
            citations=["rag:nested-github-ref-kinds"],
            metadata={"metadata": {"kinds": ["github_ref"]}},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:nested-github-ref-kinds"])
        self.assertTrue(any("collaboration reference lane material" in error for error in result.errors))

    def test_rag_index_rejects_plural_nested_recent_action_trace_kinds(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:nested-action-trace-kinds",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Nested plural kind metadata must not let recent action traces become active RAG.",
            citations=["rag:nested-action-trace-kinds"],
            metadata={"metadata": {"kinds": ["action_trace"]}},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:nested-action-trace-kinds"])
        self.assertTrue(any("recent action trace lane material" in error for error in result.errors))

    def test_rag_index_rejects_plural_nested_non_advisory_source_types(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:nested-manual-artifact-source-types",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Nested plural source type metadata must not let non-advisory material become active RAG.",
            citations=["rag:nested-manual-artifact-source-types"],
            metadata={"metadata": {"source_types": ["manual_artifact"]}},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:nested-manual-artifact-source-types"])
        self.assertTrue(any("requires advisory source_type" in error for error in result.errors))

    def test_report_sink_rejects_uncited_ai_target_facts_and_raw_flags(self) -> None:
        accepted = ContextEnvelope(
            ref="finding:web-1",
            kind="finding",
            authority="reviewed",
            source_type="runtime_state",
            target_id="target-a",
            purpose="report_generation",
            sink="report",
            content="Reviewed finding supported by evidence.",
            citations=["evidence:banner"],
        )
        envelopes = [
            accepted,
            ContextEnvelope(
                ref="model:uncited-summary",
                kind="model_summary",
                authority="derived",
                source_type="ai_output",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="Uncited AI summary should not enter reports.",
                citations=[],
            ),
            ContextEnvelope(
                ref="model:target-fact",
                kind="model_summary",
                authority="derived",
                source_type="ai_output",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="Target fact backed only by advisory RAG.",
                citations=["rag:method-1"],
                metadata={"contains_target_fact": True},
            ),
            ContextEnvelope(
                ref="ctfd:raw-flag",
                kind="ctfd_ref",
                authority="asserted",
                source_type="ctfd",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="Raw hidden flag material must not be reported.",
                citations=[],
                metadata={"contains_raw_flag": True},
            ),
        ]

        result = ContextSinkValidator().validate("report", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["finding:web-1"])
        self.assertEqual(
            result.rejected_refs,
            ["ctfd:raw-flag", "model:target-fact", "model:uncited-summary"],
        )
        self.assertTrue(any("requires citations for AI-derived" in error for error in result.errors))
        self.assertTrue(any("requires evidence:<id>" in error for error in result.errors))
        self.assertTrue(any("hidden or raw sensitive material" in error for error in result.errors))

    def test_report_sink_rejects_nested_ai_summary_source_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="model:nested-report-source-ref-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="report_generation",
            sink="report",
            content="Nested report provenance must not hide unsupported source references.",
            citations=["evidence:http-banner"],
            metadata={
                "metadata": {
                    "source_refs": ["evidence:http-banner", "github:issue-42"],
                }
            },
        )

        result = ContextSinkValidator().validate(
            "report",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:nested-report-source-ref-summary"])
        self.assertTrue(any("unsupported source_refs" in error for error in result.errors))

    def test_report_sink_rejects_placeholder_ai_summary_citation(self) -> None:
        envelope = ContextEnvelope(
            ref="model:placeholder-report-citation-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="report_generation",
            sink="report",
            content="Placeholder citations must not satisfy report provenance.",
            citations=["note:null"],
        )

        result = ContextSinkValidator().validate("report", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:placeholder-report-citation-summary"])
        self.assertTrue(any("placeholder" in error for error in result.errors))
        self.assertTrue(any("note:null" in error for error in result.errors))

    def test_report_sink_rejects_nested_raw_chat_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:report-nested-chat-source",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="report_generation",
            sink="report",
            content="Top-level methodology metadata must not mask nested chat provenance.",
            citations=["rag:report-nested-chat-source"],
            metadata={
                "metadata": {
                    "source_type": "chat",
                },
            },
        )

        result = ContextSinkValidator().validate(
            "report",
            [envelope],
            known_rag_refs={"rag:report-nested-chat-source"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:report-nested-chat-source"])
        self.assertTrue(any("raw chat context" in error for error in result.errors))

    def test_direct_report_sink_rejects_plural_nested_raw_chat_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:direct-report-plural-chat-source",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="report_generation",
            sink="report",
            content="Top-level methodology source type must not mask plural nested chat provenance.",
            citations=["rag:direct-report-plural-chat-source"],
            metadata={
                "metadata": {
                    "source_types": ["chat"],
                },
            },
        )

        decision = validate_report_sink(envelope)

        self.assertEqual(decision.action, "reject")
        self.assertIn("raw chat context", decision.message)

    def test_report_sink_rejects_generated_export_source_url(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:report-export-url",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="report_generation",
            sink="report",
            content="Generated export URLs must not recurse into report context.",
            citations=["rag:report-export-url"],
            metadata={"source_url": "https://example.invalid/findings/notion/target-a/notion-export.md"},
        )

        result = ContextSinkValidator().validate(
            "report",
            [envelope],
            known_rag_refs={"rag:report-export-url"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:report-export-url"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_report_sink_rejects_nested_writeups_disabled_writeup(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:report-writeups-disabled",
            kind="rag",
            authority="advisory",
            source_type="writeup",
            purpose="report_generation",
            sink="report",
            content="Report generation must not use writeup-denied material.",
            citations=["rag:report-writeups-disabled"],
            metadata={"metadata": {"writeups_allowed": False}},
        )

        result = ContextSinkValidator().validate(
            "report",
            [envelope],
            known_rag_refs={"rag:report-writeups-disabled"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:report-writeups-disabled"])
        self.assertTrue(any("writeups_forbidden" in error for error in result.errors))

    def test_report_sink_rejects_masked_nested_closed_book_writeup_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:report-masked-closed-book-writeup",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="report_generation",
            sink="report",
            content="Nested writeup source metadata must not be masked as methodology in closed-book reports.",
            citations=["rag:report-masked-closed-book-writeup"],
            metadata={"metadata": {"source_types": ["writeup"], "benchmark_mode": "closed_book"}},
        )

        result = ContextSinkValidator().validate(
            "report",
            [envelope],
            known_rag_refs={"rag:report-masked-closed-book-writeup"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:report-masked-closed-book-writeup"])
        self.assertTrue(any("closed_book_forbidden" in error for error in result.errors))

    def test_report_sink_rejects_list_valued_writeup_policy_metadata(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="rag:report-list-closed-book-writeup",
                kind="rag",
                authority="advisory",
                source_type="writeup",
                purpose="report_generation",
                sink="report",
                content="List-valued benchmark metadata must not hide closed-book writeups.",
                citations=["rag:report-list-closed-book-writeup"],
                metadata={"benchmark_mode": ["open_book", "closed_book"]},
            ),
            ContextEnvelope(
                ref="rag:report-list-postmortem-only-writeup",
                kind="rag",
                authority="advisory",
                source_type="writeup",
                purpose="report_generation",
                sink="report",
                content="List-valued policy metadata must not hide postmortem-only writeups.",
                citations=["rag:report-list-postmortem-only-writeup"],
                metadata={"writeup_access_policy": ["allowed", "postmortem_only"]},
            ),
            ContextEnvelope(
                ref="rag:report-list-writeups-disabled",
                kind="rag",
                authority="advisory",
                source_type="writeup",
                purpose="report_generation",
                sink="report",
                content="List-valued writeups_allowed metadata must not hide disabled writeups.",
                citations=["rag:report-list-writeups-disabled"],
                metadata={"writeups_allowed": [True, False]},
            ),
        ]

        result = ContextSinkValidator().validate(
            "report",
            envelopes,
            known_rag_refs={envelope.ref for envelope in envelopes},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(
            result.rejected_refs,
            [
                "rag:report-list-closed-book-writeup",
                "rag:report-list-postmortem-only-writeup",
                "rag:report-list-writeups-disabled",
            ],
        )
        self.assertTrue(any("closed_book_forbidden" in error for error in result.errors))
        self.assertTrue(any("postmortem_only_forbidden" in error for error in result.errors))
        self.assertTrue(any("writeups_forbidden" in error for error in result.errors))

    def test_report_sink_rejects_model_refs_against_rejected_operator_note(self) -> None:
        note = ContextEnvelope(
            ref="note:bad-report-provenance",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            purpose="report_generation",
            sink="report",
            content="Report note provenance must not cite unresolved evidence.",
            citations=["note:bad-report-provenance", "evidence:missing-banner"],
            metadata={"source_refs": ["evidence:missing-banner"]},
        )
        model_summary = ContextEnvelope(
            ref="model:bad-report-note-backed",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="report_generation",
            sink="report",
            content="Report model output must not resolve against a rejected operator note.",
            citations=["note:bad-report-provenance"],
            metadata={"source_refs": ["note:bad-report-provenance"]},
        )

        result = ContextSinkValidator().validate("report", [note, model_summary], known_evidence_refs=set())

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:bad-report-note-backed", "note:bad-report-provenance"])
        self.assertTrue(any("unresolved evidence citation" in error for error in result.errors))
        self.assertTrue(any("unresolved note citation" in error for error in result.errors))

    def test_report_sink_rejects_rag_with_unsupported_source_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:report-unsupported-source-refs",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="report_generation",
            sink="report",
            content="Report RAG context must not hide unsupported provenance.",
            citations=["rag:report-unsupported-source-refs"],
            metadata={"source_refs": ["github:issue-42"]},
        )

        result = ContextSinkValidator().validate("report", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:report-unsupported-source-refs"])
        self.assertTrue(any("unsupported source_refs" in error for error in result.errors))

    def test_direct_report_sink_rejects_rag_with_unsupported_source_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:direct-report-unsupported-source-refs",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="report_generation",
            sink="report",
            content="Direct report validation must not let RAG hide unsupported provenance.",
            citations=["rag:direct-report-unsupported-source-refs"],
            metadata={"source_refs": ["github:issue-42"]},
        )

        decision = validate_report_sink(envelope)

        self.assertEqual(decision.action, "reject")
        self.assertIn("unsupported source_refs", decision.message)
        self.assertIn("github:issue-42", decision.message)

    def test_direct_report_sink_rejects_operator_note_with_unsupported_source_refs(self) -> None:
        note = ContextEnvelope(
            ref="note:direct-report-unsupported-source-refs",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            purpose="report_generation",
            sink="report",
            content="Direct report validation must not let operator notes hide unsupported provenance.",
            citations=["note:direct-report-unsupported-source-refs"],
            metadata={"source_refs": ["github:issue-42"]},
        )

        decision = validate_report_sink(note)

        self.assertEqual(decision.action, "reject")
        self.assertIn("unsupported source_refs", decision.message)
        self.assertIn("github:issue-42", decision.message)

    def test_report_sink_rejects_rag_with_unresolved_source_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:report-unresolved-source-refs",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="report_generation",
            sink="report",
            content="Report RAG context must not cite unresolved evidence provenance.",
            citations=["rag:report-unresolved-source-refs", "evidence:missing-banner"],
            metadata={"source_refs": ["evidence:missing-banner"]},
        )

        result = ContextSinkValidator().validate(
            "report",
            [envelope],
            known_evidence_refs=set(),
            known_rag_refs={"rag:report-unresolved-source-refs"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:report-unresolved-source-refs"])
        self.assertTrue(any("unresolved evidence citation" in error for error in result.errors))


class ContextNormalizationTests(unittest.TestCase):
    def test_canonical_rag_domain_normalizes_shared_aliases(self) -> None:
        from primordial.core.context.normalization import canonical_rag_domain

        self.assertEqual(canonical_rag_domain("HTB Writeup"), "htb_writeup")
        self.assertEqual(canonical_rag_domain("API Web"), "api_security")
        self.assertEqual(canonical_rag_domain("vulnerability_intel"), "vuln_intel")
        self.assertEqual(canonical_rag_domain("future-domain"), "general_security")

    def test_metadata_helpers_preserve_human_readable_values(self) -> None:
        from primordial.core.context.normalization import metadata_bool_value, metadata_list_value, metadata_value

        metadata = {
            "Source trust": "official_feed",
            "CVE IDs": ("CVE-2026-0001", "CVE-2026-0002"),
            "Walkthrough hint": "yes",
        }

        self.assertEqual(metadata_value(metadata, "source_trust"), "official_feed")
        self.assertEqual(metadata_list_value(metadata, "cve_ids"), ["CVE-2026-0001", "CVE-2026-0002"])
        self.assertTrue(metadata_bool_value(metadata, "walkthrough_hint"))

    def test_rag_envelope_preserves_human_readable_binding_metadata(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "display-binding",
                "text": "Advisory context with display metadata.",
                "metadata": {
                    "Target ID": "target-a",
                    "Active generation ID": "generation:2",
                    "Corpus type": "vuln_intel",
                    "Domain": "vuln_intel",
                    "Valid for": ("planner", "vuln_hint_for_target"),
                    "Invalid for": "evidence",
                    "Poison flags": ("generated_export",),
                },
            },
            purpose="planner",
            sink="prompt",
        )

        self.assertEqual(envelope.target_id, "target-a")
        self.assertEqual(envelope.active_generation_id, "generation:2")
        self.assertEqual(envelope.corpus, "vuln_intel")
        self.assertEqual(envelope.domain, "vuln_intel")
        self.assertEqual(envelope.valid_for, ["planner", "vuln_hint_for_target"])
        self.assertEqual(envelope.invalid_for, ["evidence"])
        self.assertEqual(envelope.poison_flags, ["generated_export"])

    def test_rag_envelope_preserves_human_readable_citation_id(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "display-citation-chunk",
                "text": "Advisory context with display-key citation metadata.",
                "metadata": {
                    "Citation ID": "display-citation-source",
                    "Corpus type": "vuln_intel",
                    "Domain": "vuln_intel",
                },
            },
            purpose="planner",
            sink="prompt",
        )

        self.assertEqual(envelope.ref, "rag:display-citation-source")
        self.assertEqual(envelope.citations, ["rag:display-citation-source"])

    def test_rag_envelope_preserves_human_readable_retrieval_text(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "display-retrieval-text",
                "metadata": {
                    "Retrieval text": "Display-key advisory RAG text must remain envelope content.",
                    "Citation ID": "display-retrieval-source",
                    "Corpus type": "methodology_standards",
                    "Domain": "methodology_standards",
                },
            },
            purpose="operator_answer",
            sink="prompt",
        )

        self.assertEqual(envelope.content, "Display-key advisory RAG text must remain envelope content.")
        self.assertEqual(envelope.ref, "rag:display-retrieval-source")

    def test_rag_envelope_preserves_human_readable_raw_text(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "display-raw-text",
                "metadata": {
                    "Raw text": "Display-key raw RAG text must remain envelope content.",
                    "Citation ID": "display-raw-source",
                    "Corpus type": "methodology_standards",
                    "Domain": "methodology_standards",
                },
            },
            purpose="operator_answer",
            sink="prompt",
        )

        self.assertEqual(envelope.content, "Display-key raw RAG text must remain envelope content.")
        self.assertEqual(envelope.ref, "rag:display-raw-source")

if __name__ == "__main__":
    unittest.main()
