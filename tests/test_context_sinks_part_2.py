from __future__ import annotations

from tests.test_context_sinks_common import *


class ContextSinkValidatorTestsPart2(ContextSinkValidatorTestsBase):
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

__all__ = ["ContextSinkValidatorTestsPart2"]
