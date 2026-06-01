from __future__ import annotations

from tests.test_context_sinks_common import *


class ContextSinkValidatorTestsPart1(ContextSinkValidatorTestsBase):
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

__all__ = ["ContextSinkValidatorTestsPart1"]
