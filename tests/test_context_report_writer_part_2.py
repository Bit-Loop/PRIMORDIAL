from __future__ import annotations

from tests.test_context_report_writer_common import *


class ContextReportWriterTestsPart2(ContextReportWriterTestsBase):
    def test_report_sink_rejects_ai_summary_with_only_collaboration_citation(self) -> None:
        envelope = ContextEnvelope(
            ref="model:github-only-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="report_generation",
            sink="report",
            content="AI-derived report context must not be backed only by collaboration prose.",
            citations=["github:issue-42"],
        )

        result = ContextSinkValidator().validate("report", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:github-only-summary"])
        self.assertTrue(any("evidence:<id>, note:<id>, or rag:<chunk_id>" in error for error in result.errors))

    def test_report_sink_rejects_ai_summary_with_mixed_collaboration_citation(self) -> None:
        envelope = ContextEnvelope(
            ref="model:github-mixed-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="report_generation",
            sink="report",
            content="AI-derived report context must not mix evidence with collaboration provenance.",
            citations=["evidence:http-banner", "github:issue-42"],
        )

        result = ContextSinkValidator().validate("report", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:github-mixed-summary"])
        self.assertTrue(any("unsupported citations" in error for error in result.errors))
        self.assertTrue(any("github:issue-42" in error for error in result.errors))

    def test_report_sink_rejects_truth_like_authority_on_ai_summary(self) -> None:
        envelope = ContextEnvelope(
            ref="model:confirmed-summary",
            kind="model_summary",
            authority="confirmed",
            source_type="ai_output",
            target_id="target-a",
            purpose="report_generation",
            sink="report",
            content="AI-derived report context must not claim confirmed target truth.",
            citations=["evidence:http-banner"],
        )

        result = ContextSinkValidator().validate("report", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:confirmed-summary"])
        self.assertTrue(any("truth-like authority" in error for error in result.errors))

    def test_report_sink_rejects_nested_truth_like_authority_on_ai_summary(self) -> None:
        envelope = ContextEnvelope(
            ref="model:nested-confirmed-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="report_generation",
            sink="report",
            content="Nested metadata must not let AI-derived report context claim confirmed target truth.",
            citations=["evidence:http-banner"],
            metadata={
                "source_refs": ["evidence:http-banner"],
                "metadata": {"authority": "confirmed"},
            },
        )

        result = ContextSinkValidator().validate(
            "report",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:nested-confirmed-summary"])
        self.assertTrue(any("truth-like authority" in error for error in result.errors))

    def test_report_sink_rejects_plural_nested_truth_like_authorities_on_ai_summary(self) -> None:
        envelope = ContextEnvelope(
            ref="model:nested-confirmed-authorities-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="report_generation",
            sink="report",
            content="Nested plural metadata must not let AI-derived report context claim confirmed target truth.",
            citations=["evidence:http-banner"],
            metadata={
                "source_refs": ["evidence:http-banner"],
                "metadata": {"authorities": ["confirmed"]},
            },
        )

        result = ContextSinkValidator().validate(
            "report",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:nested-confirmed-authorities-summary"])
        self.assertTrue(any("truth-like authority" in error for error in result.errors))

    def test_report_sink_rejects_generated_export_recursion(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="model:generated-export-report-summary",
                kind="model_summary",
                authority="derived",
                source_type="generated_export",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="A previous generated export must not feed report output as model prose.",
                citations=["evidence:http-banner"],
            ),
            ContextEnvelope(
                ref="model:export-origin-report-summary",
                kind="model_summary",
                authority="derived",
                source_type="ai_output",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="AI prose derived from a generated export must not feed report output.",
                citations=["evidence:http-banner"],
                metadata={"origin": "generated export"},
            ),
        ]

        result = ContextSinkValidator().validate(
            "report",
            envelopes,
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(
            result.rejected_refs,
            ["model:export-origin-report-summary", "model:generated-export-report-summary"],
        )
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_report_sink_rejects_generated_export_source_path(self) -> None:
        envelope = ContextEnvelope(
            ref="model:export-path-report-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="report_generation",
            sink="report",
            content="AI prose sourced from a generated Notion export must not feed report output.",
            citations=["evidence:http-banner"],
            metadata={
                "source_file": "findings/notion/target-a/notion-export.md",
                "source_refs": ["evidence:http-banner"],
            },
        )

        result = ContextSinkValidator().validate(
            "report",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:export-path-report-summary"])
        self.assertTrue(any("generated export" in error for error in result.errors))

__all__ = ["ContextReportWriterTestsPart2"]
