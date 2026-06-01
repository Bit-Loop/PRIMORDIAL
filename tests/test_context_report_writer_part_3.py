from __future__ import annotations

from tests.test_context_report_writer_common import *


class ContextReportWriterTestsPart3(ContextReportWriterTestsBase):
    def test_report_sink_rejects_non_evidence_sources_from_evidence_records(self) -> None:
        result = ContextSinkValidator().validate("report", self._non_evidence_report_envelopes())

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["evidence:scan-1"])
        self.assertEqual(
            result.rejected_refs,
            [
                "evidence:ai-summary",
                "evidence:ctfd-challenge",
                "evidence:github-issue",
                "evidence:notion-projection",
                "evidence:vuln-intel",
            ],
        )
        for source_type in ("ai_output", "ctfd", "github", "notion", "vuln_intel"):
            self.assertTrue(any(f"source_type={source_type}" in error for error in result.errors), source_type)

    def _non_evidence_report_envelopes(self) -> list[ContextEnvelope]:
        return [
            ContextEnvelope(
                ref="evidence:scan-1",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="Observed scanner output is valid report evidence.",
                citations=["evidence:scan-1"],
            ),
            ContextEnvelope(
                ref="evidence:notion-projection",
                kind="evidence",
                authority="observed",
                source_type="notion",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="Notion projection must not render as report evidence.",
                citations=["evidence:notion-projection"],
            ),
            ContextEnvelope(
                ref="evidence:github-issue",
                kind="evidence",
                authority="observed",
                source_type="github",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="GitHub issue prose must not render as report evidence.",
                citations=["evidence:github-issue"],
            ),
            ContextEnvelope(
                ref="evidence:ctfd-challenge",
                kind="evidence",
                authority="observed",
                source_type="ctfd",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="CTFd challenge metadata must not render as report evidence.",
                citations=["evidence:ctfd-challenge"],
            ),
            ContextEnvelope(
                ref="evidence:vuln-intel",
                kind="evidence",
                authority="observed",
                source_type="vuln_intel",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="Vulnerability intelligence must remain advisory in reports.",
                citations=["evidence:vuln-intel"],
            ),
            ContextEnvelope(
                ref="evidence:ai-summary",
                kind="evidence",
                authority="observed",
                source_type="ai_output",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="Model output must not render as report evidence.",
                citations=["evidence:ai-summary"],
            ),
        ]

    def test_report_sink_rejects_malformed_evidence_records(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="evidence:scan-1",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="Observed scanner output is valid report evidence.",
                citations=["evidence:scan-1"],
            ),
            ContextEnvelope(
                ref="evidence:advisory-proof",
                kind="evidence",
                authority="advisory",
                source_type="tool_output",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="Advisory authority must not render as report evidence.",
                citations=["evidence:advisory-proof"],
            ),
            ContextEnvelope(
                ref="model:evidence-shaped",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="A non-evidence ref must not render as report evidence.",
                citations=["evidence:scan-1"],
            ),
        ]

        result = ContextSinkValidator().validate("report", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["evidence:scan-1"])
        self.assertEqual(result.rejected_refs, ["evidence:advisory-proof", "model:evidence-shaped"])
        self.assertTrue(any("rejects evidence authority=advisory" in error for error in result.errors))
        self.assertTrue(any("requires evidence:<id> ref" in error for error in result.errors))

    def test_report_sink_rejects_non_evidence_sources_from_reviewed_findings(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="finding:runtime",
                kind="finding",
                authority="reviewed",
                source_type="runtime_state",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="Runtime-reviewed finding belongs in reports.",
                citations=["evidence:scan-1"],
            ),
            ContextEnvelope(
                ref="finding:notion-projection",
                kind="finding",
                authority="reviewed",
                source_type="notion",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="Notion projection must not render as a reviewed report finding.",
                citations=["evidence:scan-1"],
            ),
            ContextEnvelope(
                ref="finding:github-issue",
                kind="finding",
                authority="reviewed",
                source_type="github",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="GitHub issue prose must not render as a reviewed report finding.",
                citations=["evidence:scan-1"],
            ),
            ContextEnvelope(
                ref="finding:ai-summary",
                kind="finding",
                authority="reviewed",
                source_type="ai_output",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="Model output must not render as a reviewed report finding.",
                citations=["evidence:scan-1"],
            ),
        ]

        result = ContextSinkValidator().validate("report", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["finding:runtime"])
        self.assertEqual(
            result.rejected_refs,
            ["finding:ai-summary", "finding:github-issue", "finding:notion-projection"],
        )
        for source_type in ("ai_output", "github", "notion"):
            self.assertTrue(any(f"source_type={source_type}" in error for error in result.errors), source_type)

    def test_report_sink_rejects_masked_nested_non_evidence_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="evidence:masked-model-proof",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            target_id="target-a",
            purpose="report_generation",
            sink="report",
            content="Top-level evidence source type must not mask nested model provenance.",
            citations=["evidence:masked-model-proof"],
            metadata={
                "metadata": {
                    "source_type": "ai_output",
                },
            },
        )

        result = ContextSinkValidator().validate("report", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["evidence:masked-model-proof"])
        self.assertTrue(any("source_type=ai_output" in error for error in result.errors))

    def test_report_sink_rejects_ai_output_disguised_as_operator_note(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="note:manual-operator",
                kind="operator_note",
                authority="asserted",
                source_type="manual_artifact",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="Human operator notes may provide report context.",
                citations=["note:manual-operator"],
            ),
            ContextEnvelope(
                ref="note:model-generated",
                kind="operator_note",
                authority="asserted",
                source_type="ai_output",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="Model prose must not masquerade as an operator note in report context.",
                citations=["note:model-generated"],
            ),
        ]

        result = ContextSinkValidator().validate("report", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["note:manual-operator"])
        self.assertEqual(result.rejected_refs, ["note:model-generated"])
        self.assertTrue(any("non_operator_note_source" in error for error in result.errors))

__all__ = ["ContextReportWriterTestsPart3"]
