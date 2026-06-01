from __future__ import annotations

from tests.test_context_report_writer_common import *


class ContextReportWriterTestsPart4(ContextReportWriterTestsBase):
    def test_report_sink_rejects_finding_shaped_records_without_finding_refs(self) -> None:
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
                ref="model:finding-shaped",
                kind="finding",
                authority="reviewed",
                source_type="runtime_state",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="A non-finding ref must not render as a reviewed report finding.",
                citations=["evidence:scan-1"],
            ),
        ]

        result = ContextSinkValidator().validate("report", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["finding:runtime"])
        self.assertEqual(result.rejected_refs, ["model:finding-shaped"])
        self.assertTrue(any("finding:<id>" in error for error in result.errors))

    def test_report_writer_omits_unbound_model_target_fact_from_current_packet(self) -> None:
        envelope = ContextEnvelope(
            ref="model:unbound-target-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="report_generation",
            sink="prompt",
            content="The target reports nginx in the HTTP banner.",
            citations=["evidence:http-banner"],
            metadata={"contains_target_fact": True},
        )

        packet = ContextAssembler().assemble(
            [envelope],
            purpose="report_generation",
            role="report_writer",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["model:unbound-target-summary"], "missing_target_binding")
        self.assertNotIn("nginx", packet["rendered"])

    def test_report_writer_omits_unbound_reviewed_findings_from_current_packet(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="finding:no-target",
                kind="finding",
                authority="reviewed",
                source_type="runtime_state",
                active_generation_id="generation:2",
                purpose="report_generation",
                sink="prompt",
                content="Unbound reviewed finding must not enter a current target report.",
                citations=["evidence:http-banner"],
            ),
            ContextEnvelope(
                ref="finding:no-generation",
                kind="finding",
                authority="reviewed",
                source_type="runtime_state",
                target_id="target-a",
                purpose="report_generation",
                sink="prompt",
                content="Generationless reviewed finding must not enter a current target report.",
                citations=["evidence:http-banner"],
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="report_generation",
            role="report_writer",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["REVIEWED_FINDINGS"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["finding:no-target"], "missing_target_binding")
        self.assertEqual(omitted_refs["finding:no-generation"], "missing_generation_binding")
        self.assertNotIn("Unbound reviewed finding", packet["rendered"])
        self.assertNotIn("Generationless reviewed finding", packet["rendered"])

__all__ = ["ContextReportWriterTestsPart4"]
