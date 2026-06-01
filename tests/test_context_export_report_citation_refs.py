from __future__ import annotations

import unittest

from primordial.core.context import ContextEnvelope, ContextSinkValidator


class ContextExportReportCitationRefTests(unittest.TestCase):
    def test_report_sink_rejects_ai_target_fact_with_unresolved_evidence_citation(self) -> None:
        envelope = ContextEnvelope(
            ref="model:fabricated-report-evidence",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="report_generation",
            sink="report",
            content="The target is running Apache 2.4.49.",
            citations=["evidence:made-up"],
            metadata={"contains_target_fact": True},
        )

        result = ContextSinkValidator().validate(
            "report",
            [envelope],
            known_evidence_refs={"evidence:observed-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:fabricated-report-evidence"])
        self.assertTrue(any("unresolved evidence citation" in error for error in result.errors))
        self.assertTrue(any("evidence:made-up" in error for error in result.errors))

    def test_notion_export_quarantines_ai_target_fact_with_unresolved_evidence_citation(self) -> None:
        envelope = ContextEnvelope(
            ref="model:fabricated-export-evidence",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="export",
            sink="notion_export",
            content="The target is running Apache 2.4.49.",
            citations=["evidence:made-up"],
            metadata={"contains_target_fact": True, "source_refs": ["evidence:made-up"]},
        )

        result = ContextSinkValidator().validate(
            "notion_export",
            [envelope],
            known_evidence_refs={"evidence:observed-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["model:fabricated-export-evidence"])
        self.assertTrue(any("unresolved evidence citation" in error for error in result.errors))
        self.assertTrue(any("evidence:made-up" in error for error in result.errors))

    def test_report_sink_rejects_ai_summary_with_unresolved_rag_provenance(self) -> None:
        envelope = ContextEnvelope(
            ref="model:fabricated-report-rag",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="report_generation",
            sink="report",
            content="The report summary cites advisory methodology that was never indexed.",
            citations=["rag:made-up"],
            metadata={"source_refs": ["rag:made-up"]},
        )

        result = ContextSinkValidator().validate(
            "report",
            [envelope],
            known_rag_refs={"rag:indexed-method"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:fabricated-report-rag"])
        self.assertTrue(any("unresolved rag citation" in error for error in result.errors))
        self.assertTrue(any("rag:made-up" in error for error in result.errors))

    def test_notion_export_quarantines_ai_summary_with_unresolved_rag_provenance(self) -> None:
        envelope = ContextEnvelope(
            ref="model:fabricated-export-rag",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="export",
            sink="notion_export",
            content="The export summary cites advisory methodology that was never indexed.",
            citations=["rag:made-up"],
            metadata={"source_refs": ["rag:made-up"]},
        )

        result = ContextSinkValidator().validate(
            "notion_export",
            [envelope],
            known_rag_refs={"rag:indexed-method"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["model:fabricated-export-rag"])
        self.assertTrue(any("unresolved rag citation" in error for error in result.errors))
        self.assertTrue(any("rag:made-up" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
