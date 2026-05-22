from __future__ import annotations

import unittest

from primordial.core.context import ContextEnvelope, ContextSinkValidator


class ContextReportSourceRefTests(unittest.TestCase):
    def test_report_sink_rejects_ai_summary_with_unsupported_source_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="model:github-source-ref-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="report_generation",
            sink="report",
            content="Report summaries must not hide collaboration provenance in source_refs metadata.",
            citations=["evidence:http-banner"],
            metadata={"source_refs": ["evidence:http-banner", "github:issue-42"]},
        )

        result = ContextSinkValidator().validate(
            "report",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:github-source-ref-summary"])
        self.assertTrue(any("unsupported source_refs" in error for error in result.errors))
        self.assertTrue(any("github:issue-42" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
