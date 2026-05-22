from __future__ import annotations

import unittest

from primordial.core.context import ContextEnvelope, ContextSinkValidator


class ContextEvidenceCitationRefTests(unittest.TestCase):
    def test_evidence_sink_rejects_unresolved_evidence_citation_support(self) -> None:
        envelope = ContextEnvelope(
            ref="evidence:scan-1",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:1",
            purpose="evidence_review",
            sink="evidence",
            content="Observed banner output from the current target.",
            citations=["evidence:made-up"],
        )

        result = ContextSinkValidator().validate(
            "evidence",
            [envelope],
            known_evidence_refs={"evidence:observed-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["evidence:scan-1"])
        self.assertTrue(any("unresolved evidence citation" in error for error in result.errors))
        self.assertTrue(any("evidence:made-up" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
