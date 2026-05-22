from __future__ import annotations

import unittest

from primordial.core.context import ContextEnvelope, ContextSinkValidator


class ContextNotionExportSourceRefTests(unittest.TestCase):
    def test_quarantines_ai_summary_with_mapping_source_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="model:mapping-source-refs",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="export",
            sink="notion_export",
            content="AI summary source refs must be explicit scalar refs, not nested metadata.",
            citations=["evidence:scan-1"],
            metadata={"source_refs": {"primary": "evidence:scan-1"}},
        )

        result = ContextSinkValidator().validate(
            "notion_export",
            [envelope],
            known_evidence_refs={"evidence:scan-1"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["model:mapping-source-refs"])
        self.assertTrue(any("malformed source_refs" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
