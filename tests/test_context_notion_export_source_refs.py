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

    def test_quarantines_ai_summary_with_unresolved_note_source_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="model:fabricated-note-export-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="export",
            sink="notion_export",
            content="Export summaries must not cite fabricated operator notes as provenance.",
            citations=["note:made-up"],
            metadata={"source_refs": ["note:made-up"]},
        )

        result = ContextSinkValidator().validate(
            "notion_export",
            [envelope],
            known_note_refs={"note:operator-1"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["model:fabricated-note-export-summary"])
        self.assertTrue(any("unresolved note citation" in error for error in result.errors))
        self.assertTrue(any("note:made-up" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
