from __future__ import annotations

from tests.test_context_notion_export_common import *


class ContextNotionExportTestsPart2(ContextNotionExportTestsBase):
    def test_quarantines_malformed_evidence_records_from_evidence_section(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="evidence:scan-1",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                target_id="target-a",
                purpose="export",
                sink="notion_export",
                content="Observed scanner output belongs in the evidence section.",
                citations=["evidence:scan-1"],
            ),
            ContextEnvelope(
                ref="evidence:advisory-proof",
                kind="evidence",
                authority="advisory",
                source_type="tool_output",
                target_id="target-a",
                purpose="export",
                sink="notion_export",
                content="Advisory authority must not render as Notion observed evidence.",
                citations=["evidence:advisory-proof"],
            ),
            ContextEnvelope(
                ref="model:evidence-shaped",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                target_id="target-a",
                purpose="export",
                sink="notion_export",
                content="A non-evidence ref must not render as Notion observed evidence.",
                citations=["evidence:scan-1"],
            ),
        ]

        result = ContextSinkValidator().validate("notion_export", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["evidence:scan-1"])
        self.assertEqual(result.quarantined_refs, ["evidence:advisory-proof", "model:evidence-shaped"])
        self.assertTrue(any("proof section rejects authority=advisory" in error for error in result.errors))
        self.assertTrue(any("proof section requires evidence:<id> ref" in error for error in result.errors))

    def test_quarantines_non_evidence_sources_from_reviewed_findings(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="finding:runtime",
                kind="finding",
                authority="reviewed",
                source_type="runtime_state",
                target_id="target-a",
                purpose="export",
                sink="notion_export",
                content="Runtime-reviewed finding belongs in reviewed finding exports.",
                citations=["evidence:scan-1"],
            ),
            ContextEnvelope(
                ref="finding:notion-projection",
                kind="finding",
                authority="reviewed",
                source_type="notion",
                target_id="target-a",
                purpose="export",
                sink="notion_export",
                content="Notion-originated prose must not export as a reviewed finding.",
                citations=["evidence:scan-1"],
            ),
            ContextEnvelope(
                ref="finding:github-issue",
                kind="finding",
                authority="reviewed",
                source_type="github",
                target_id="target-a",
                purpose="export",
                sink="notion_export",
                content="GitHub issue prose must not export as a reviewed finding.",
                citations=["evidence:scan-1"],
            ),
            ContextEnvelope(
                ref="finding:vuln-intel",
                kind="finding",
                authority="reviewed",
                source_type="vuln_intel",
                target_id="target-a",
                purpose="export",
                sink="notion_export",
                content="Vulnerability intelligence must remain advisory, not a reviewed finding.",
                citations=["evidence:scan-1"],
            ),
        ]

        result = ContextSinkValidator().validate("notion_export", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["finding:runtime"])
        self.assertEqual(
            result.quarantined_refs,
            ["finding:github-issue", "finding:notion-projection", "finding:vuln-intel"],
        )
        for source_type in ("github", "notion", "vuln_intel"):
            self.assertTrue(any(f"source_type={source_type}" in error for error in result.errors), source_type)

    def test_quarantines_finding_shaped_records_without_finding_refs(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="finding:runtime",
                kind="finding",
                authority="reviewed",
                source_type="runtime_state",
                target_id="target-a",
                purpose="export",
                sink="notion_export",
                content="Runtime-reviewed finding belongs in reviewed finding exports.",
                citations=["evidence:scan-1"],
            ),
            ContextEnvelope(
                ref="model:finding-shaped",
                kind="finding",
                authority="reviewed",
                source_type="runtime_state",
                target_id="target-a",
                purpose="export",
                sink="notion_export",
                content="A non-finding ref must not export as a reviewed finding.",
                citations=["evidence:scan-1"],
            ),
        ]

        result = ContextSinkValidator().validate("notion_export", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["finding:runtime"])
        self.assertEqual(result.quarantined_refs, ["model:finding-shaped"])
        self.assertTrue(any("finding:<id>" in error for error in result.errors))

    def test_quarantines_raw_sensitive_material(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="ctfd:raw-flag",
                kind="ctfd_ref",
                authority="asserted",
                source_type="ctfd",
                target_id="target-a",
                purpose="export",
                sink="notion_export",
                content="Raw expected flag must not be projected to Notion.",
                citations=["ctfd:raw-flag"],
                metadata={"contains_raw_expected_flag": True},
            ),
            ContextEnvelope(
                ref="note:secret",
                kind="operator_note",
                authority="asserted",
                source_type="manual_artifact",
                target_id="target-a",
                purpose="export",
                sink="notion_export",
                content="Secret-bearing note must not be projected to Notion.",
                citations=["note:secret"],
                poison_flags=["contains_secret"],
            ),
        ]

        result = ContextSinkValidator().validate("notion_export", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["ctfd:raw-flag", "note:secret"])
        self.assertTrue(any("raw sensitive material" in error for error in result.errors))

    def test_quarantines_raw_chat_context(self) -> None:
        envelope = ContextEnvelope(
            ref="note:raw-chat",
            kind="operator_note",
            authority="asserted",
            source_type="chat",
            target_id="target-a",
            purpose="export",
            sink="notion_export",
            content="Raw chat transcript must not be projected to Notion.",
            citations=["note:raw-chat"],
        )

        result = ContextSinkValidator().validate("notion_export", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["note:raw-chat"])
        self.assertTrue(any("raw chat context" in error for error in result.errors))

    def test_quarantines_generated_export_recursion(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="export:notion-old",
                kind="generated_export",
                authority="derived",
                source_type="generated_export",
                purpose="export",
                sink="notion_export",
                content="A previous generated Notion export must not feed a fresh export.",
                citations=["evidence:scan-1"],
            ),
            ContextEnvelope(
                ref="export:archive-old",
                kind="export_archive",
                authority="historical",
                source_type="export_archive",
                purpose="export",
                sink="notion_export",
                content="Archived export prose is not source material for a new export.",
                citations=["evidence:scan-1"],
            ),
            ContextEnvelope(
                ref="model:export-derived-summary",
                kind="model_summary",
                authority="derived",
                source_type="ai_output",
                purpose="export",
                sink="notion_export",
                content="An AI summary derived from a generated export must be quarantined.",
                citations=["evidence:scan-1"],
                metadata={"origin": "generated export", "source_refs": ["evidence:scan-1"]},
            ),
        ]

        result = ContextSinkValidator().validate("notion_export", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(
            result.quarantined_refs,
            ["export:archive-old", "export:notion-old", "model:export-derived-summary"],
        )
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_quarantines_human_readable_generated_export_origin(self) -> None:
        envelope = ContextEnvelope(
            ref="model:display-origin-export-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="export",
            sink="notion_export",
            content="Display-style generated export origin metadata must still quarantine summaries.",
            citations=["evidence:scan-1"],
            metadata={"Origin": "Generated export", "source_refs": ["evidence:scan-1"]},
        )

        result = ContextSinkValidator().validate("notion_export", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["model:display-origin-export-summary"])
        self.assertTrue(any("generated export" in error for error in result.errors))

__all__ = ["ContextNotionExportTestsPart2"]
