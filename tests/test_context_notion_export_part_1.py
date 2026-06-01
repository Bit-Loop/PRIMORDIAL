from __future__ import annotations

from tests.test_context_notion_export_common import *


class ContextNotionExportTestsPart1(ContextNotionExportTestsBase):
    def test_quarantines_ai_summary_with_uncited_source_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="model:hidden-rag-source-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="export",
            sink="notion_export",
            content="AI summaries must cite every declared source ref so provenance stays visible.",
            citations=["evidence:scan-1"],
            metadata={"source_refs": ["evidence:scan-1", "rag:method-1", "note:operator-1"]},
        )

        result = ContextSinkValidator().validate("notion_export", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["model:hidden-rag-source-summary"])
        self.assertTrue(any("uncited source_refs" in error for error in result.errors))

    def test_quarantines_ai_summary_with_uncited_human_readable_scalar_source_ref(self) -> None:
        envelope = ContextEnvelope(
            ref="model:hidden-scalar-rag-source-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="export",
            sink="notion_export",
            content="AI summaries must not hide scalar source refs behind display-style metadata keys.",
            citations=["evidence:scan-1"],
            metadata={"Source refs": "rag:method-1"},
        )

        result = ContextSinkValidator().validate("notion_export", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["model:hidden-scalar-rag-source-summary"])
        self.assertTrue(any("uncited source_refs" in error for error in result.errors))
        self.assertTrue(any("rag:method-1" in error for error in result.errors))

    def test_quarantines_ai_summary_with_collaboration_source_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="model:github-sourced-export-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="export",
            sink="notion_export",
            content="AI summaries must not blend engineering ledger prose into export analysis provenance.",
            citations=["evidence:scan-1", "github:issue-42"],
            metadata={"source_refs": ["evidence:scan-1", "github:issue-42"]},
        )

        result = ContextSinkValidator().validate("notion_export", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["model:github-sourced-export-summary"])
        self.assertTrue(any("unsupported source_refs" in error for error in result.errors))
        self.assertTrue(any("github:issue-42" in error for error in result.errors))

    def test_quarantines_ai_summary_with_collaboration_citations_without_source_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="model:github-cited-export-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="export",
            sink="notion_export",
            content="AI summaries must not blend collaboration citations into export analysis provenance.",
            citations=["evidence:scan-1", "github:issue-42"],
        )

        result = ContextSinkValidator().validate("notion_export", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["model:github-cited-export-summary"])
        self.assertTrue(any("unsupported citations" in error for error in result.errors))
        self.assertTrue(any("github:issue-42" in error for error in result.errors))

    def test_quarantines_truth_like_authority_on_ai_summary(self) -> None:
        envelope = ContextEnvelope(
            ref="model:confirmed-export-summary",
            kind="model_summary",
            authority="confirmed",
            source_type="ai_output",
            target_id="target-a",
            purpose="export",
            sink="notion_export",
            content="AI-generated Notion export summaries must not claim confirmed target truth.",
            citations=["evidence:scan-1"],
            metadata={"source_refs": ["evidence:scan-1"]},
        )

        result = ContextSinkValidator().validate("notion_export", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["model:confirmed-export-summary"])
        self.assertTrue(any("truth-like authority" in error for error in result.errors))

    def test_quarantines_ai_target_fact_supported_only_by_rag(self) -> None:
        envelope = ContextEnvelope(
            ref="model:rag-only-target-fact",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="export",
            sink="notion_export",
            content="The target is running Apache 2.4.49.",
            citations=["rag:apache-249"],
            metadata={"contains_target_fact": True, "source_refs": ["rag:apache-249"]},
        )

        result = ContextSinkValidator().validate("notion_export", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["model:rag-only-target-fact"])
        self.assertTrue(any("requires evidence:<id>" in error for error in result.errors))

    def test_quarantines_placeholder_rag_advisory_export(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:unknown",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            target_id="target-a",
            purpose="export",
            sink="notion_export",
            content="Exported RAG advisory text must have an explicit retrievable identity.",
            citations=["rag:unknown"],
        )

        result = ContextSinkValidator().validate("notion_export", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["rag:unknown"])
        self.assertTrue(any("placeholder rag citation" in error for error in result.errors))

    def test_quarantines_rag_only_reviewed_finding_export(self) -> None:
        envelope = ContextEnvelope(
            ref="finding:rag-only",
            kind="finding",
            authority="reviewed",
            source_type="runtime_state",
            target_id="target-a",
            purpose="export",
            sink="notion_export",
            content="Reviewed finding exports must remain evidence-backed.",
            citations=["rag:version-hint"],
        )

        result = ContextSinkValidator().validate("notion_export", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["finding:rag-only"])
        self.assertTrue(any("requires evidence:<id>" in error for error in result.errors))

    def test_quarantines_non_evidence_sources_from_evidence_section(self) -> None:
        result = ContextSinkValidator().validate("notion_export", self._non_evidence_export_envelopes())

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["evidence:scan-1"])
        self.assertEqual(
            result.quarantined_refs,
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

    def _non_evidence_export_envelopes(self) -> list[ContextEnvelope]:
        return [
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
                ref="evidence:notion-projection",
                kind="evidence",
                authority="observed",
                source_type="notion",
                target_id="target-a",
                purpose="export",
                sink="notion_export",
                content="Notion-originated prose must not render as observed evidence.",
                citations=["evidence:notion-projection"],
            ),
            ContextEnvelope(
                ref="evidence:github-issue",
                kind="evidence",
                authority="observed",
                source_type="github",
                target_id="target-a",
                purpose="export",
                sink="notion_export",
                content="GitHub issue prose must not render as observed evidence.",
                citations=["evidence:github-issue"],
            ),
            ContextEnvelope(
                ref="evidence:ctfd-challenge",
                kind="evidence",
                authority="observed",
                source_type="ctfd",
                target_id="target-a",
                purpose="export",
                sink="notion_export",
                content="CTFd challenge text must not render as observed evidence.",
                citations=["evidence:ctfd-challenge"],
            ),
            ContextEnvelope(
                ref="evidence:vuln-intel",
                kind="evidence",
                authority="observed",
                source_type="vuln_intel",
                target_id="target-a",
                purpose="export",
                sink="notion_export",
                content="Vulnerability intelligence is advisory and must not render as observed evidence.",
                citations=["evidence:vuln-intel"],
            ),
            ContextEnvelope(
                ref="evidence:ai-summary",
                kind="evidence",
                authority="observed",
                source_type="ai_output",
                target_id="target-a",
                purpose="export",
                sink="notion_export",
                content="Model output must not render as observed evidence.",
                citations=["evidence:ai-summary"],
            ),
        ]

__all__ = ["ContextNotionExportTestsPart1"]
