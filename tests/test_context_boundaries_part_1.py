from __future__ import annotations

from tests.test_context_boundaries_common import *


class ContextBoundaryTestsPart1(ContextBoundaryTestsBase):
    def test_evidence_sink_rejects_rag_and_model_summary_envelopes(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="rag:chunk-api",
                kind="rag",
                authority="advisory",
                source_type="vuln_intel",
                purpose="evidence_review",
                sink="evidence",
                content="A CVE advisory says a package may be affected.",
                citations=["rag:chunk-api"],
            ),
            ContextEnvelope(
                ref="model:summary-1",
                kind="model_summary",
                authority="derived",
                source_type="ai_output",
                purpose="evidence_review",
                sink="evidence",
                content="The model thinks the service is exploitable.",
                citations=[],
            ),
        ]

        result = ContextSinkValidator().validate("evidence", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:summary-1", "rag:chunk-api"])
        self.assertTrue(any("rag:chunk-api" in error for error in result.errors))
        self.assertTrue(any("model:summary-1" in error for error in result.errors))

    def test_notion_export_quarantines_uncited_ai_summary(self) -> None:
        envelope = ContextEnvelope(
            ref="model:summary-uncited",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="export",
            sink="notion_export",
            content="The target probably exposes an admin panel.",
            citations=[],
        )

        result = ContextSinkValidator().validate("notion_export", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.quarantined_refs, ["model:summary-uncited"])
        self.assertTrue(any("missing citations" in error for error in result.errors))

    def test_notion_export_quarantines_duplicate_ai_summary(self) -> None:
        first = ContextEnvelope(
            ref="model:summary-1",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="export",
            sink="notion_export",
            content="The target state is sparse; continue evidence-backed recon.",
            citations=["evidence:scan-1", "rag:method-1"],
            metadata={"source_refs": ["evidence:scan-1", "rag:method-1"]},
        )
        duplicate = ContextEnvelope(
            ref="model:summary-2",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="export",
            sink="notion_export",
            content="The target state is sparse; continue evidence-backed recon.",
            citations=["evidence:scan-1", "rag:method-1"],
            metadata={"source_refs": ["rag:method-1", "evidence:scan-1"]},
        )

        result = ContextSinkValidator().validate("notion_export", [first, duplicate], known_rag_refs=["rag:method-1"])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["model:summary-1"])
        self.assertEqual(result.quarantined_refs, ["model:summary-2"])
        self.assertTrue(any("duplicate AI summary" in error for error in result.errors))

    def test_citation_validator_rejects_rag_as_reviewed_finding_support(self) -> None:
        finding = ContextEnvelope(
            ref="finding:apache-version",
            kind="finding",
            authority="reviewed",
            source_type="ai_output",
            purpose="finding_generation",
            sink="finding",
            content="The target is running Apache 2.4.49.",
            citations=["rag:apache-249"],
        )

        result = CitationValidator().validate([finding])

        self.assertFalse(result.valid)
        self.assertEqual(result.rejected_refs, ["finding:apache-version"])
        self.assertTrue(any("requires evidence:<id>" in error for error in result.errors))
        self.assertTrue(any("rag:apache-249" in error for error in result.errors))

    def test_finding_sink_rejects_rag_only_reviewed_finding(self) -> None:
        finding = ContextEnvelope(
            ref="finding:rag-only",
            kind="finding",
            authority="reviewed",
            source_type="ai_output",
            purpose="finding_generation",
            sink="finding",
            content="RAG-only version claim must not become a reviewed finding.",
            citations=["rag:version-hint"],
        )

        result = ContextSinkValidator().validate("finding", [finding])

        self.assertFalse(result.valid)
        self.assertEqual(result.rejected_refs, ["finding:rag-only"])
        self.assertTrue(any("requires evidence:<id>" in error for error in result.errors))

    def test_task_metadata_sink_rejects_vuln_intel_only_executable_action_under_recon(self) -> None:
        candidate = ContextEnvelope(
            ref="task:cve-exploit-check",
            kind="candidate_task",
            authority="advisory",
            source_type="vuln_intel",
            purpose="task_generation",
            sink="task_metadata",
            target_id="target-a",
            content="Validate public exploit applicability for a CVE mentioned by advisory RAG.",
            citations=["rag:cve-advisory"],
            metadata={
                "active_intent": "recon_only",
                "engagement_profile": "hack_the_box",
                "action_class": "exploit_validation",
                "creates_executable_task": True,
                "supporting_evidence_refs": [],
            },
        )

        result = ContextSinkValidator().validate("task_metadata", [candidate])

        self.assertFalse(result.valid)
        self.assertEqual(result.rejected_refs, ["task:cve-exploit-check"])
        self.assertTrue(any("policy_decision:<id>" in error for error in result.errors))
        self.assertTrue(any("recon_only" in error for error in result.errors))

    def test_rag_index_sink_rejects_generated_exports(self) -> None:
        envelope = ContextEnvelope(
            ref="export:notion-target-1",
            kind="generated_export",
            authority="derived",
            source_type="generated_export",
            purpose="cleanup",
            sink="rag_index",
            content="Generated Notion export prose must not become active RAG.",
            citations=["evidence:current"],
            metadata={
                "ingest_allowed": False,
                "operational_retrieval_allowed": False,
            },
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.rejected_refs, ["export:notion-target-1"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_rag_index_rejects_human_readable_generated_export_deny_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="model:export-derived-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="cleanup",
            sink="rag_index",
            content="Export-derived AI summary must not become active operational RAG.",
            citations=["evidence:current"],
            metadata={
                "Origin": "generated export",
                "Ingest allowed": False,
                "Operational retrieval allowed": False,
            },
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:export-derived-summary"])
        self.assertTrue(any("ingest_allowed=false" in error for error in result.errors))

    def test_discord_notification_quarantines_unlabeled_advisory_context(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:cve-advisory",
            kind="rag",
            authority="advisory",
            source_type="vuln_intel",
            purpose="discord_notification",
            sink="discord_notification",
            content="Potential public exploit reference found for a product string.",
            citations=["rag:cve-advisory"],
        )

        result = ContextSinkValidator().validate("discord_notification", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.quarantined_refs, ["rag:cve-advisory"])
        self.assertTrue(any("requires advisory or unverified label" in error for error in result.errors))

    def test_discord_notification_rejects_evidence_rendering_and_approval_claims(self) -> None:
        evidence_like = ContextEnvelope(
            ref="model:summary-as-evidence",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="discord_notification",
            sink="discord_notification",
            content="The model summary is formatted as proof of exploitability.",
            citations=["evidence:scan-1"],
            metadata={"labels": ["derived"], "renders_as_evidence": True},
        )
        approval_like = ContextEnvelope(
            ref="task:approval-implied",
            kind="candidate_task",
            authority="advisory",
            source_type="vuln_intel",
            purpose="discord_notification",
            sink="discord_notification",
            content="Exploit validation is ready to run.",
            citations=["rag:cve-advisory"],
            metadata={"labels": ["advisory"], "implies_approval": True},
        )

        result = ContextSinkValidator().validate("discord_notification", [evidence_like, approval_like])

        self.assertFalse(result.valid)
        self.assertEqual(result.rejected_refs, ["model:summary-as-evidence", "task:approval-implied"])
        self.assertTrue(any("must not render derived context as evidence" in error for error in result.errors))
        self.assertTrue(any("must not imply approval" in error for error in result.errors))

__all__ = ["ContextBoundaryTestsPart1"]
