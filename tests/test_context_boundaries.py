from __future__ import annotations

import unittest

from primordial.core.context import CitationValidator, ContextEnvelope, ContextSinkValidator
from primordial.runtime import PrimordialRuntime


class ContextBoundaryTests(unittest.TestCase):
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

    def test_github_issue_sink_rejects_target_authority_and_sensitive_raw_evidence(self) -> None:
        target_authority = ContextEnvelope(
            ref="github:issue-target-truth",
            kind="github_ref",
            authority="authoritative",
            source_type="github",
            purpose="patch_planning",
            sink="github_issue",
            content="A GitHub issue must not become target authority.",
            citations=["github:issue-target-truth"],
            metadata={"creates_target_authority": True},
        )
        raw_evidence = ContextEnvelope(
            ref="github:issue-raw-evidence",
            kind="github_ref",
            authority="asserted",
            source_type="github",
            purpose="patch_planning",
            sink="github_issue",
            content="Raw request/response body or secret-like target evidence belongs in the runtime store, not GitHub.",
            citations=["evidence:scan-1"],
            metadata={"contains_sensitive_raw_target_evidence": True, "redacted": False},
        )

        result = ContextSinkValidator().validate("github_issue", [target_authority, raw_evidence])

        self.assertFalse(result.valid)
        self.assertEqual(result.rejected_refs, ["github:issue-raw-evidence", "github:issue-target-truth"])
        self.assertTrue(any("must not create target authority" in error for error in result.errors))
        self.assertTrue(any("requires redacted evidence refs" in error for error in result.errors))

    def test_github_issue_sink_accepts_redacted_engineering_context(self) -> None:
        envelope = ContextEnvelope(
            ref="github:issue-parser-regression",
            kind="github_ref",
            authority="asserted",
            source_type="github",
            purpose="patch_planning",
            sink="github_issue",
            content="Parser regression needs a failing test and patch proposal.",
            citations=["evidence:redacted-scan-1"],
            metadata={
                "context_type": "failure_analysis",
                "redacted": True,
                "evidence_refs": ["evidence:redacted-scan-1"],
                "test_ids": ["tests.test_context_boundaries"],
            },
        )

        result = ContextSinkValidator().validate("github_issue", [envelope])

        self.assertTrue(result.valid)
        self.assertEqual(result.accepted_refs, ["github:issue-parser-regression"])
        self.assertEqual(result.errors, [])
        self.assertEqual(result.warnings, [])

    def test_ctfd_submission_sink_blocks_recon_only_flag_submission(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:submission-user",
            kind="ctfd_ref",
            authority="asserted",
            source_type="ctfd",
            purpose="ctf_benchmark",
            sink="ctfd_submission",
            content="Submit captured user flag to the scoreboard.",
            citations=["evidence:flag-proof"],
            metadata={
                "active_intent": "recon_only",
                "submission_type": "flag",
                "contains_captured_flag": True,
                "evidence_refs": ["evidence:flag-proof"],
            },
        )

        result = ContextSinkValidator().validate("ctfd_submission", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.rejected_refs, ["ctfd:submission-user"])
        self.assertTrue(any("requires ctf solve intent" in error for error in result.errors))

    def test_ctfd_submission_sink_blocks_human_readable_recon_flag_submission(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:display-submission-user",
            kind="ctfd_ref",
            authority="asserted",
            source_type="ctfd",
            purpose="ctf_benchmark",
            sink="ctfd_submission",
            content="Submit captured user flag to the scoreboard.",
            citations=["evidence:flag-proof"],
            metadata={
                "Active intent": "Recon only",
                "Submission type": "Flag",
                "Contains captured flag": True,
                "Evidence refs": ["evidence:flag-proof"],
            },
        )

        result = ContextSinkValidator().validate("ctfd_submission", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:display-submission-user"])
        self.assertTrue(any("requires ctf solve intent" in error for error in result.errors))

    def test_ctfd_submission_sink_rejects_hidden_or_raw_flag_material(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:hidden-expected-flag",
            kind="ctfd_ref",
            authority="asserted",
            source_type="ctfd",
            purpose="ctf_benchmark",
            sink="ctfd_submission",
            content="Hidden expected flag must stay in the scorer, not solver context.",
            citations=[],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "submission_type": "flag",
                "contains_raw_expected_flag": True,
                "hidden_solution_material": True,
            },
        )

        result = ContextSinkValidator().validate("ctfd_submission", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.rejected_refs, ["ctfd:hidden-expected-flag"])
        self.assertTrue(any("must not expose hidden or raw flag material" in error for error in result.errors))

    def test_ctfd_submission_sink_accepts_scoreboard_projection_without_authority(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:challenge-42",
            kind="ctfd_ref",
            authority="asserted",
            source_type="ctfd",
            purpose="ctf_benchmark",
            sink="ctfd_submission",
            content="Challenge metadata projection: Web category, 100 points, unsolved.",
            citations=[],
            metadata={
                "projection_type": "scoreboard",
                "challenge_id": "42",
                "solved": False,
                "creates_target_authority": False,
            },
        )

        result = ContextSinkValidator().validate("ctfd_submission", [envelope])

        self.assertTrue(result.valid)
        self.assertEqual(result.accepted_refs, ["ctfd:challenge-42"])
        self.assertEqual(result.errors, [])
        self.assertEqual(result.warnings, [])

    def test_operational_rag_synthesis_requires_supplied_context(self) -> None:
        runtime = self._runtime_without_store()

        result = runtime.synthesize_rag_answer(
            "What should the planner do next?",
            mode="planner",
        )

        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "operational_context_required")
        self.assertIn("retrieved_chunks", result["error"])

    def test_operational_rag_synthesis_normalizes_human_readable_purposes(self) -> None:
        runtime = self._runtime_without_store()

        result = runtime.synthesize_rag_answer(
            "Prepare a Notion export summary.",
            mode="Notion export",
        )

        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "operational_context_required")
        self.assertIn("retrieved_chunks", result["error"])

    def test_operator_answer_rag_synthesis_requires_supplied_context(self) -> None:
        runtime = self._runtime_without_store()

        result = runtime.synthesize_rag_answer(
            "Answer the operator about current target state.",
            mode="operator_answer",
        )

        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "operational_context_required")
        self.assertIn("retrieved_chunks", result["error"])

    def test_report_mode_rag_synthesis_requires_supplied_context(self) -> None:
        runtime = self._runtime_without_store()

        result = runtime.synthesize_rag_answer(
            "Prepare a durable report summary.",
            mode="report",
        )

        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "operational_context_required")
        self.assertIn("retrieved_chunks", result["error"])

    def _runtime_without_store(self) -> PrimordialRuntime:
        runtime = PrimordialRuntime.__new__(PrimordialRuntime)
        runtime.rag_search = _blocked_rag_search  # type: ignore[method-assign]
        return runtime


def _blocked_rag_search(*_args: object, **_kwargs: object) -> dict[str, object]:
    raise AssertionError("unscoped fallback search was called")


if __name__ == "__main__":
    unittest.main()
