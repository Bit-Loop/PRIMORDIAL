from __future__ import annotations

from tests.test_context_boundaries_common import *


class ContextBoundaryTestsPart2(ContextBoundaryTestsBase):
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

__all__ = ["ContextBoundaryTestsPart2"]
