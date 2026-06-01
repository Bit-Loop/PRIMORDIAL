from __future__ import annotations

import unittest

from primordial.labs.ctf import FailureAnalysis
from tests.support import fixture_flag


class FailureAnalysisContractTests(unittest.TestCase):
    def test_failure_analysis_links_failed_solve_to_evidence_policy_models_and_patch_context(self) -> None:
        analysis = FailureAnalysis.create(
            id="failure-juice-1",
            solve_session_id="solve-juice-1",
            failure_class="policy_blocked",
            related_evidence=["evidence:http-title"],
            related_policy_decisions=["policy:block-flag"],
            related_model_runs=["model:solver-run-1"],
            suspected_root_cause="Solver attempted flag submission while active intent was recon_only.",
            proposed_fix="Gate CTFd flag submission on ctf solve intent and supporting evidence.",
            github_issue_id="github:issue-42",
        )

        self.assertEqual(analysis.id, "failure-juice-1")
        self.assertEqual(analysis.solve_session_id, "solve-juice-1")
        self.assertEqual(analysis.failure_class, "policy_blocked")
        self.assertEqual(analysis.related_evidence, ("evidence:http-title",))
        self.assertEqual(analysis.related_policy_decisions, ("policy:block-flag",))
        self.assertEqual(analysis.related_model_runs, ("model:solver-run-1",))
        self.assertEqual(analysis.github_issue_id, "github:issue-42")
        self.assertIn("recon_only", analysis.suspected_root_cause)
        self.assertIn("supporting evidence", analysis.proposed_fix)

    def test_failure_analysis_requires_runtime_backed_references(self) -> None:
        with self.assertRaisesRegex(ValueError, "solve_session_id"):
            FailureAnalysis.create(
                id="failure-missing-session",
                solve_session_id="",
                failure_class="tool_parser",
                related_evidence=["evidence:http-title"],
                related_policy_decisions=[],
                related_model_runs=[],
                suspected_root_cause="Parser failed to extract a title.",
                proposed_fix="Add parser fixture coverage.",
                github_issue_id="",
            )

    def test_failure_analysis_rejects_raw_flag_material(self) -> None:
        with self.assertRaisesRegex(ValueError, "raw flag"):
            FailureAnalysis.create(
                id="failure-raw-flag",
                solve_session_id="solve-juice-1",
                failure_class="reporting",
                related_evidence=["evidence:http-title"],
                related_policy_decisions=[],
                related_model_runs=[],
                suspected_root_cause="Report included " + fixture_flag("hidden-answer").upper() + ".",
                proposed_fix="Store redacted proof references instead of raw flags.",
                github_issue_id="github:issue-43",
            )

    def test_failure_analysis_rejects_raw_flag_material_in_references(self) -> None:
        with self.assertRaisesRegex(ValueError, "hidden flag material"):
            FailureAnalysis.create(
                id="failure-raw-flag-ref",
                solve_session_id="solve-juice-1",
                failure_class="reporting",
                related_evidence=["evidence:http-title", fixture_flag("hidden-answer")],
                related_policy_decisions=[],
                related_model_runs=[],
                suspected_root_cause="Report copied an unsafe reference into failure analysis.",
                proposed_fix="Store redacted proof references instead.",
                github_issue_id="github:issue-44",
            )


if __name__ == "__main__":
    unittest.main()
