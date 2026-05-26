from __future__ import annotations

import unittest

from primordial.labs.ctf import PatchProposal


class PatchProposalContractTests(unittest.TestCase):
    def test_patch_proposal_links_failure_to_change_tests_and_validation(self) -> None:
        proposal = PatchProposal.create(
            id="patch-juice-1",
            failure_analysis_id="failure-juice-1",
            proposed_change="Add CTFd flag submission intent gate.",
            files_changed=[
                "primordial/labs/ctf/sessions.py",
                "tests/test_ctf_harness_sessions.py",
            ],
            tests_added=[
                "tests.test_ctf_harness_sessions."
                "SolveSessionContractTests."
                "test_solve_session_blocks_flag_submission_under_recon_only"
            ],
            validation_results=[
                {
                    "command": "python3 -m unittest tests.test_ctf_harness_sessions -v",
                    "status": "passed",
                }
            ],
            regression_results=[
                {
                    "command": "python3 -m unittest tests.test_context_ctfd_registry -v",
                    "status": "passed",
                }
            ],
            hardcode_scan_result={"status": "pass"},
            status="proposed",
            benchmark_run_id="benchmark:run-juice-1",
        )

        self.assertEqual(proposal.id, "patch-juice-1")
        self.assertEqual(proposal.failure_analysis_id, "failure-juice-1")
        self.assertEqual(proposal.benchmark_run_id, "benchmark:run-juice-1")
        self.assertEqual(proposal.files_changed[0], "primordial/labs/ctf/sessions.py")
        self.assertEqual(proposal.validation_results[0]["status"], "passed")
        self.assertEqual(proposal.regression_results[0]["status"], "passed")
        self.assertEqual(proposal.hardcode_scan_result["status"], "pass")
        self.assertEqual(proposal.status, "proposed")

    def test_patch_proposal_requires_validation_before_acceptance(self) -> None:
        with self.assertRaisesRegex(ValueError, "validation"):
            PatchProposal.create(
                id="patch-unvalidated",
                failure_analysis_id="failure-juice-1",
                proposed_change="Add CTFd flag submission intent gate.",
                files_changed=["primordial/labs/ctf/sessions.py"],
                tests_added=["tests.test_ctf_harness_sessions"],
                validation_results=[],
                regression_results=[
                    {
                        "command": "python3 -m unittest tests.test_context_ctfd_registry -v",
                        "status": "passed",
                    }
                ],
                hardcode_scan_result={"status": "pass"},
                status="accepted",
            )

    def test_patch_proposal_rejects_raw_flag_material(self) -> None:
        with self.assertRaisesRegex(ValueError, "raw flag"):
            PatchProposal.create(
                id="patch-raw-flag",
                failure_analysis_id="failure-juice-1",
                proposed_change="Hardcode ctf{hidden-answer} into the solve check.",
                files_changed=["primordial/labs/ctf/sessions.py"],
                tests_added=["tests.test_ctf_harness_sessions"],
                validation_results=[
                    {
                        "command": "python3 -m unittest tests.test_ctf_harness_sessions -v",
                        "status": "passed",
                    }
                ],
                regression_results=[
                    {
                        "command": "python3 -m unittest tests.test_context_ctfd_registry -v",
                        "status": "passed",
                    }
                ],
                hardcode_scan_result={"status": "pass"},
                status="proposed",
            )

    def test_patch_proposal_rejects_raw_flag_material_in_validation_payloads(self) -> None:
        with self.assertRaisesRegex(ValueError, "hidden flag material"):
            PatchProposal.create(
                id="patch-validation-raw-flag",
                failure_analysis_id="failure-juice-1",
                proposed_change="Add generalized validation handling.",
                files_changed=["primordial/labs/ctf/verification.py"],
                tests_added=["tests.test_ctf_harness_solve_verification"],
                validation_results=[
                    {
                        "command": "python3 -m unittest tests.test_ctf_harness_solve_verification -v",
                        "status": "passed",
                        "note": "Captured ctf{hidden-answer} during validation.",
                    }
                ],
                regression_results=[
                    {
                        "command": "python3 -m unittest tests.test_ctf_harness_hardcode_scan -v",
                        "status": "passed",
                    }
                ],
                hardcode_scan_result={"status": "pass"},
                status="proposed",
            )

    def test_patch_proposal_routes_review_only_hardcode_findings_to_manual_review(self) -> None:
        proposal = PatchProposal.create(
            id="patch-review-only",
            failure_analysis_id="failure-review-1",
            proposed_change="Improve generalized evidence parsing for CTF benchmark runs.",
            files_changed=["primordial/labs/ctf/verification.py"],
            tests_added=["tests.test_ctf_harness_solve_verification"],
            validation_results=[
                {
                    "command": "python3 -m unittest tests.test_ctf_harness_solve_verification -v",
                    "status": "passed",
                }
            ],
            regression_results=[
                {
                    "command": "python3 -m unittest tests.test_ctf_harness_hardcode_scan -v",
                    "status": "passed",
                }
            ],
            hardcode_scan_result={
                "status": "fail",
                "findings": (
                    {
                        "rule_id": "code_simhash_similarity",
                        "severity": "review",
                    },
                ),
            },
            status="review_required",
        )

        self.assertEqual(proposal.status, "review_required")
        self.assertEqual(proposal.hardcode_scan_result["findings"][0]["severity"], "review")

        with self.assertRaisesRegex(ValueError, "hardcode scan"):
            PatchProposal.create(
                id="patch-hard-fail",
                failure_analysis_id="failure-review-1",
                proposed_change="Improve generalized evidence parsing for CTF benchmark runs.",
                files_changed=["primordial/labs/ctf/verification.py"],
                tests_added=["tests.test_ctf_harness_solve_verification"],
                validation_results=[
                    {
                        "command": "python3 -m unittest tests.test_ctf_harness_solve_verification -v",
                        "status": "passed",
                    }
                ],
                regression_results=[
                    {
                        "command": "python3 -m unittest tests.test_ctf_harness_hardcode_scan -v",
                        "status": "passed",
                    }
                ],
                hardcode_scan_result={
                    "status": "fail",
                    "findings": (
                        {
                            "rule_id": "raw_flag",
                            "severity": "hard_fail",
                        },
                    ),
                },
                status="review_required",
            )


if __name__ == "__main__":
    unittest.main()
