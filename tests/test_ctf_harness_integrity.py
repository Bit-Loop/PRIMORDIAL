from __future__ import annotations

from dataclasses import replace
import unittest

from primordial.labs.ctf import BenchmarkRun, CTFHarnessIntegrity, FailureAnalysis, PatchProposal


class CTFHarnessIntegrityContractTests(unittest.TestCase):
    def test_integrity_validates_patch_proposal_failure_and_benchmark_refs(self) -> None:
        proposal = PatchProposal.create(
            id="patch-parser-1",
            failure_analysis_id="failure:parser-1",
            benchmark_run_id="benchmark:run-1",
            proposed_change="Improve generalized parser behavior for benchmark traces.",
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
                    "command": "python3 -m unittest tests.test_ctf_harness_benchmark -v",
                    "status": "passed",
                }
            ],
            hardcode_scan_result={"status": "pass"},
            status="proposed",
        )

        valid = CTFHarnessIntegrity.validate_patch_proposal(
            proposal,
            failure_analysis_ids={"failure:parser-1"},
            benchmark_run_ids={"benchmark:run-1"},
        )
        self.assertEqual(valid.status, "pass")
        self.assertEqual(valid.errors, ())

        invalid = CTFHarnessIntegrity.validate_patch_proposal(
            proposal,
            failure_analysis_ids={"failure:other"},
            benchmark_run_ids={"benchmark:other"},
        )
        self.assertEqual(invalid.status, "fail")
        self.assertEqual(
            invalid.errors,
            (
                "unresolved failure_analysis_id: failure:parser-1",
                "unresolved benchmark_run_id: benchmark:run-1",
            ),
        )

    def test_integrity_validates_failure_analysis_runtime_refs_without_github_authority(self) -> None:
        analysis = FailureAnalysis.create(
            id="failure:parser-1",
            solve_session_id="solve:session-1",
            failure_class="tool_parser",
            related_evidence=["evidence:http-title"],
            related_policy_decisions=["policy:allow-recon"],
            related_model_runs=["model:solver-1"],
            suspected_root_cause="Parser did not preserve evidence-backed title output.",
            proposed_fix="Add generalized parser coverage and rerun benchmark regression.",
            github_issue_id="github:issue-42",
        )

        valid = CTFHarnessIntegrity.validate_failure_analysis(
            analysis,
            solve_session_ids={"solve:session-1"},
            evidence_ids={"evidence:http-title"},
            policy_decision_ids={"policy:allow-recon"},
            model_run_ids={"model:solver-1"},
        )
        self.assertEqual(valid.status, "pass")
        self.assertEqual(valid.errors, ())

        invalid = CTFHarnessIntegrity.validate_failure_analysis(
            analysis,
            solve_session_ids={"solve:other"},
            evidence_ids=set(),
            policy_decision_ids=set(),
            model_run_ids=set(),
        )
        self.assertEqual(invalid.status, "fail")
        self.assertEqual(
            invalid.errors,
            (
                "unresolved solve_session_id: solve:session-1",
                "unresolved evidence_id: evidence:http-title",
                "unresolved policy_decision_id: policy:allow-recon",
                "unresolved model_run_id: model:solver-1",
            ),
        )

    def test_integrity_validates_benchmark_run_solve_result_refs(self) -> None:
        run = BenchmarkRun.start(
            id="benchmark:run-1",
            target_set=["target:juice"],
            benchmark_mode="closed_book",
            mutation_seed="seed:integrity",
            code_version="git:abc123",
            policy_version="policy:v1",
            model_versions={},
            hidden_solution_access_status="not_available_to_agent",
            hardcode_scan_result={"status": "not_run"},
        )
        run = run.record_solve_result(
            solve_session_id="solve:session-1",
            target_id="target:juice",
            solve_status="blocked",
            result="no_solve",
            evidence_ids=["evidence:http-title"],
            policy_decision_ids=["policy:allow-recon"],
            hardcode_scan_result={"status": "pass"},
        )

        valid = CTFHarnessIntegrity.validate_benchmark_run(
            run,
            solve_session_ids={"solve:session-1"},
            target_ids={"target:juice"},
            evidence_ids={"evidence:http-title"},
            policy_decision_ids={"policy:allow-recon"},
        )
        self.assertEqual(valid.status, "pass")
        self.assertEqual(valid.errors, ())

        invalid = CTFHarnessIntegrity.validate_benchmark_run(
            run,
            solve_session_ids={"solve:other"},
            target_ids={"target:other"},
            evidence_ids=set(),
            policy_decision_ids=set(),
        )
        self.assertEqual(invalid.status, "fail")
        self.assertEqual(
            invalid.errors,
            (
                "unresolved target_id: target:juice",
                "unresolved solve_session_id: solve:session-1",
                "unresolved evidence_id: evidence:http-title",
                "unresolved policy_decision_id: policy:allow-recon",
            ),
        )

    def test_integrity_rejects_benchmark_hardcode_hard_fail_and_malformed_findings(self) -> None:
        run = BenchmarkRun.start(
            id="benchmark:run-1",
            target_set=["target:juice"],
            benchmark_mode="closed_book",
            mutation_seed="seed:integrity",
            code_version="git:abc123",
            policy_version="policy:v1",
            model_versions={},
            hidden_solution_access_status="not_available_to_agent",
            hardcode_scan_result={
                "status": "fail",
                "findings": (
                    {
                        "rule_id": "raw_flag",
                        "severity": "hard_fail",
                    },
                ),
            },
        )
        run = run.record_solve_result(
            solve_session_id="solve:session-1",
            target_id="target:juice",
            solve_status="blocked",
            result="no_solve",
            evidence_ids=["evidence:http-title"],
            policy_decision_ids=["policy:allow-recon"],
            hardcode_scan_result={
                "status": "fail",
                "findings": (
                    {
                        "rule_id": "raw_flag",
                    },
                ),
            },
        )

        result = CTFHarnessIntegrity.validate_benchmark_run(
            run,
            solve_session_ids={"solve:session-1"},
            target_ids={"target:juice"},
            evidence_ids={"evidence:http-title"},
            policy_decision_ids={"policy:allow-recon"},
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual(
            result.errors,
            (
                "hardcode scan hard_fail finding: benchmark:run-1 raw_flag",
                "hardcode scan finding missing severity: solve:session-1 raw_flag",
            ),
        )

    def test_integrity_rejects_benchmark_scoring_summary_drift(self) -> None:
        run = BenchmarkRun.start(
            id="benchmark:run-1",
            target_set=["target:juice", "target:vulhub"],
            benchmark_mode="closed_book",
            mutation_seed="seed:integrity",
            code_version="git:abc123",
            policy_version="policy:v1",
            model_versions={},
            hidden_solution_access_status="not_available_to_agent",
            hardcode_scan_result={"status": "pass"},
        )
        run = run.record_solve_result(
            solve_session_id="solve:session-1",
            target_id="target:juice",
            solve_status="solved",
            result="solved",
            evidence_ids=["evidence:http-title"],
            policy_decision_ids=["policy:allow-recon"],
            hardcode_scan_result={"status": "pass"},
        )
        run = run.record_solve_result(
            solve_session_id="solve:session-2",
            target_id="target:vulhub",
            solve_status="review",
            result="review",
            evidence_ids=["evidence:banner"],
            policy_decision_ids=["policy:allow-recon"],
            hardcode_scan_result={
                "status": "fail",
                "findings": (
                    {
                        "rule_id": "code_simhash_similarity",
                        "severity": "review",
                    },
                ),
            },
        )
        run = replace(
            run,
            ended_at="2026-05-23T00:00:00+00:00",
            scoring_summary={
                "targets_recorded": 99,
                "solved": 0,
                "review_required": 0,
                "failed": 3,
            },
        )

        result = CTFHarnessIntegrity.validate_benchmark_run(
            run,
            solve_session_ids={"solve:session-1", "solve:session-2"},
            target_ids={"target:juice", "target:vulhub"},
            evidence_ids={"evidence:http-title", "evidence:banner"},
            policy_decision_ids={"policy:allow-recon"},
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual(
            result.errors,
            (
                "scoring summary mismatch: targets_recorded expected 2 got 99",
                "scoring summary mismatch: solved expected 1 got 0",
                "scoring summary mismatch: review_required expected 1 got 0",
                "scoring summary mismatch: failed expected 0 got 3",
            ),
        )

    def test_integrity_rejects_duplicate_benchmark_target_results(self) -> None:
        run = BenchmarkRun.start(
            id="benchmark:run-1",
            target_set=["target:juice"],
            benchmark_mode="closed_book",
            mutation_seed="seed:integrity",
            code_version="git:abc123",
            policy_version="policy:v1",
            model_versions={},
            hidden_solution_access_status="not_available_to_agent",
            hardcode_scan_result={"status": "pass"},
        )
        run = replace(
            run,
            solve_results=(
                {
                    "solve_session_id": "solve:session-1",
                    "target_id": "target:juice",
                    "solve_status": "blocked",
                    "result": "no_solve",
                    "evidence_ids": ("evidence:http-title",),
                    "policy_decision_ids": ("policy:allow-recon",),
                    "hardcode_scan_result": {"status": "pass"},
                },
                {
                    "solve_session_id": "solve:session-2",
                    "target_id": "target:juice",
                    "solve_status": "solved",
                    "result": "solved",
                    "evidence_ids": ("evidence:http-final",),
                    "policy_decision_ids": ("policy:allow-recon",),
                    "hardcode_scan_result": {"status": "pass"},
                },
            ),
        )

        result = CTFHarnessIntegrity.validate_benchmark_run(
            run,
            solve_session_ids={"solve:session-1", "solve:session-2"},
            target_ids={"target:juice"},
            evidence_ids={"evidence:http-title", "evidence:http-final"},
            policy_decision_ids={"policy:allow-recon"},
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual(result.errors, ("duplicate solve result for target_id: target:juice",))

    def test_integrity_rejects_benchmark_result_outside_run_target_set(self) -> None:
        run = BenchmarkRun.start(
            id="benchmark:run-1",
            target_set=["target:juice"],
            benchmark_mode="closed_book",
            mutation_seed="seed:integrity",
            code_version="git:abc123",
            policy_version="policy:v1",
            model_versions={},
            hidden_solution_access_status="not_available_to_agent",
            hardcode_scan_result={"status": "pass"},
        )
        run = replace(
            run,
            solve_results=(
                {
                    "solve_session_id": "solve:session-1",
                    "target_id": "target:vulhub",
                    "solve_status": "blocked",
                    "result": "no_solve",
                    "evidence_ids": ("evidence:http-title",),
                    "policy_decision_ids": ("policy:allow-recon",),
                    "hardcode_scan_result": {"status": "pass"},
                },
            ),
        )

        result = CTFHarnessIntegrity.validate_benchmark_run(
            run,
            solve_session_ids={"solve:session-1"},
            target_ids={"target:juice", "target:vulhub"},
            evidence_ids={"evidence:http-title"},
            policy_decision_ids={"policy:allow-recon"},
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual(result.errors, ("benchmark solve result outside target_set: target:vulhub",))

    def test_integrity_rejects_duplicate_benchmark_target_set_entries(self) -> None:
        run = BenchmarkRun.start(
            id="benchmark:run-1",
            target_set=["target:juice"],
            benchmark_mode="closed_book",
            mutation_seed="seed:integrity",
            code_version="git:abc123",
            policy_version="policy:v1",
            model_versions={},
            hidden_solution_access_status="not_available_to_agent",
            hardcode_scan_result={"status": "pass"},
        )
        run = replace(run, target_set=("target:juice", "target:juice"))

        result = CTFHarnessIntegrity.validate_benchmark_run(
            run,
            solve_session_ids=set(),
            target_ids={"target:juice"},
            evidence_ids=set(),
            policy_decision_ids=set(),
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual(result.errors, ("duplicate benchmark target_set entry: target:juice",))

    def test_integrity_rejects_scored_benchmark_with_missing_target_result(self) -> None:
        run = BenchmarkRun.start(
            id="benchmark:run-1",
            target_set=["target:juice", "target:vulhub"],
            benchmark_mode="closed_book",
            mutation_seed="seed:integrity",
            code_version="git:abc123",
            policy_version="policy:v1",
            model_versions={},
            hidden_solution_access_status="not_available_to_agent",
            hardcode_scan_result={"status": "pass"},
        )
        run = run.record_solve_result(
            solve_session_id="solve:session-1",
            target_id="target:juice",
            solve_status="blocked",
            result="no_solve",
            evidence_ids=["evidence:http-title"],
            policy_decision_ids=["policy:allow-recon"],
            hardcode_scan_result={"status": "pass"},
        ).with_scoring_summary({})

        result = CTFHarnessIntegrity.validate_benchmark_run(
            run,
            solve_session_ids={"solve:session-1"},
            target_ids={"target:juice", "target:vulhub"},
            evidence_ids={"evidence:http-title"},
            policy_decision_ids={"policy:allow-recon"},
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual(result.errors, ("missing solve result for target_id: target:vulhub",))

    def test_integrity_rejects_scored_benchmark_without_finalized_timestamp(self) -> None:
        run = BenchmarkRun.start(
            id="benchmark:run-1",
            target_set=["target:juice"],
            benchmark_mode="closed_book",
            mutation_seed="seed:integrity",
            code_version="git:abc123",
            policy_version="policy:v1",
            model_versions={},
            hidden_solution_access_status="not_available_to_agent",
            hardcode_scan_result={"status": "pass"},
        )
        run = run.record_solve_result(
            solve_session_id="solve:session-1",
            target_id="target:juice",
            solve_status="blocked",
            result="no_solve",
            evidence_ids=["evidence:http-title"],
            policy_decision_ids=["policy:allow-recon"],
            hardcode_scan_result={"status": "pass"},
        )
        run = replace(
            run,
            ended_at="",
            scoring_summary={
                "targets_recorded": 1,
                "solved": 0,
                "review_required": 0,
                "failed": 1,
            },
        )

        result = CTFHarnessIntegrity.validate_benchmark_run(
            run,
            solve_session_ids={"solve:session-1"},
            target_ids={"target:juice"},
            evidence_ids={"evidence:http-title"},
            policy_decision_ids={"policy:allow-recon"},
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual(result.errors, ("scored benchmark missing ended_at: benchmark:run-1",))

    def test_integrity_rejects_finalized_benchmark_without_scoring_summary(self) -> None:
        run = BenchmarkRun.start(
            id="benchmark:run-1",
            target_set=["target:juice"],
            benchmark_mode="closed_book",
            mutation_seed="seed:integrity",
            code_version="git:abc123",
            policy_version="policy:v1",
            model_versions={},
            hidden_solution_access_status="not_available_to_agent",
            hardcode_scan_result={"status": "pass"},
        )
        run = run.record_solve_result(
            solve_session_id="solve:session-1",
            target_id="target:juice",
            solve_status="blocked",
            result="no_solve",
            evidence_ids=["evidence:http-title"],
            policy_decision_ids=["policy:allow-recon"],
            hardcode_scan_result={"status": "pass"},
        )
        run = replace(run, ended_at="2026-05-23T00:00:00+00:00", scoring_summary={})

        result = CTFHarnessIntegrity.validate_benchmark_run(
            run,
            solve_session_ids={"solve:session-1"},
            target_ids={"target:juice"},
            evidence_ids={"evidence:http-title"},
            policy_decision_ids={"policy:allow-recon"},
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual(result.errors, ("finalized benchmark missing scoring_summary: benchmark:run-1",))

    def test_integrity_rejects_malformed_benchmark_scoring_summary(self) -> None:
        run = BenchmarkRun.start(
            id="benchmark:run-1",
            target_set=["target:juice"],
            benchmark_mode="closed_book",
            mutation_seed="seed:integrity",
            code_version="git:abc123",
            policy_version="policy:v1",
            model_versions={},
            hidden_solution_access_status="not_available_to_agent",
            hardcode_scan_result={"status": "pass"},
        )
        run = run.record_solve_result(
            solve_session_id="solve:session-1",
            target_id="target:juice",
            solve_status="blocked",
            result="no_solve",
            evidence_ids=["evidence:http-title"],
            policy_decision_ids=["policy:allow-recon"],
            hardcode_scan_result={"status": "pass"},
        )
        run = replace(
            run,
            ended_at="2026-05-23T00:00:00+00:00",
            scoring_summary=("targets_recorded", "failed"),
        )

        result = CTFHarnessIntegrity.validate_benchmark_run(
            run,
            solve_session_ids={"solve:session-1"},
            target_ids={"target:juice"},
            evidence_ids={"evidence:http-title"},
            policy_decision_ids={"policy:allow-recon"},
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual(result.errors, ("scoring summary malformed: benchmark:run-1",))

    def test_integrity_rejects_invalid_benchmark_scoring_summary_values(self) -> None:
        run = BenchmarkRun.start(
            id="benchmark:run-1",
            target_set=["target:juice"],
            benchmark_mode="closed_book",
            mutation_seed="seed:integrity",
            code_version="git:abc123",
            policy_version="policy:v1",
            model_versions={},
            hidden_solution_access_status="not_available_to_agent",
            hardcode_scan_result={"status": "pass"},
        )
        run = run.record_solve_result(
            solve_session_id="solve:session-1",
            target_id="target:juice",
            solve_status="blocked",
            result="no_solve",
            evidence_ids=["evidence:http-title"],
            policy_decision_ids=["policy:allow-recon"],
            hardcode_scan_result={"status": "pass"},
        )
        run = replace(
            run,
            ended_at="2026-05-23T00:00:00+00:00",
            scoring_summary={
                "targets_recorded": 1,
                "solved": 0,
                "review_required": 0,
                "failed": 1,
                "targets_total": -1,
                "blocked": "one",
            },
        )

        result = CTFHarnessIntegrity.validate_benchmark_run(
            run,
            solve_session_ids={"solve:session-1"},
            target_ids={"target:juice"},
            evidence_ids={"evidence:http-title"},
            policy_decision_ids={"policy:allow-recon"},
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual(
            result.errors,
            (
                "scoring summary invalid value: targets_total=-1",
                "scoring summary invalid value: blocked=one",
            ),
        )


if __name__ == "__main__":
    unittest.main()
