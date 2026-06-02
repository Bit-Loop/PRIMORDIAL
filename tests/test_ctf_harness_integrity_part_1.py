from __future__ import annotations

from tests.test_ctf_harness_integrity_common import *


class CTFHarnessIntegrityContractTestsPart1(CTFHarnessIntegrityContractTestsBase):
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

    def test_integrity_rejects_benchmark_without_executed_hardcode_scan(self) -> None:
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

        result = CTFHarnessIntegrity.validate_benchmark_run(
            run,
            solve_session_ids=set(),
            target_ids={"target:juice"},
            evidence_ids=set(),
            policy_decision_ids=set(),
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual(result.errors, ("hardcode scan not run: benchmark:run-1",))

__all__ = ["CTFHarnessIntegrityContractTestsPart1"]
