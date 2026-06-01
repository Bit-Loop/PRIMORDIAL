from __future__ import annotations

from tests.test_ctf_harness_integrity_common import *


class CTFHarnessIntegrityContractTestsPart2(CTFHarnessIntegrityContractTestsBase):
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
            source_refs=["ctfd:challenge-juice", "rag:web-methodology"],
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

__all__ = ["CTFHarnessIntegrityContractTestsPart2"]
