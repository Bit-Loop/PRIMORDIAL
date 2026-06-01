from __future__ import annotations

from tests.test_ctf_harness_integrity_common import *


class CTFHarnessIntegrityContractTestsPart3(CTFHarnessIntegrityContractTestsBase):
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

    def test_integrity_rejects_scored_closed_book_writeup_source_refs(self) -> None:
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
            ended_at="2026-05-23T00:00:00+00:00",
            solve_results=(
                {
                    "solve_session_id": "solve:session-1",
                    "target_id": "target:juice",
                    "solve_status": "solved",
                    "result": "solved",
                    "evidence_ids": ("evidence:http-title",),
                    "policy_decision_ids": ("policy:allow-solve",),
                    "source_refs": ("writeup:juice",),
                    "hardcode_scan_result": {"status": "pass"},
                },
            ),
            scoring_summary={
                "targets_recorded": 1,
                "solved": 1,
                "review_required": 0,
                "failed": 0,
            },
        )

        result = CTFHarnessIntegrity.validate_benchmark_run(
            run,
            solve_session_ids={"solve:session-1"},
            target_ids={"target:juice"},
            evidence_ids={"evidence:http-title"},
            policy_decision_ids={"policy:allow-solve"},
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual(
            result.errors,
            ("closed-book solve result uses forbidden source_ref: writeup:juice",),
        )

    def test_integrity_rejects_scored_closed_book_solved_result_without_source_refs(self) -> None:
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
            ended_at="2026-05-23T00:00:00+00:00",
            solve_results=(
                {
                    "solve_session_id": "solve:session-1",
                    "target_id": "target:juice",
                    "solve_status": "solved",
                    "result": "solved",
                    "evidence_ids": ("evidence:http-title",),
                    "policy_decision_ids": ("policy:allow-solve",),
                    "hardcode_scan_result": {"status": "pass"},
                },
            ),
            scoring_summary={
                "targets_recorded": 1,
                "solved": 1,
                "review_required": 0,
                "failed": 0,
            },
        )

        result = CTFHarnessIntegrity.validate_benchmark_run(
            run,
            solve_session_ids={"solve:session-1"},
            target_ids={"target:juice"},
            evidence_ids={"evidence:http-title"},
            policy_decision_ids={"policy:allow-solve"},
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual(result.errors, ("closed-book solved result missing source_refs: target:juice",))

__all__ = ["CTFHarnessIntegrityContractTestsPart3"]
