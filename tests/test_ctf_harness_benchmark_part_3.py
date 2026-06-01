from __future__ import annotations

from tests.test_ctf_harness_benchmark_common import *


class BenchmarkRunContractTestsPart3(BenchmarkRunContractTestsBase):
    def test_benchmark_run_rejects_duplicate_solve_result_evidence_ids(self) -> None:
        run = BenchmarkRun.start(
            id="benchmark-duplicate-evidence-result-ref",
            target_set=["juice-shop-foundation"],
            benchmark_mode="closed_book",
            mutation_seed="seed:2026-05-23",
            code_version="git:abc123",
            policy_version="policy:v1",
            model_versions={},
            hidden_solution_access_status="not_available_to_agent",
            hardcode_scan_result={"status": "not_run"},
        )

        with self.assertRaisesRegex(ValueError, "duplicate evidence_ids entry"):
            run.record_solve_result(
                solve_session_id="solve-juice-1",
                target_id="juice-shop-foundation",
                solve_status="blocked",
                result="no_solve",
                evidence_ids=["evidence:http-title", "evidence:http-title"],
                policy_decision_ids=["policy:allow-recon"],
                hardcode_scan_result={"status": "pass"},
            )

    def test_benchmark_run_rejects_non_policy_refs_in_solve_result_policy_decision_ids(self) -> None:
        run = BenchmarkRun.start(
            id="benchmark-non-policy-result-ref",
            target_set=["juice-shop-foundation"],
            benchmark_mode="closed_book",
            mutation_seed="seed:2026-05-23",
            code_version="git:abc123",
            policy_version="policy:v1",
            model_versions={},
            hidden_solution_access_status="not_available_to_agent",
            hardcode_scan_result={"status": "not_run"},
        )

        with self.assertRaisesRegex(ValueError, "policy_decision_ids entry must use policy:<id>"):
            run.record_solve_result(
                solve_session_id="solve-juice-1",
                target_id="juice-shop-foundation",
                solve_status="blocked",
                result="no_solve",
                evidence_ids=["evidence:http-title"],
                policy_decision_ids=["note:operator-observation"],
                hardcode_scan_result={"status": "pass"},
            )

    def test_benchmark_run_rejects_result_after_scoring_finalizes_run(self) -> None:
        run = BenchmarkRun.start(
            id="benchmark-finalized-run",
            target_set=["juice-shop-foundation", "vulhub-cve-smoke"],
            benchmark_mode="closed_book",
            mutation_seed="seed:2026-05-23",
            code_version="git:abc123",
            policy_version="policy:v1",
            model_versions={},
            hidden_solution_access_status="not_available_to_agent",
            hardcode_scan_result={"status": "not_run"},
        )
        run = run.record_solve_result(
            solve_session_id="solve-juice-1",
            target_id="juice-shop-foundation",
            solve_status="blocked",
            result="no_solve",
            evidence_ids=["evidence:http-title"],
            policy_decision_ids=["policy:allow-recon"],
            hardcode_scan_result={"status": "pass"},
        ).with_scoring_summary({})

        with self.assertRaisesRegex(ValueError, "finalized"):
            run.record_solve_result(
                solve_session_id="solve-vulhub-1",
                target_id="vulhub-cve-smoke",
                solve_status="blocked",
                result="no_solve",
                evidence_ids=["evidence:banner"],
                policy_decision_ids=["policy:allow-recon"],
                hardcode_scan_result={"status": "pass"},
            )

    def test_benchmark_run_rejects_rescoring_after_finalization(self) -> None:
        run = BenchmarkRun.start(
            id="benchmark-rescore-run",
            target_set=["juice-shop-foundation"],
            benchmark_mode="closed_book",
            mutation_seed="seed:2026-05-23",
            code_version="git:abc123",
            policy_version="policy:v1",
            model_versions={},
            hidden_solution_access_status="not_available_to_agent",
            hardcode_scan_result={"status": "not_run"},
        )
        run = run.record_solve_result(
            solve_session_id="solve-juice-1",
            target_id="juice-shop-foundation",
            solve_status="blocked",
            result="no_solve",
            evidence_ids=["evidence:http-title"],
            policy_decision_ids=["policy:allow-recon"],
            hardcode_scan_result={"status": "pass"},
        ).with_scoring_summary({"targets_total": 1})

        with self.assertRaisesRegex(ValueError, "finalized"):
            run.with_scoring_summary({"blocked": 1})

    def test_compute_scoring_summary_is_shared_public_contract(self) -> None:
        from primordial.labs.ctf.scoring import compute_scoring_summary, is_scoring_counter

        solve_results = (
            {"solve_status": "solved", "result": "solved"},
            {"solve_status": "review_required", "result": "review"},
            {"solve_status": "blocked", "result": "no_solve"},
            {"solve_status": "unknown", "result": "unknown"},
        )

        self.assertEqual(
            compute_scoring_summary(solve_results),
            {
                "targets_recorded": 4,
                "solved": 1,
                "review_required": 1,
                "failed": 1,
            },
        )
        self.assertTrue(is_scoring_counter(0))
        self.assertTrue(is_scoring_counter(3))
        self.assertFalse(is_scoring_counter(-1))
        self.assertFalse(is_scoring_counter("3"))
        self.assertFalse(is_scoring_counter(True))

    def test_benchmark_run_scores_solved_result_with_non_writeup_source_refs(self) -> None:
        run = BenchmarkRun.start(
            id="benchmark-scored-no-writeups",
            target_set=["juice-shop-foundation"],
            benchmark_mode="closed_book",
            mutation_seed="seed:2026-05-23",
            code_version="git:abc123",
            policy_version="policy:v1",
            model_versions={},
            hidden_solution_access_status="not_available_to_agent",
            hardcode_scan_result={"status": "not_run"},
        )

        run = run.record_solve_result(
            solve_session_id="solve-juice-1",
            target_id="juice-shop-foundation",
            solve_status="solved",
            result="solved",
            evidence_ids=["evidence:http-title", "evidence:captured-flag-redacted"],
            policy_decision_ids=["policy:allow-solve"],
            hardcode_scan_result={"status": "pass"},
            source_refs=["ctfd:juice-shop-foundation", "rag:web-methodology"],
        ).with_scoring_summary({"targets_total": 1})

        self.assertEqual(run.solve_results[0]["source_refs"], ("ctfd:juice-shop-foundation", "rag:web-methodology"))
        self.assertEqual(run.scoring_summary["solved"], 1)

    def test_benchmark_run_rejects_solved_closed_book_result_without_source_refs(self) -> None:
        run = BenchmarkRun.start(
            id="benchmark-missing-source-refs",
            target_set=["juice-shop-foundation"],
            benchmark_mode="closed_book",
            mutation_seed="seed:2026-05-23",
            code_version="git:abc123",
            policy_version="policy:v1",
            model_versions={},
            hidden_solution_access_status="not_available_to_agent",
            hardcode_scan_result={"status": "not_run"},
        )

        with self.assertRaisesRegex(ValueError, "source_refs"):
            run.record_solve_result(
                solve_session_id="solve-juice-1",
                target_id="juice-shop-foundation",
                solve_status="solved",
                result="solved",
                evidence_ids=["evidence:http-title", "evidence:captured-flag-redacted"],
                policy_decision_ids=["policy:allow-solve"],
                hardcode_scan_result={"status": "pass"},
            )

    def test_benchmark_run_rejects_closed_book_writeup_source_refs(self) -> None:
        run = BenchmarkRun.start(
            id="benchmark-writeup-source-refs",
            target_set=["juice-shop-foundation"],
            benchmark_mode="closed_book",
            mutation_seed="seed:2026-05-23",
            code_version="git:abc123",
            policy_version="policy:v1",
            model_versions={},
            hidden_solution_access_status="not_available_to_agent",
            hardcode_scan_result={"status": "not_run"},
        )

        with self.assertRaisesRegex(ValueError, "writeup"):
            run.record_solve_result(
                solve_session_id="solve-juice-1",
                target_id="juice-shop-foundation",
                solve_status="blocked",
                result="no_solve",
                evidence_ids=["evidence:http-title"],
                policy_decision_ids=["policy:allow-recon"],
                hardcode_scan_result={"status": "pass"},
                source_refs=["writeup:juice-shop-foundation"],
            )

__all__ = ["BenchmarkRunContractTestsPart3"]
