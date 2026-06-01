from __future__ import annotations

from tests.test_ctf_harness_benchmark_common import *


class BenchmarkRunContractTestsPart1(BenchmarkRunContractTestsBase):
    def test_benchmark_run_records_versions_targets_results_and_scoring(self) -> None:
        run = BenchmarkRun.start(
            id="benchmark-juice-smoke",
            target_set=["juice-shop-foundation", "vulhub-cve-smoke"],
            benchmark_mode="closed_book",
            mutation_seed="seed:2026-05-23",
            code_version="git:abc123",
            policy_version="policy:v1",
            model_versions={"solver": "local_fast:v1", "reviewer": "local_deep:v1"},
            hidden_solution_access_status="not_available_to_agent",
            hardcode_scan_result={"status": "not_run"},
        )

        run = run.record_solve_result(
            solve_session_id="solve-juice-1",
            target_id="juice-shop-foundation",
            solve_status="blocked",
            result="no_solve",
            evidence_ids=["evidence:http-title"],
            policy_decision_ids=["policy:block-flag"],
            hardcode_scan_result={"status": "pass"},
        )
        run = run.with_scoring_summary({"targets_total": 2, "blocked": 1})

        self.assertEqual(run.target_set, ("juice-shop-foundation", "vulhub-cve-smoke"))
        self.assertEqual(run.benchmark_mode, "closed_book")
        self.assertEqual(run.solve_results[0]["solve_session_id"], "solve-juice-1")
        self.assertEqual(run.solve_results[0]["evidence_ids"], ("evidence:http-title",))
        self.assertEqual(run.scoring_summary["targets_recorded"], 1)
        self.assertEqual(run.scoring_summary["solved"], 0)
        self.assertEqual(run.scoring_summary["blocked"], 1)
        self.assertEqual(run.hidden_solution_access_status, "not_available_to_agent")
        self.assertEqual(run.hardcode_scan_result["status"], "not_run")

    def test_benchmark_run_rejects_closed_book_hidden_solution_access(self) -> None:
        with self.assertRaisesRegex(ValueError, "hidden solution"):
            BenchmarkRun.start(
                id="benchmark-unsafe",
                target_set=["juice-shop-foundation"],
                benchmark_mode="closed_book",
                mutation_seed="seed:unsafe",
                code_version="git:abc123",
                policy_version="policy:v1",
                model_versions={},
                hidden_solution_access_status="available_to_agent",
                hardcode_scan_result={"status": "not_run"},
            )

    def test_benchmark_run_rejects_raw_flag_material_in_start_payload(self) -> None:
        with self.assertRaisesRegex(ValueError, "hidden flag material"):
            BenchmarkRun.start(
                id="benchmark-" + fixture_flag(),
                target_set=["juice-shop-foundation"],
                benchmark_mode="closed_book",
                mutation_seed="seed:2026-05-23",
                code_version="git:abc123",
                policy_version="policy:v1",
                model_versions={"solver": "local_fast:v1"},
                hidden_solution_access_status="not_available_to_agent",
                hardcode_scan_result={"status": "not_run"},
            )

    def test_benchmark_run_rejects_duplicate_target_set_entries(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate target_set"):
            BenchmarkRun.start(
                id="benchmark-duplicate-targets",
                target_set=["juice-shop-foundation", "juice-shop-foundation"],
                benchmark_mode="closed_book",
                mutation_seed="seed:2026-05-23",
                code_version="git:abc123",
                policy_version="policy:v1",
                model_versions={},
                hidden_solution_access_status="not_available_to_agent",
                hardcode_scan_result={"status": "not_run"},
            )

    def test_benchmark_run_rejects_invalid_target_set_entries(self) -> None:
        for target_set in ([1], [""]):
            with self.subTest(target_set=target_set):
                with self.assertRaisesRegex(ValueError, "target_set entry"):
                    BenchmarkRun.start(
                        id="benchmark-invalid-target-set-entry",
                        target_set=target_set,
                        benchmark_mode="closed_book",
                        mutation_seed="seed:2026-05-23",
                        code_version="git:abc123",
                        policy_version="policy:v1",
                        model_versions={},
                        hidden_solution_access_status="not_available_to_agent",
                        hardcode_scan_result={"status": "not_run"},
                    )

    def test_benchmark_run_rejects_solved_result_without_evidence(self) -> None:
        run = BenchmarkRun.start(
            id="benchmark-juice-smoke",
            target_set=["juice-shop-foundation"],
            benchmark_mode="closed_book",
            mutation_seed="seed:2026-05-23",
            code_version="git:abc123",
            policy_version="policy:v1",
            model_versions={},
            hidden_solution_access_status="not_available_to_agent",
            hardcode_scan_result={"status": "not_run"},
        )

        with self.assertRaisesRegex(ValueError, "evidence"):
            run.record_solve_result(
                solve_session_id="solve-juice-1",
                target_id="juice-shop-foundation",
                solve_status="solved",
                result="solved",
                evidence_ids=[],
                policy_decision_ids=["policy:allow"],
                hardcode_scan_result={"status": "pass"},
            )

    def test_benchmark_run_rejects_raw_flag_material_in_solve_result_payload(self) -> None:
        run = BenchmarkRun.start(
            id="benchmark-juice-smoke",
            target_set=["juice-shop-foundation"],
            benchmark_mode="closed_book",
            mutation_seed="seed:2026-05-23",
            code_version="git:abc123",
            policy_version="policy:v1",
            model_versions={},
            hidden_solution_access_status="not_available_to_agent",
            hardcode_scan_result={"status": "not_run"},
        )

        with self.assertRaisesRegex(ValueError, "hidden flag material"):
            run.record_solve_result(
                solve_session_id="solve-" + fixture_flag(),
                target_id="juice-shop-foundation",
                solve_status="blocked",
                result="no_solve",
                evidence_ids=["evidence:http-title"],
                policy_decision_ids=["policy:allow-recon"],
                hardcode_scan_result={"status": "pass"},
            )

    def test_benchmark_run_rejects_result_outside_target_set(self) -> None:
        run = BenchmarkRun.start(
            id="benchmark-juice-smoke",
            target_set=["juice-shop-foundation"],
            benchmark_mode="closed_book",
            mutation_seed="seed:2026-05-23",
            code_version="git:abc123",
            policy_version="policy:v1",
            model_versions={},
            hidden_solution_access_status="not_available_to_agent",
            hardcode_scan_result={"status": "not_run"},
        )

        with self.assertRaisesRegex(ValueError, "target_set"):
            run.record_solve_result(
                solve_session_id="solve-vulhub-1",
                target_id="vulhub-cve-smoke",
                solve_status="blocked",
                result="no_solve",
                evidence_ids=["evidence:http-title"],
                policy_decision_ids=["policy:allow-recon"],
                hardcode_scan_result={"status": "pass"},
            )

    def test_benchmark_run_rejects_duplicate_target_result(self) -> None:
        run = BenchmarkRun.start(
            id="benchmark-juice-smoke",
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
        )

        with self.assertRaisesRegex(ValueError, "duplicate"):
            run.record_solve_result(
                solve_session_id="solve-juice-2",
                target_id="juice-shop-foundation",
                solve_status="blocked",
                result="no_solve",
                evidence_ids=["evidence:http-title-2"],
                policy_decision_ids=["policy:allow-recon"],
                hardcode_scan_result={"status": "pass"},
            )

    def test_benchmark_run_scores_review_results_separately_from_failures(self) -> None:
        run = BenchmarkRun.start(
            id="benchmark-review-smoke",
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
            solve_session_id="solve-review-1",
            target_id="juice-shop-foundation",
            solve_status="review",
            result="review",
            evidence_ids=["evidence:http-title"],
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
        run = run.with_scoring_summary({"targets_total": 1})

        self.assertEqual(run.solve_results[0]["solve_status"], "review")
        self.assertEqual(run.scoring_summary["review_required"], 1)
        self.assertEqual(run.scoring_summary["solved"], 0)
        self.assertEqual(run.scoring_summary["failed"], 0)

__all__ = ["BenchmarkRunContractTestsPart1"]
