from __future__ import annotations

import unittest

from primordial.labs.ctf import BenchmarkRun


class BenchmarkRunContractTests(unittest.TestCase):
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
                id="benchmark-ctf{training-only-hidden-value}",
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
                solve_session_id="solve-ctf{training-only-hidden-value}",
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

    def test_benchmark_run_rejects_scoring_summary_computed_key_overrides(self) -> None:
        run = BenchmarkRun.start(
            id="benchmark-computed-scoring",
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

        with self.assertRaisesRegex(ValueError, "computed scoring"):
            run.with_scoring_summary({"targets_recorded": 99})

    def test_benchmark_run_rejects_invalid_extra_scoring_summary_values(self) -> None:
        run = BenchmarkRun.start(
            id="benchmark-invalid-scoring",
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

        with self.assertRaisesRegex(ValueError, "scoring summary value"):
            run.with_scoring_summary({"targets_total": -1})
        with self.assertRaisesRegex(ValueError, "scoring summary value"):
            run.with_scoring_summary({"blocked": "one"})
        with self.assertRaisesRegex(ValueError, "scoring summary value"):
            run.with_scoring_summary({"blocked": True})

    def test_benchmark_run_rejects_malformed_scoring_summary_input(self) -> None:
        run = BenchmarkRun.start(
            id="benchmark-malformed-scoring",
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

        with self.assertRaisesRegex(ValueError, "scoring summary malformed"):
            run.with_scoring_summary(("targets_total", "blocked"))

    def test_benchmark_run_rejects_malformed_hardcode_scan_results(self) -> None:
        with self.assertRaisesRegex(ValueError, "hardcode scan result malformed"):
            BenchmarkRun.start(
                id="benchmark-malformed-hardcode-start",
                target_set=["juice-shop-foundation"],
                benchmark_mode="closed_book",
                mutation_seed="seed:2026-05-23",
                code_version="git:abc123",
                policy_version="policy:v1",
                model_versions={},
                hidden_solution_access_status="not_available_to_agent",
                hardcode_scan_result=("status", "pass"),
            )

        run = BenchmarkRun.start(
            id="benchmark-malformed-hardcode-result",
            target_set=["juice-shop-foundation"],
            benchmark_mode="closed_book",
            mutation_seed="seed:2026-05-23",
            code_version="git:abc123",
            policy_version="policy:v1",
            model_versions={},
            hidden_solution_access_status="not_available_to_agent",
            hardcode_scan_result={"status": "not_run"},
        )

        with self.assertRaisesRegex(ValueError, "hardcode scan result malformed"):
            run.record_solve_result(
                solve_session_id="solve-juice-1",
                target_id="juice-shop-foundation",
                solve_status="blocked",
                result="no_solve",
                evidence_ids=["evidence:http-title"],
                policy_decision_ids=["policy:allow-recon"],
                hardcode_scan_result=("status", "pass"),
            )

    def test_benchmark_run_rejects_malformed_model_versions(self) -> None:
        with self.assertRaisesRegex(ValueError, "model versions malformed"):
            BenchmarkRun.start(
                id="benchmark-malformed-model-versions",
                target_set=["juice-shop-foundation"],
                benchmark_mode="closed_book",
                mutation_seed="seed:2026-05-23",
                code_version="git:abc123",
                policy_version="policy:v1",
                model_versions=("solver", "local_fast:v1"),
                hidden_solution_access_status="not_available_to_agent",
                hardcode_scan_result={"status": "not_run"},
            )

    def test_benchmark_run_rejects_invalid_model_version_entries(self) -> None:
        for model_versions in (
            {"": "local_fast:v1"},
            {"solver": ""},
            {"solver": 1},
        ):
            with self.subTest(model_versions=model_versions):
                with self.assertRaisesRegex(ValueError, "model versions entry"):
                    BenchmarkRun.start(
                        id="benchmark-invalid-model-version-entry",
                        target_set=["juice-shop-foundation"],
                        benchmark_mode="closed_book",
                        mutation_seed="seed:2026-05-23",
                        code_version="git:abc123",
                        policy_version="policy:v1",
                        model_versions=model_versions,
                        hidden_solution_access_status="not_available_to_agent",
                        hardcode_scan_result={"status": "not_run"},
                    )

    def test_benchmark_run_rejects_malformed_result_ref_containers(self) -> None:
        run = BenchmarkRun.start(
            id="benchmark-malformed-result-refs",
            target_set=["juice-shop-foundation"],
            benchmark_mode="closed_book",
            mutation_seed="seed:2026-05-23",
            code_version="git:abc123",
            policy_version="policy:v1",
            model_versions={},
            hidden_solution_access_status="not_available_to_agent",
            hardcode_scan_result={"status": "not_run"},
        )

        with self.assertRaisesRegex(ValueError, "evidence_ids malformed"):
            run.record_solve_result(
                solve_session_id="solve-juice-1",
                target_id="juice-shop-foundation",
                solve_status="blocked",
                result="no_solve",
                evidence_ids="evidence:http-title",
                policy_decision_ids=["policy:allow-recon"],
                hardcode_scan_result={"status": "pass"},
            )

        with self.assertRaisesRegex(ValueError, "policy_decision_ids malformed"):
            run.record_solve_result(
                solve_session_id="solve-juice-1",
                target_id="juice-shop-foundation",
                solve_status="blocked",
                result="no_solve",
                evidence_ids=["evidence:http-title"],
                policy_decision_ids="policy:allow-recon",
                hardcode_scan_result={"status": "pass"},
            )

    def test_benchmark_run_rejects_invalid_result_ref_entries(self) -> None:
        run = BenchmarkRun.start(
            id="benchmark-invalid-result-ref-entries",
            target_set=["juice-shop-foundation"],
            benchmark_mode="closed_book",
            mutation_seed="seed:2026-05-23",
            code_version="git:abc123",
            policy_version="policy:v1",
            model_versions={},
            hidden_solution_access_status="not_available_to_agent",
            hardcode_scan_result={"status": "not_run"},
        )

        for evidence_ids in ([1], [""]):
            with self.subTest(evidence_ids=evidence_ids):
                with self.assertRaisesRegex(ValueError, "evidence_ids entry"):
                    run.record_solve_result(
                        solve_session_id="solve-juice-1",
                        target_id="juice-shop-foundation",
                        solve_status="blocked",
                        result="no_solve",
                        evidence_ids=evidence_ids,
                        policy_decision_ids=["policy:allow-recon"],
                        hardcode_scan_result={"status": "pass"},
                    )

        for policy_decision_ids in ([1], [""]):
            with self.subTest(policy_decision_ids=policy_decision_ids):
                with self.assertRaisesRegex(ValueError, "policy_decision_ids entry"):
                    run.record_solve_result(
                        solve_session_id="solve-juice-1",
                        target_id="juice-shop-foundation",
                        solve_status="blocked",
                        result="no_solve",
                        evidence_ids=["evidence:http-title"],
                        policy_decision_ids=policy_decision_ids,
                        hardcode_scan_result={"status": "pass"},
                    )

    def test_benchmark_run_rejects_non_evidence_refs_in_solve_result_evidence_ids(self) -> None:
        run = BenchmarkRun.start(
            id="benchmark-non-evidence-result-ref",
            target_set=["juice-shop-foundation"],
            benchmark_mode="closed_book",
            mutation_seed="seed:2026-05-23",
            code_version="git:abc123",
            policy_version="policy:v1",
            model_versions={},
            hidden_solution_access_status="not_available_to_agent",
            hardcode_scan_result={"status": "not_run"},
        )

        with self.assertRaisesRegex(ValueError, "evidence_ids entry must use evidence:<id>"):
            run.record_solve_result(
                solve_session_id="solve-juice-1",
                target_id="juice-shop-foundation",
                solve_status="blocked",
                result="no_solve",
                evidence_ids=["note:operator-observation"],
                policy_decision_ids=["policy:allow-recon"],
                hardcode_scan_result={"status": "pass"},
            )

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


if __name__ == "__main__":
    unittest.main()
