from __future__ import annotations

from tests.test_ctf_harness_benchmark_common import *


class BenchmarkRunContractTestsPart2(BenchmarkRunContractTestsBase):
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

__all__ = ["BenchmarkRunContractTestsPart2"]
