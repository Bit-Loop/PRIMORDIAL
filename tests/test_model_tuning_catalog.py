from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from primordial.core.catalog.loader import CatalogValidationError, load_yaml_file
from primordial.core.catalog.model_tuning import ModelTuningCatalog


REPO_ROOT = Path(__file__).resolve().parents[1]


class ModelTuningCatalogTests(unittest.TestCase):
    def test_lmstudio_tuning_markdown_is_migrated_to_typed_catalog(self) -> None:
        tuning = ModelTuningCatalog(REPO_ROOT / "catalog" / "project").load()

        self.assertEqual(tuning.id, "lmstudio_tuning_live_20260509")
        self.assertEqual(tuning.source_path, "ai-tuning.md")
        self.assertEqual(tuning.status, "migrated_live_benchmark_profile")
        self.assertEqual(tuning.date, "2026-05-09")
        self.assertEqual(tuning.live_tuning.context_length, 1024)
        self.assertEqual(tuning.live_tuning.max_tokens, 128)
        self.assertEqual(tuning.live_tuning.temperature, 0.0)
        self.assertEqual(tuning.live_tuning.cpu_reserve_mb, 4096)
        self.assertEqual(tuning.live_tuning.vram_soft_reserve_mb, 128)
        self.assertEqual(tuning.live_tuning.timeout_seconds, 120)
        self.assertFalse(tuning.execution_context.runtime_cli_used)
        self.assertEqual(tuning.execution_context.runtime_cli_skip_reason, "primordial_database_url_not_configured")
        self.assertIn("proc_meminfo", tuning.execution_context.sampler_sources)
        self.assertIn("nvidia_smi", tuning.execution_context.sampler_sources)

    def test_lmstudio_tuning_preserves_models_artifacts_and_best_configs(self) -> None:
        tuning = ModelTuningCatalog(REPO_ROOT / "catalog" / "project").load()
        best = {item.model: item for item in tuning.best_configs}

        self.assertEqual(len(tuning.models_checked), 7)
        self.assertIn("gpt-oss-cybersecurity-20b-merged-heretic-i1", tuning.models_checked)
        self.assertEqual(tuning.result.status, "ok")
        self.assertEqual(tuning.result.rows_recorded, 105)
        self.assertEqual(tuning.result.warnings, ())
        self.assertEqual(
            tuning.result.detailed_artifact,
            "artifacts/model_eval/lmstudio_tuning_live_20260509T000055Z/lmstudio_tuning_20260509T001430Z.json",
        )
        self.assertEqual(tuning.result.reusable_profile, "runtime/model_eval/lmstudio_performance_profile.json")
        self.assertFalse(tuning.result.post_run_loaded_models_reported)

        self.assertAlmostEqual(best["lily-cybersecurity-7b-v0.2"].tokens_per_second, 124.2831)
        self.assertEqual(best["lily-cybersecurity-7b-v0.2"].best_load_config.eval_batch_size, 1024)
        self.assertTrue(best["lily-cybersecurity-7b-v0.2"].best_load_config.flash_attention)
        self.assertTrue(best["lily-cybersecurity-7b-v0.2"].best_load_config.offload_kv_cache_to_gpu)
        self.assertIsNone(best["lily-cybersecurity-7b-v0.2"].best_load_config.num_experts)
        self.assertEqual(best["qwen3.5-35b-a3b-uncensored-hauhaucs-aggressive"].best_load_config.num_experts, 4)

    def test_role_findings_are_relative_and_do_not_enable_code_auto_routing(self) -> None:
        tuning = ModelTuningCatalog(REPO_ROOT / "catalog" / "project").load()
        roles = {item.role: item for item in tuning.role_findings.roles}

        self.assertFalse(tuning.role_findings.recommendation_gate_met)
        self.assertEqual(tuning.role_findings.guidance, "relative_guidance_not_durable_role_routing")
        self.assertIn("recommendation_id", tuning.role_findings.aggregate_row_fields)
        self.assertIn("role_fit_summary", tuning.role_findings.aggregate_row_fields)
        self.assertEqual(roles["local_fast"].relative_best, ("lily-cybersecurity-7b-v0.2",))
        self.assertIn("pass_rate_only_0.1176", roles["local_fast"].caution)
        self.assertEqual(
            roles["local_code"].relative_best,
            ("lily-cybersecurity-7b-v0.2", "gpt-oss-cybersecurity-20b-merged-heretic-i1"),
        )
        self.assertFalse(tuning.role_findings.practical_defaults.auto_route_code_work)
        self.assertEqual(tuning.role_findings.practical_defaults.small_context_workhorse, "lily-cybersecurity-7b-v0.2")
        self.assertEqual(
            tuning.role_findings.practical_defaults.deep_candidate_to_retest,
            "qwen3.5-35b-a3b-uncensored-hauhaucs-aggressive",
        )

    def test_runtime_guard_preserves_skip_policy_and_cli_override(self) -> None:
        tuning = ModelTuningCatalog(REPO_ROOT / "catalog" / "project").load()
        guard = tuning.runtime_guard

        self.assertEqual(guard.max_model_runtime_seconds, 1800)
        self.assertEqual(guard.max_model_runtime_label, "30 minutes")
        self.assertEqual(guard.skip_result.stage, "planning")
        self.assertEqual(guard.skip_result.error, "skipped_estimated_timeout")
        self.assertEqual(guard.skip_result.load_state, "skipped_estimated_timeout")
        self.assertIn("tokens_per_second", guard.estimate_inputs)
        self.assertIn("benchmark_case_count", guard.estimate_inputs)
        self.assertEqual(guard.offload_targets, ("claude", "gpt"))
        self.assertIn("eval_config.runtime_estimates", guard.eval_metadata_fields)
        self.assertIn("--max-model-minutes 45", guard.cli_override)
        self.assertIn("runtime/model_eval/lmstudio_performance_profile.json", guard.saved_artifacts_updated)

    def test_runtime_guard_saved_source_artifacts_are_existing_catalog_authorities(self) -> None:
        tuning = ModelTuningCatalog(REPO_ROOT / "catalog" / "project").load()
        required_paths = (
            tuning.result.detailed_artifact,
            *tuning.runtime_guard.saved_artifacts_updated,
        )

        missing = [
            path
            for path in required_paths
            if not path.startswith("runtime/") and not (REPO_ROOT / path).exists()
        ]

        self.assertEqual(missing, [])

    def test_model_eval_artifact_cleanup_manifest_tracks_removed_generated_json(self) -> None:
        manifest = load_yaml_file(REPO_ROOT / "catalog" / "project" / "model_eval_artifact_cleanup.yaml")
        removed = manifest["removed_artifacts"]

        self.assertEqual(manifest["status"], "generated_artifact_cleanup_manifest")
        self.assertEqual(len(removed), 2)
        for record in removed:
            self.assertFalse((REPO_ROOT / record["path"]).exists())
            self.assertRegex(record["sha256"], r"^[0-9a-f]{64}$")
            self.assertGreater(record["bytes"], 0)
            self.assertTrue(record["reason"])
            self.assertTrue(record["retained_refs"])
            self.assertEqual(
                [ref for ref in record["retained_refs"] if not (REPO_ROOT / ref).exists()],
                [],
            )

    def test_model_tuning_catalog_rejects_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "lmstudio_tuning.yaml").write_text(
                "id: lmstudio_tuning_live_20260509\n"
                "source_path: ai-tuning.md\n"
                "status: migrated_live_benchmark_profile\n"
                "date: '2026-05-09'\n"
                "live_tuning:\n"
                "  context_length: 1024\n"
                "  max_tokens: 128\n"
                "  temperature: 0.0\n"
                "  cpu_reserve_mb: 4096\n"
                "  vram_soft_reserve_mb: 128\n"
                "  timeout_seconds: 120\n"
                "execution_context:\n"
                "  runtime_cli_used: false\n"
                "  runtime_cli_skip_reason: primordial_database_url_not_configured\n"
                "  provider_level_tuner_used: true\n"
                "  sampler_sources: []\n"
                "models_checked: []\n"
                "result:\n"
                "  status: ok\n"
                "  rows_recorded: 0\n"
                "  warnings: []\n"
                "  detailed_artifact: artifact.json\n"
                "  reusable_profile: profile.json\n"
                "  post_run_loaded_models_reported: false\n"
                "best_configs: []\n"
                "role_findings:\n"
                "  recommendation_gate_met: false\n"
                "  guidance: relative_guidance_not_durable_role_routing\n"
                "  aggregate_row_fields: []\n"
                "  roles: []\n"
                "  practical_defaults:\n"
                "    small_context_workhorse: none\n"
                "    next_cyber_code_candidate: none\n"
                "    deep_candidate_to_retest: none\n"
                "    auto_route_code_work: false\n"
                "runtime_guard:\n"
                "  max_model_runtime_seconds: 1800\n"
                "  max_model_runtime_label: 30 minutes\n"
                "  estimate_inputs: []\n"
                "  skip_result:\n"
                "    stage: planning\n"
                "    error: skipped_estimated_timeout\n"
                "    load_state: skipped_estimated_timeout\n"
                "  result_fields: []\n"
                "  offload_targets: []\n"
                "  eval_metadata_fields: []\n"
                "  cli_override: override\n"
                "  saved_artifacts_updated: []\n"
                "usage_commands: []\n"
                "unknown: true\n",
                encoding="utf-8",
            )

            with self.assertRaises(CatalogValidationError):
                ModelTuningCatalog(root).load()


if __name__ == "__main__":
    unittest.main()
