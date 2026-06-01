from __future__ import annotations

from tests.test_model_eval_common import *


class _FakeBenchmarkRuntime:
    MODEL_ROLE_CONFIG = {
        "local_fast": {},
        "local_deep": {},
        "local_code": {},
        "local_compact": {},
    }
    last = None

    @classmethod
    def from_env(cls):
        cls.last = cls()
        return cls.last

    def initialize(self) -> None:
        self.initialized = True

    def shutdown(self) -> None:
        self.shutdown_called = True

    def evaluate_models(self, **kwargs):
        self.kwargs = kwargs
        return {
            "providers": kwargs["providers"],
            "models": ["ollama-test", "lmstudio:lm-test"],
            "results": [],
            "model_metadata": {},
            "model_identification": {
                "ollama-test": {
                    "tags": ["fast", "quality_strong"],
                    "suggested_roles": [{"role": "local_fast", "rank": 1, "confidence": 0.91}],
                }
            },
            "role_suggestions": [self._role_suggestion()],
            "aggregate_rows": [self._aggregate_row()],
            "recommendations": {"local_fast": "ollama-test", "local_code": "lmstudio:lm-test"},
            "artifacts": {"csv_path": "/tmp/eval.csv", "json_path": "/tmp/eval.json"},
        }

    def _role_suggestion(self) -> dict[str, object]:
        return {
            "role": "local_fast",
            "provider": "ollama",
            "model": "ollama-test",
            "recommendation_id": "ollama-test",
            "rank": 1,
            "confidence": 0.91,
            "status": "recommended",
            "reasons": ["fast runtime fit"],
            "warnings": [],
        }

    def _aggregate_row(self) -> dict[str, object]:
        return {
            "provider": "ollama",
            "model": "ollama-test",
            "identified_tags": "fast,quality_strong",
            "role_recommendation": "local_fast",
            "suggested_roles": [{"role": "local_fast", "rank": 1, "confidence": 0.91}],
            "role_confidence": {"local_fast": 0.91},
            "aggregate_score": 0.9,
            "avg_latency_sec": 1.2,
            "avg_tokens_sec": 30.0,
            "best_context_length": 2048,
        }


class ModelEvaluationTestsPart4(ModelEvaluationTestsBase):
    def test_cli_evaluate_passes_new_benchmark_flags_without_live_providers(self) -> None:
        stdout = io.StringIO()
        with patch("primordial.cli.run_startup_preflight"), patch(
            "primordial.cli.PrimordialRuntime", _FakeBenchmarkRuntime
        ), redirect_stdout(stdout):
            exit_code = cli_main(
                [
                    "models",
                    "evaluate",
                    "--providers",
                    "ollama,lmstudio",
                    "--exhaustive",
                    "--max-context",
                    "4096",
                    "--context-size",
                    "1024",
                    "--temperature",
                    "0.0",
                    "--temperature",
                    "0.1",
                    "--lmstudio-profile",
                    "/tmp/lmstudio-profile.json",
                    "--max-model-minutes",
                    "45",
                    "--csv",
                    "/tmp/eval.csv",
                    "--json-out",
                    "/tmp/eval.json",
                ]
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(_FakeBenchmarkRuntime.last.kwargs["providers"], ["ollama", "lmstudio"])
        self.assertTrue(_FakeBenchmarkRuntime.last.kwargs["exhaustive"])
        self.assertEqual(_FakeBenchmarkRuntime.last.kwargs["max_context"], 4096)
        self.assertEqual(_FakeBenchmarkRuntime.last.kwargs["context_sizes"], [1024])
        self.assertEqual(_FakeBenchmarkRuntime.last.kwargs["temperatures"], [0.0, 0.1])
        self.assertEqual(_FakeBenchmarkRuntime.last.kwargs["lmstudio_profile_path"], Path("/tmp/lmstudio-profile.json"))
        self.assertTrue(_FakeBenchmarkRuntime.last.kwargs["use_lmstudio_profile"])
        self.assertEqual(_FakeBenchmarkRuntime.last.kwargs["max_model_runtime_seconds"], 2700)
        self.assertIn("local_code: lmstudio:lm-test", stdout.getvalue())
        self.assertIn("role suggestions:", stdout.getvalue())
        self.assertIn("confidence=0.91", stdout.getvalue())

    def test_cli_tune_lmstudio_passes_flags_without_live_provider(self) -> None:
        class FakeRuntime:
            MODEL_ROLE_CONFIG = {
                "local_fast": {},
                "local_deep": {},
                "local_code": {},
                "local_compact": {},
            }
            last = None

            @classmethod
            def from_env(cls):
                cls.last = cls()
                return cls.last

            def initialize(self) -> None:
                self.initialized = True

            def shutdown(self) -> None:
                self.shutdown_called = True

            def tune_lmstudio_models(self, **kwargs):
                self.kwargs = kwargs
                return {
                    "status": "ok",
                    "models": {
                        "lm-test": {
                            "best_config": {"eval_batch_size": 1024, "flash_attention": True},
                            "tokens_per_second": 55.0,
                        }
                    },
                    "artifacts": {"profile_path": "/tmp/profile.json", "json_path": "/tmp/tuning.json"},
                    "warnings": [],
                }

        stdout = io.StringIO()
        with patch("primordial.cli.run_startup_preflight"), patch(
            "primordial.cli.PrimordialRuntime", FakeRuntime
        ), redirect_stdout(stdout):
            exit_code = cli_main(
                [
                    "models",
                    "tune-lmstudio",
                    "--model",
                    "lm-test",
                    "--context",
                    "1024",
                    "--max-tokens",
                    "64",
                    "--cpu-reserve-mb",
                    "4096",
                    "--vram-soft-reserve-mb",
                    "128",
                    "--timeout",
                    "5",
                    "--profile-out",
                    "/tmp/profile.json",
                    "--json-out",
                    "/tmp/tuning.json",
                ]
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(FakeRuntime.last.kwargs["models"], ["lm-test"])
        self.assertEqual(FakeRuntime.last.kwargs["context_length"], 1024)
        self.assertEqual(FakeRuntime.last.kwargs["max_tokens"], 64)
        self.assertEqual(FakeRuntime.last.kwargs["cpu_reserve_mb"], 4096)
        self.assertEqual(FakeRuntime.last.kwargs["vram_soft_reserve_mb"], 128)
        self.assertEqual(FakeRuntime.last.kwargs["profile_out"], Path("/tmp/profile.json"))
        self.assertIn("tok/s=55.0", stdout.getvalue())

__all__ = ["ModelEvaluationTestsPart4"]
