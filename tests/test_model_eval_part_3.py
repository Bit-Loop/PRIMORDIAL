from __future__ import annotations

from tests.test_model_eval_common import *


class ModelEvaluationTestsPart3(ModelEvaluationTestsBase):
    def test_lmstudio_client_preserves_reasoning_only_response(self) -> None:
        class Response:
            def __init__(self, payload: dict[str, object]) -> None:
                self.payload = payload

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps(self.payload).encode("utf-8")

        def fake_urlopen(req, timeout):
            return Response(
                {
                    "model": "reasoning-model",
                    "choices": [
                        {
                            "message": {"content": "", "reasoning_content": "private reasoning trace"},
                            "finish_reason": "length",
                        }
                    ],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 20},
                }
            )

        client = LMStudioClient(base_url="http://lmstudio.test")
        with patch("primordial.core.providers.lmstudio.request.urlopen", side_effect=fake_urlopen):
            response = client.chat(model="reasoning-model", system="s", prompt="p")

        self.assertEqual(response.text, "")
        self.assertEqual(response.reasoning_content, "private reasoning trace")
        self.assertEqual(response.finish_reason, "length")

    def test_lmstudio_profile_applies_to_evaluation_load_config(self) -> None:
        profile = {
            "models": {
                "lmstudio:lm-test": {
                    "best_config": {
                        "eval_batch_size": 1024,
                        "flash_attention": False,
                        "offload_kv_cache_to_gpu": False,
                        "num_experts": 4,
                    }
                }
            }
        }
        lmstudio = FakeLMStudio({"lm-test": broad_good_output()})
        summary = ModelEvaluationService(lmstudio=lmstudio, lmstudio_profile=profile).evaluate(
            providers=["lmstudio"],
            models=["lm-test"],
            context_sizes=[2048],
            temperatures=[0.0],
        )

        self.assertEqual(lmstudio.load_calls[0]["context_length"], 2048)
        self.assertEqual(lmstudio.load_calls[0]["eval_batch_size"], 1024)
        self.assertFalse(lmstudio.load_calls[0]["flash_attention"])
        self.assertFalse(lmstudio.load_calls[0]["offload_kv_cache_to_gpu"])
        self.assertEqual(lmstudio.load_calls[0]["num_experts"], 4)
        eval_results = [item for item in summary.results if item.stage == "eval"]
        self.assertTrue(eval_results)
        self.assertTrue(all(item.tuned_profile_applied for item in eval_results))
        self.assertEqual(eval_results[0].load_config["eval_batch_size"], 1024)

    def test_lmstudio_runtime_estimate_skips_slow_model_for_remote_offload(self) -> None:
        profile = {
            "models": {
                "lmstudio:slow-model": {
                    "tokens_per_second": 1.0,
                    "load_time_seconds": 0.0,
                    "best_config": {
                        "eval_batch_size": 512,
                        "flash_attention": True,
                        "offload_kv_cache_to_gpu": True,
                    },
                }
            }
        }
        lmstudio = FakeLMStudio({"slow-model": broad_good_output()})
        summary = ModelEvaluationService(lmstudio=lmstudio, lmstudio_profile=profile).evaluate(
            providers=["lmstudio"],
            models=["slow-model"],
            context_sizes=[4096],
            temperatures=[0.0],
            max_model_runtime_seconds=30,
        )
        payload = summary.as_payload()

        self.assertEqual(lmstudio.load_calls, [])
        self.assertEqual(lmstudio.chat_calls, [])
        self.assertEqual(payload["results"][0]["stage"], "planning")
        self.assertEqual(payload["results"][0]["error"], "skipped_estimated_timeout")
        self.assertIn("claude", payload["results"][0]["offload_recommendation"]["targets"])
        self.assertIn("gpt", payload["results"][0]["offload_recommendation"]["targets"])
        estimate = payload["eval_config"]["runtime_estimates"]["lmstudio:slow-model"]
        self.assertEqual(estimate["action"], "skip_remote_offload")
        self.assertGreater(estimate["estimated_seconds"], estimate["max_runtime_seconds"])

    def test_lmstudio_reasoning_only_eval_is_not_transport_failure(self) -> None:
        class ReasoningOnlyLMStudio(FakeLMStudio):
            def chat(self, **kwargs) -> LMStudioResponse:
                self.chat_calls.append(kwargs)
                return LMStudioResponse(
                    model=str(kwargs["model"]),
                    text="",
                    reasoning_content="thinking without final content",
                    finish_reason="length",
                    elapsed_seconds=1.0,
                    completion_tokens=20,
                    tokens_per_second=20.0,
                )

        lmstudio = ReasoningOnlyLMStudio({"lm-test": ""})
        summary = ModelEvaluationService(lmstudio=lmstudio).evaluate(
            providers=["lmstudio"],
            models=["lm-test"],
            context_sizes=[2048],
            temperatures=[0.0],
        )

        eval_results = [item for item in summary.results if item.stage == "eval"]
        self.assertTrue(eval_results)
        self.assertTrue(any("reasoning-only response" in " ".join(item.reasons) for item in eval_results))
        self.assertFalse(any(item.error and "generation failed" in item.error for item in eval_results))

    def test_lmstudio_tuner_selects_best_config_and_writes_profile(self) -> None:
        class SpeedyLMStudio(FakeLMStudio):
            def chat(self, **kwargs) -> LMStudioResponse:
                self.chat_calls.append(kwargs)
                last_load = self.load_calls[-1]
                speed = float(last_load["eval_batch_size"]) / 16.0
                if last_load["offload_kv_cache_to_gpu"]:
                    speed += 10.0
                if not last_load["flash_attention"]:
                    speed -= 20.0
                return LMStudioResponse(
                    model=str(kwargs["model"]),
                    text='{"summary":"ok"}',
                    elapsed_seconds=1.0,
                    prompt_tokens=20,
                    completion_tokens=32,
                    tokens_per_second=speed,
                    ttft_seconds=0.1,
                )

        client = SpeedyLMStudio({"speed-model": '{"summary":"ok"}'})
        def metrics() -> dict[str, object]:
            return {
                "cpu": {"memory_available_mb": 16000},
                "gpu": {"available": True, "memory_free_mb": 512},
            }

        tuner = LMStudioPerformanceTuner(client, host_metrics_sampler=metrics)

        payload = tuner.tune(models=["speed-model"], context_length=1024, max_tokens=32, timeout_seconds=1)

        self.assertEqual(payload["status"], "ok")
        self.assertIn("role_findings", payload)
        self.assertEqual(payload["benchmark_head"]["max_model_runtime_seconds"], 1800)
        self.assertEqual(payload["role_findings"]["roles"]["local_fast"]["recommended_model"], "speed-model")
        best_config = payload["models"]["speed-model"]["best_config"]
        self.assertEqual(best_config["eval_batch_size"], 1024)
        self.assertTrue(best_config["flash_attention"])
        self.assertTrue(best_config["offload_kv_cache_to_gpu"])
        with tempfile.TemporaryDirectory() as temp_dir:
            artifacts = tuner.write_artifacts(
                payload,
                output_dir=Path(temp_dir) / "details",
                profile_path=Path(temp_dir) / "profile.json",
            )
            self.assertTrue(Path(artifacts["json_path"]).exists())
            self.assertTrue(Path(artifacts["profile_path"]).exists())

    def test_lmstudio_tuner_aborts_before_load_when_cpu_reserve_is_low(self) -> None:
        client = FakeLMStudio({"speed-model": '{"summary":"ok"}'})
        tuner = LMStudioPerformanceTuner(
            client,
            host_metrics_sampler=lambda: {"cpu": {"memory_available_mb": 1024}, "gpu": {"available": True}},
        )

        payload = tuner.tune(models=["speed-model"], cpu_reserve_mb=4096)

        self.assertEqual(payload["status"], "aborted")
        self.assertEqual(client.load_calls, [])

__all__ = ["ModelEvaluationTestsPart3"]
