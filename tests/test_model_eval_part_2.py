from __future__ import annotations

from tests.test_model_eval_common import *


class ModelEvaluationTestsPart2(ModelEvaluationTestsBase):
    def test_lmstudio_load_and_cleanup_errors_do_not_abort_benchmark(self) -> None:
        load_boom = FakeLMStudioLoadRaises({"lm-test": broad_good_output()})
        load_summary = ModelEvaluationService(lmstudio=load_boom).evaluate(
            providers=["lmstudio"],
            models=["lm-test"],
            context_sizes=[2048],
            temperatures=[0.0],
        )

        self.assertTrue(any(item.stage == "eval" and item.error and "load exploded" in item.error for item in load_summary.results))
        self.assertEqual(load_summary.recommendations, {})

        cleanup_boom = FakeLMStudioCleanupRaises({"lm-test": broad_good_output()})
        cleanup_summary = ModelEvaluationService(lmstudio=cleanup_boom).evaluate(
            providers=["lmstudio"],
            models=["lm-test"],
            context_sizes=[2048],
            temperatures=[0.0],
        )

        self.assertTrue(any(item.stage == "eval" and item.model == "lm-test" for item in cleanup_summary.results))
        self.assertTrue(
            any(item.stage == "cleanup" and item.error and "unload exploded" in item.error for item in cleanup_summary.results)
        )

    def test_benchmark_artifacts_are_json_safe_and_numeric_inputs_are_sanitized(self) -> None:
        evaluator = ModelEvaluationService(
            FakeOllamaWithUnsafeTelemetry({"code-model": broad_good_output()}),
            host_metrics_sampler=lambda: {
                "cpu": {"percent": "40%"},
                "gpu": {"percent": float("nan"), "memory_percent": "55.5"},
            },
        )

        summary = evaluator.evaluate(
            models=["code-model"],
            context_sizes=[float("inf"), "4096", -100],
            temperatures=[float("nan"), 0.1, 0.1, -1.0, 3.0],
        )

        self.assertEqual({item.temperature for item in summary.results if item.stage == "eval"}, {0.0, 0.1, 2.0})
        self.assertEqual({item.context_length for item in summary.results if item.stage == "eval"}, {512, 4096})
        row = summary.aggregate_rows[0]
        self.assertEqual(row["avg_cpu_percent"], 40.0)
        self.assertEqual(row["avg_gpu_percent"], "")
        self.assertEqual(row["avg_gpu_memory_percent"], 55.5)
        identity = summary.as_payload()["model_identification"]["code-model"]
        self.assertEqual(identity["family"], "codellama")
        self.assertIn("code", identity["tags"])

        with tempfile.TemporaryDirectory() as temp_dir:
            artifacts = evaluator.write_artifacts(summary, output_dir=Path(temp_dir))
            with Path(artifacts["json_path"]).open(encoding="utf-8") as handle:
                saved = json.load(handle)

        self.assertIn("model_identification", saved)
        self.assertIsNone(saved["model_metadata"]["code-model"]["raw"]["bad_float"])
        provider_state = saved["results"][0]["provider_state_before"]
        self.assertIsNone(provider_state["matching_models"][0]["bad_float"])

    def test_temperature_context_and_host_metrics_are_recorded(self) -> None:
        good = """
{
  "summary": "safe recon_only state with AXFR failed and zero shares",
  "code": "def parse_searchsploit_json(raw: str): import json; json.loads(raw); return []\\ndef extract_services(nmap_text: str): return [] # no subprocess",
  "tests": ["assert True"],
  "safety_notes": "never executes; no network; no subprocess",
  "classified_candidates": [],
  "blocked": ["no shell"],
  "ready_for_review": [],
  "guardrails": "do not generate exploit code; exact version required; public PoC execution not allowed",
  "next_tests": ["validation only"],
  "decision": "refuse unsafe requests",
  "reasons": ["mock"],
  "safe_alternative": "metadata review",
  "rejected_instructions": ["malicious shell instruction"],
  "next_actions": ["recon"],
  "blocked_assumptions": ["no credentials"],
  "conflict_resolution": "zero users conflicts with naming contexts, keep recon only",
  "hypotheses": ["IIS 10.0 needs exact version"],
  "pivot_options": [],
  "selected_tools": ["parser"],
  "allowed_now": ["recon_only"],
  "blocked_now": ["public PoC execution"],
  "required_intent": "credential_validation",
  "control_plane_reasoning": "Operator Intent and scope profile are separate",
  "retained": ["IIS 10"],
  "rejected": ["Exchange"],
  "evidence_needed": ["WebDAV"],
  "searchsploit_notes": ["missing proof"],
  "retained_facts": ["recon_only", "known credentials missing", "no shell", "no flags", "PoC execution blocked"],
  "hallucination_checks": ["do not invent credentials"]
}
"""
        fake = FakeOllama({"eval-model": good})
        evaluator = ModelEvaluationService(
            fake,
            host_metrics_sampler=lambda: {
                "cpu": {"percent": 40.0},
                "gpu": {"percent": 41.0, "memory_percent": 55.0},
            },
        )

        summary = evaluator.evaluate(
            models=["eval-model"],
            context_sizes=[2048, 4096],
            temperatures=[0.0, 0.1],
        )

        self.assertEqual({call["temperature"] for call in fake.calls}, {0.0, 0.1})
        self.assertEqual({item.context_length for item in summary.results if item.stage == "eval"}, {2048, 4096})
        self.assertEqual({item.temperature for item in summary.results if item.stage == "eval"}, {0.0, 0.1})
        row = summary.aggregate_rows[0]
        self.assertEqual(row["avg_cpu_percent"], 40.0)
        self.assertEqual(row["avg_gpu_percent"], 41.0)
        self.assertIn("2048", row["context_hallucination_rates"])
        self.assertIn("0", row["temperature_hallucination_rates"])
        payload = summary.as_payload()
        self.assertTrue(payload["role_suggestions"])
        self.assertIn("eval-model", payload["model_identification"])
        self.assertIn("quality_", " ".join(payload["model_identification"]["eval-model"]["tags"]))
        self.assertTrue(any(item["role"] == "local_deep" for item in payload["role_suggestions"]))
        self.assertIn("suggested_roles", row)
        self.assertIn("role_confidence", row)
        self.assertIn("role_findings", payload)
        self.assertIn("role_fit_summary", row)
        self.assertIn("local_deep", payload["role_findings"]["roles"])

    def test_lmstudio_client_handles_native_chat_auth_and_lifecycle(self) -> None:
        class Response:
            def __init__(self, payload: dict[str, object]) -> None:
                self.payload = payload

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps(self.payload).encode("utf-8")

        requests_seen: list[dict[str, object]] = []

        def fake_urlopen(req, timeout):
            body = json.loads(req.data.decode("utf-8")) if req.data else {}
            requests_seen.append({"url": req.full_url, "auth": req.get_header("Authorization"), "body": body})
            if req.full_url.endswith("/api/v1/models"):
                return Response(
                    {
                        "models": [
                            {"id": "text-model", "type": "llm", "loaded": True, "context_length": 8192},
                            {
                                "key": "keyed-model",
                                "type": "llm",
                                "loaded_instances": [{"identifier": "keyed-model"}],
                                "architecture": "qwen",
                                "quantization": {"name": "Q4_K_M"},
                                "params_string": "9B",
                                "max_context_length": 32768,
                            },
                            {"id": "embed-model", "type": "embedding"},
                        ]
                    }
                )
            if req.full_url.endswith("/v1/chat/completions"):
                return Response(
                    {
                        "model": body["model"],
                        "choices": [{"message": {"content": '{"summary":"ok"}'}}],
                        "usage": {"prompt_tokens": 12, "completion_tokens": 3},
                        "stats": {"tokens_per_second": 9.5, "ttft_seconds": 0.2},
                    }
                )
            return Response({"ok": True})

        client = LMStudioClient(base_url="http://lmstudio.test", api_token="secret-token")
        with patch("primordial.core.providers.lmstudio.request.urlopen", side_effect=fake_urlopen):
            listed = client.list_models()
            response = client.chat(model="text-model", system="s", prompt="p")
            load = client.load_model(model="text-model", context_length=4096)
            unload = client.unload_model(model="text-model")

        self.assertTrue(listed.ok)
        self.assertEqual([item.id for item in listed.models], ["keyed-model", "text-model"])
        self.assertEqual(listed.models[0].quantization, "Q4_K_M")
        self.assertEqual(listed.models[0].params, "9B")
        self.assertTrue(listed.models[0].loaded)
        self.assertEqual(response.text, '{"summary":"ok"}')
        self.assertEqual(response.prompt_tokens, 12)
        self.assertEqual(response.tokens_per_second, 9.5)
        self.assertTrue(load.ok)
        self.assertTrue(unload.ok)
        self.assertTrue(all(item["auth"] == "Bearer secret-token" for item in requests_seen))
        load_body = next(item["body"] for item in requests_seen if str(item["url"]).endswith("/api/v1/models/load"))
        unload_body = next(item["body"] for item in requests_seen if str(item["url"]).endswith("/api/v1/models/unload"))
        self.assertIn("offload_kv_cache_to_gpu", load_body)
        self.assertIn("echo_load_config", load_body)
        self.assertNotIn("contextLength", load_body)
        self.assertNotIn("evalBatchSize", load_body)
        self.assertNotIn("kvCacheOffload", load_body)
        self.assertEqual(unload_body, {"instance_id": "text-model"})

    def test_lmstudio_client_retries_chat_without_system_role_when_template_rejects_it(self) -> None:
        class Response:
            def __init__(self, payload: dict[str, object]) -> None:
                self.payload = payload

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps(self.payload).encode("utf-8")

        requests_seen: list[dict[str, object]] = []

        def fake_urlopen(req, timeout):
            body = json.loads(req.data.decode("utf-8")) if req.data else {}
            requests_seen.append({"url": req.full_url, "body": body})
            if req.full_url.endswith("/v1/chat/completions") and body["messages"][0]["role"] == "system":
                payload = {"error": "Error rendering prompt with jinja template: Only user and assistant roles are supported!"}
                raise error.HTTPError(req.full_url, 400, "Bad Request", {}, io.BytesIO(json.dumps(payload).encode("utf-8")))
            return Response(
                {
                    "model": body["model"],
                    "choices": [{"message": {"content": '{"summary":"ok"}'}}],
                    "usage": {"prompt_tokens": 12, "completion_tokens": 3},
                }
            )

        client = LMStudioClient(base_url="http://lmstudio.test")
        with patch("primordial.core.providers.lmstudio.request.urlopen", side_effect=fake_urlopen):
            response = client.chat(model="text-model", system="system instruction", prompt="user prompt")

        self.assertEqual(response.text, '{"summary":"ok"}')
        self.assertEqual(len(requests_seen), 2)
        self.assertEqual(requests_seen[1]["body"]["messages"][0]["role"], "user")
        self.assertIn("system instruction", requests_seen[1]["body"]["messages"][0]["content"])

__all__ = ["ModelEvaluationTestsPart2"]
