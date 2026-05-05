from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from primordial.config import AppConfig
from primordial.core.providers.model_eval import ModelEvaluationService
from primordial.core.providers.ollama import OllamaModelListResult, OllamaResponse
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
  "safety_notes": "never executes; denial of service entries filtered",
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
  "safety_notes": "never executes; denial of service filtered",
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
            finally:
                runtime.shutdown()

        self.assertEqual(payload["models"], ["qwen3-coder-next:q4_K_M"])
        self.assertEqual(fake.calls[0]["num_gpu"], 0)
        self.assertIn("local_code", payload["recommendations"])


if __name__ == "__main__":
    unittest.main()
