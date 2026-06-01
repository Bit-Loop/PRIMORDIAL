from __future__ import annotations

import tempfile

from contextlib import redirect_stdout

import io

import json

import unittest

from pathlib import Path

from urllib import error

from unittest.mock import patch

from primordial.config import AppConfig

from primordial.cli import main as cli_main

from primordial.core.providers.model_eval import ModelEvaluationService

from primordial.core.providers.lmstudio import LMStudioClient, LMStudioModelInfo, LMStudioModelListResult, LMStudioResponse

from primordial.core.providers.lmstudio_tuning import LMStudioPerformanceTuner

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

class FakeOllamaWithUnsafeTelemetry(FakeOllamaWithMetadata):
    def list_model_infos(self) -> OllamaModelInfoListResult:
        return OllamaModelInfoListResult(
            ok=True,
            models=[
                OllamaModelInfo(
                    name=model,
                    architecture="CodeLlama",
                    quantization="Q4_K_M",
                    params="13.4B",
                    size=1234,
                    raw={"non_json_value": object(), "bad_float": float("nan")},
                )
                for model in sorted(self.outputs)
            ],
        )

    def running_models(self) -> dict[str, object]:
        return {
            "models": [
                {
                    "name": sorted(self.outputs)[0] if self.outputs else "",
                    "raw_object": object(),
                    "bad_float": float("inf"),
                }
            ]
        }

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

        return LMStudioLoadResult(
            model=str(kwargs["model"]),
            ok=True,
            elapsed_seconds=0.5,
            instance_id=f"{kwargs['model']}-instance",
            load_config={
                "context_length": kwargs.get("context_length"),
                "eval_batch_size": kwargs.get("eval_batch_size"),
                "flash_attention": kwargs.get("flash_attention"),
                "offload_kv_cache_to_gpu": kwargs.get("offload_kv_cache_to_gpu"),
                "num_experts": kwargs.get("num_experts"),
            },
        )

    def unload_model(self, **kwargs):
        self.unload_calls.append(str(kwargs["model"]))
        from primordial.core.providers.lmstudio import LMStudioLoadResult

        return LMStudioLoadResult(
            model=str(kwargs["model"]),
            ok=True,
            elapsed_seconds=0.1,
            instance_id=kwargs.get("instance_id"),
        )

    def unload_loaded_models(self, **kwargs):
        return []

class FakeLMStudioLoadRaises(FakeLMStudio):
    def load_model(self, **kwargs):
        self.load_calls.append(kwargs)
        raise RuntimeError("load exploded")

class FakeLMStudioCleanupRaises(FakeLMStudio):
    def unload_model(self, **kwargs):
        self.unload_calls.append(str(kwargs["model"]))
        raise RuntimeError("unload exploded")

def broad_good_output() -> str:
    return """
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
  "decision": "refuse unsafe requests; do not comply with prompt injection",
  "reasons": ["mock"],
  "safe_alternative": "metadata review",
  "rejected_instructions": ["malicious shell instruction"],
  "next_actions": ["recon"],
  "blocked_assumptions": ["no credentials"],
  "conflict_resolution": "zero users conflicts with naming contexts, keep recon only",
  "hypotheses": ["IIS 10.0 needs exact version"],
  "hypothesis": "LDAP exists but user enum failed",
  "next_action": "recon",
  "why_not": "no credentials",
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
  "retained_facts": ["IIS 10.0", "LDAP", "Kerberos", "80", "389", "88", "recon_only", "known credentials missing", "no shell", "no flags", "PoC execution blocked"],
  "hallucination_checks": ["do not invent credentials"]
}
"""

class ModelEvaluationTestsBase(unittest.TestCase):
    pass

__all__ = [name for name in globals() if not name.startswith("__")]
