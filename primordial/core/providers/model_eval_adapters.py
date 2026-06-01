from __future__ import annotations

from primordial.core.providers.model_eval_deps import (
    LMStudioClient,
    LMStudioModelInfo,
    OllamaClient,
    dataclass,
)
from primordial.core.providers.model_eval_types import ModelCandidate


@dataclass(slots=True)
class _UnifiedResponse:
    model: str
    text: str
    elapsed_seconds: float | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    tokens_per_second: float | None = None
    ttft_seconds: float | None = None
    reasoning_content: str = ""
    finish_reason: str | None = None


class _OllamaAdapter:
    provider = "ollama"

    def __init__(self, client: OllamaClient) -> None:
        self.client = client

    def list_candidates(self) -> tuple[list[ModelCandidate], str | None]:
        if hasattr(self.client, "list_model_infos"):
            result = self.client.list_model_infos()
            if not result.ok:
                return [], result.error or "Ollama model listing failed"
            return [
                ModelCandidate(
                    provider=self.provider,
                    model=item.name,
                    architecture=item.architecture,
                    quantization=item.quantization,
                    params=item.params,
                    size=item.size,
                    loaded=True,
                    raw=item.raw,
                )
                for item in result.models
            ], None
        result = self.client.list_models()
        if not result.ok:
            return [], result.error or "Ollama model listing failed"
        return [ModelCandidate(provider=self.provider, model=model, loaded=True) for model in result.models], None

    def generate(
        self,
        *,
        candidate: ModelCandidate,
        system: str,
        prompt: str,
        temperature: float,
        context_length: int,
        num_gpu: int | None,
        timeout_seconds: int,
    ) -> _UnifiedResponse:
        response = self.client.generate(
            model=candidate.model,
            system=system,
            prompt=prompt,
            temperature=temperature,
            num_ctx=context_length,
            num_gpu=num_gpu,
            timeout_seconds=timeout_seconds,
        )
        tokens_per_second = None
        if response.completion_tokens and response.elapsed_seconds and response.elapsed_seconds > 0:
            tokens_per_second = float(response.completion_tokens) / response.elapsed_seconds
        return _UnifiedResponse(
            model=response.model,
            text=response.text,
            elapsed_seconds=response.elapsed_seconds,
            prompt_tokens=response.prompt_tokens,
            completion_tokens=response.completion_tokens,
            tokens_per_second=tokens_per_second,
        )

    def load_for_context(self, candidate: ModelCandidate, context_length: int) -> tuple[str, float | None, str | None]:
        return "already_loaded", None, None

    def cleanup(self, candidate: ModelCandidate) -> tuple[str, str | None]:
        return "skipped", None

    def provider_state(self, candidate: ModelCandidate) -> dict[str, object]:
        if not hasattr(self.client, "running_models"):
            return {}
        try:
            state = self.client.running_models()
        except Exception as exc:  # noqa: BLE001 - telemetry must not break evaluation
            return {"ok": False, "error": str(exc)}
        if isinstance(state, dict):
            models = state.get("models", [])
            if isinstance(models, list):
                matching = [
                    item
                    for item in models
                    if isinstance(item, dict) and str(item.get("name") or item.get("model") or "") == candidate.model
                ]
                return {**state, "matching_models": matching}
            return state
        return {"raw": state}


class _LMStudioAdapter:
    provider = "lmstudio"

    def __init__(self, client: LMStudioClient, performance_profile: dict[str, object] | None = None) -> None:
        self.client = client
        self.performance_profile = performance_profile or {}
        self._loaded_by_eval: dict[str, str | None] = {}
        self._load_configs: dict[str, dict[str, object]] = {}
        self._profile_applied: set[str] = set()

    def list_candidates(self) -> tuple[list[ModelCandidate], str | None]:
        result = self.client.list_models()
        if not result.ok:
            return [], result.error or "LM Studio model listing failed"
        candidates = [self._candidate_from_info(model) for model in result.models]
        return candidates, None

    def generate(
        self,
        *,
        candidate: ModelCandidate,
        system: str,
        prompt: str,
        temperature: float,
        context_length: int,
        num_gpu: int | None,
        timeout_seconds: int,
    ) -> _UnifiedResponse:
        del num_gpu
        response = self.client.chat(
            model=candidate.model,
            system=system,
            prompt=prompt,
            temperature=temperature,
            num_ctx=context_length,
            timeout_seconds=timeout_seconds,
        )
        return _UnifiedResponse(
            model=response.model,
            text=response.text,
            elapsed_seconds=response.elapsed_seconds,
            prompt_tokens=response.prompt_tokens,
            completion_tokens=response.completion_tokens,
            tokens_per_second=response.tokens_per_second,
            ttft_seconds=response.ttft_seconds,
            reasoning_content=response.reasoning_content,
            finish_reason=response.finish_reason,
        )

    def load_for_context(self, candidate: ModelCandidate, context_length: int) -> tuple[str, float | None, str | None]:
        tuned_config = self._tuned_config_for(candidate)
        if candidate.loaded and not tuned_config:
            return "already_loaded", None, None
        if candidate.loaded and tuned_config:
            try:
                self.client.unload_model(model=candidate.model)
            except Exception:
                pass
        result = self.client.load_model(
            model=candidate.model,
            context_length=context_length,
            eval_batch_size=int(tuned_config.get("eval_batch_size", 512)),
            flash_attention=bool(tuned_config.get("flash_attention", True)),
            offload_kv_cache_to_gpu=bool(tuned_config.get("offload_kv_cache_to_gpu", True)),
            num_experts=self._optional_positive_int(tuned_config.get("num_experts")),
        )
        if result.ok:
            self._loaded_by_eval[candidate.model] = result.instance_id
            self._load_configs[candidate.model] = dict(result.load_config)
            if tuned_config:
                self._profile_applied.add(candidate.model)
            return "loaded_by_eval_tuned" if tuned_config else "loaded_by_eval", result.elapsed_seconds, None
        self._load_configs[candidate.model] = dict(result.load_config)
        return "load_failed", result.elapsed_seconds, result.error or "LM Studio load failed"

    def cleanup(self, candidate: ModelCandidate) -> tuple[str, str | None]:
        if candidate.model not in self._loaded_by_eval:
            return "skipped", None
        result = self.client.unload_model(model=candidate.model, instance_id=self._loaded_by_eval.get(candidate.model))
        self._loaded_by_eval.pop(candidate.model, None)
        return ("unloaded", None) if result.ok else ("unload_failed", result.error)

    def provider_state(self, candidate: ModelCandidate) -> dict[str, object]:
        return {
            "provider": self.provider,
            "model": candidate.model,
            "loaded_at_list_time": candidate.loaded,
            "max_context_length": candidate.max_context_length,
            "load_strategy": "sequential_auto_load",
            "tuned_profile_available": bool(self._tuned_config_for(candidate)),
            "tuned_profile_applied": candidate.model in self._profile_applied,
            "load_config": self._load_configs.get(candidate.model, {}),
            "raw": candidate.raw,
        }

    def load_config_for(self, candidate: ModelCandidate) -> dict[str, object]:
        return dict(self._load_configs.get(candidate.model, {}))

    def profile_applied_for(self, candidate: ModelCandidate) -> bool:
        return candidate.model in self._profile_applied

    def _candidate_from_info(self, info: LMStudioModelInfo) -> ModelCandidate:
        return ModelCandidate(
            provider=self.provider,
            model=info.id,
            architecture=info.architecture,
            quantization=info.quantization,
            params=info.params,
            size=info.size,
            max_context_length=info.max_context_length,
            loaded=info.loaded,
            raw=info.raw,
        )

    def _tuned_config_for(self, candidate: ModelCandidate) -> dict[str, object]:
        profile = self.performance_profile if isinstance(self.performance_profile, dict) else {}
        models = profile.get("models")
        if not isinstance(models, dict):
            return {}
        keys = (candidate.recommendation_id, candidate.model, f"lmstudio:{candidate.model}")
        entry: object = None
        for key in keys:
            entry = models.get(key)
            if isinstance(entry, dict):
                break
        if not isinstance(entry, dict):
            return {}
        raw_config = entry.get("best_config") or entry.get("load_config") or entry.get("config") or {}
        if not isinstance(raw_config, dict):
            return {}
        config: dict[str, object] = {}
        eval_batch_size = self._optional_positive_int(raw_config.get("eval_batch_size"))
        if eval_batch_size:
            config["eval_batch_size"] = eval_batch_size
        if "flash_attention" in raw_config:
            config["flash_attention"] = bool(raw_config.get("flash_attention"))
        if "offload_kv_cache_to_gpu" in raw_config:
            config["offload_kv_cache_to_gpu"] = bool(raw_config.get("offload_kv_cache_to_gpu"))
        num_experts = self._optional_positive_int(raw_config.get("num_experts"))
        if num_experts:
            config["num_experts"] = num_experts
        return config

    def _optional_positive_int(self, value: object) -> int | None:
        if isinstance(value, bool):
            return None
        if isinstance(value, int) and value > 0:
            return value
        if isinstance(value, float) and value > 0:
            return int(value)
        if isinstance(value, str) and value.strip().isdigit():
            parsed = int(value.strip())
            return parsed if parsed > 0 else None
        return None
