from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from primordial.core.providers.lmstudio import LMStudioClient, LMStudioModelInfo
from primordial.core.providers.model_eval_aggregation import aggregate_model_eval_results
from primordial.core.providers.model_eval_artifacts import json_safe as _json_safe
from primordial.core.providers.model_eval_artifacts import write_model_eval_artifacts
from primordial.core.providers.model_eval_cases import DEFAULT_MODEL_EVAL_CASE_SPECS
from primordial.core.providers.model_eval_constants import DEFAULT_MODEL_BENCHMARK_TIMEOUT_SECONDS
from primordial.core.providers.model_eval_constants import DEFAULT_UNSAFE_PATTERNS
from primordial.core.providers.model_eval_constants import REFUSAL_PATTERNS
from primordial.core.providers.model_eval_constants import ROLE_NAMES
from primordial.core.providers.model_eval_failures import estimated_timeout_result
from primordial.core.providers.model_eval_failures import failed_context_results
from primordial.core.providers.model_eval_failures import offload_recommendation
from primordial.core.providers.model_eval_failures import runtime_timeout_result_if_needed
from primordial.core.providers.model_eval_identification import identify_model_eval_models
from primordial.core.providers.model_eval_identity import build_identity_tags
from primordial.core.providers.model_eval_identity import build_quality_profile
from primordial.core.providers.model_eval_identity import build_role_finding_rationale
from primordial.core.providers.model_eval_identity import build_role_fit_summary
from primordial.core.providers.model_eval_identity import metadata_role_score
from primordial.core.providers.model_eval_identity import model_size_class
from primordial.core.providers.model_eval_measurements import aggregate_notes
from primordial.core.providers.model_eval_measurements import average
from primordial.core.providers.model_eval_measurements import average_host_metric
from primordial.core.providers.model_eval_measurements import best_context
from primordial.core.providers.model_eval_measurements import context_cap
from primordial.core.providers.model_eval_measurements import correct_refusal_rate
from primordial.core.providers.model_eval_measurements import extract_json_object
from primordial.core.providers.model_eval_measurements import finite_float
from primordial.core.providers.model_eval_measurements import has_guardrails
from primordial.core.providers.model_eval_measurements import has_tests_or_validation
from primordial.core.providers.model_eval_measurements import legacy_recommend
from primordial.core.providers.model_eval_measurements import looks_like_refusal
from primordial.core.providers.model_eval_measurements import looks_structured
from primordial.core.providers.model_eval_measurements import malformed_json_like
from primordial.core.providers.model_eval_measurements import optional_positive_int
from primordial.core.providers.model_eval_measurements import reason_rate
from primordial.core.providers.model_eval_measurements import reason_rate_by_context
from primordial.core.providers.model_eval_measurements import reason_rate_by_temperature
from primordial.core.providers.model_eval_measurements import rejects_prompt_injection
from primordial.core.providers.model_eval_measurements import role_scores
from primordial.core.providers.model_eval_persistence import persist_model_eval_summary
from primordial.core.providers.model_eval_recommendations import recommend_model_eval_roles
from primordial.core.providers.model_eval_role_findings import build_model_eval_role_findings
from primordial.core.providers.model_eval_role_selection import relative_candidates_for_model_eval_role
from primordial.core.providers.model_eval_role_selection import suggest_model_eval_roles
from primordial.core.providers.model_eval_role_suggestions import build_role_suggestion_payload
from primordial.core.providers.model_eval_runtime_estimates import estimate_model_runtime
from primordial.core.providers.model_eval_runtime_profiles import build_model_eval_runtime_profile
from primordial.core.providers.model_eval_scoring import build_model_eval_score_payload
from primordial.core.providers.ollama import OllamaClient


GenerateCallable = Callable[..., object]


@dataclass(frozen=True, slots=True)
class ModelEvalCase:
    id: str
    category: str
    title: str
    system: str
    prompt: str
    required_terms: tuple[str, ...]
    forbidden_terms: tuple[str, ...] = DEFAULT_UNSAFE_PATTERNS
    min_score: float = 0.72
    weight: float = 1.0
    role_name: str = ""
    scenario_group: str = ""
    scenario_tags: tuple[str, ...] = ()
    expected_terms: tuple[str, ...] = ()
    hallucination_terms: tuple[str, ...] = ()
    unsafe_request: bool = False
    authorized_safe_request: bool = False
    prompt_injection: bool = False


@dataclass(slots=True)
class ModelCandidate:
    provider: str
    model: str
    architecture: str | None = None
    quantization: str | None = None
    params: str | None = None
    size: int | None = None
    max_context_length: int | None = None
    loaded: bool = True
    raw: dict[str, object] = field(default_factory=dict)

    @property
    def recommendation_id(self) -> str:
        return self.model if self.provider == "ollama" else f"{self.provider}:{self.model}"

    def as_payload(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "model": self.model,
            "recommendation_id": self.recommendation_id,
            "architecture": self.architecture,
            "quantization": self.quantization,
            "params": self.params,
            "size": self.size,
            "max_context_length": self.max_context_length,
            "loaded": self.loaded,
            "raw": _json_safe(self.raw),
        }


@dataclass(slots=True)
class ModelEvalResult:
    model: str
    case_id: str
    category: str
    score: float
    passed: bool
    elapsed_seconds: float | None
    reasons: list[str] = field(default_factory=list)
    output_excerpt: str = ""
    role_name: str = ""
    stage: str = "eval"
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    retry_count: int = 0
    provider: str = "ollama"
    context_length: int | None = None
    temperature: float = 0.0
    scenario_group: str = ""
    tokens_per_second: float | None = None
    ttft_seconds: float | None = None
    load_time_seconds: float | None = None
    load_state: str = "already_loaded"
    error: str | None = None
    host_metrics_before: dict[str, object] = field(default_factory=dict)
    host_metrics_after: dict[str, object] = field(default_factory=dict)
    provider_state_before: dict[str, object] = field(default_factory=dict)
    provider_state_after: dict[str, object] = field(default_factory=dict)
    reasoning_content_excerpt: str = ""
    finish_reason: str | None = None
    load_config: dict[str, object] = field(default_factory=dict)
    tuned_profile_applied: bool = False
    estimated_runtime_seconds: float | None = None
    max_runtime_seconds: int | None = None
    benchmark_plan: dict[str, object] = field(default_factory=dict)
    offload_recommendation: dict[str, object] = field(default_factory=dict)

    @property
    def recommendation_id(self) -> str:
        return self.model if self.provider == "ollama" else f"{self.provider}:{self.model}"

    def as_payload(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "model": self.model,
            "recommendation_id": self.recommendation_id,
            "case_id": self.case_id,
            "category": self.category,
            "role_name": self.role_name or self.category,
            "score": round(self.score, 4),
            "passed": self.passed,
            "elapsed_seconds": self.elapsed_seconds,
            "reasons": list(self.reasons),
            "output_excerpt": self.output_excerpt,
            "stage": self.stage,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "retry_count": self.retry_count,
            "context_length": self.context_length,
            "temperature": self.temperature,
            "scenario_group": self.scenario_group or self.category,
            "tokens_per_second": self.tokens_per_second,
            "ttft_seconds": self.ttft_seconds,
            "load_time_seconds": self.load_time_seconds,
            "load_state": self.load_state,
            "error": self.error,
            "host_metrics_before": _json_safe(self.host_metrics_before),
            "host_metrics_after": _json_safe(self.host_metrics_after),
            "provider_state_before": _json_safe(self.provider_state_before),
            "provider_state_after": _json_safe(self.provider_state_after),
            "reasoning_content_excerpt": self.reasoning_content_excerpt,
            "finish_reason": self.finish_reason,
            "load_config": _json_safe(self.load_config),
            "tuned_profile_applied": self.tuned_profile_applied,
            "estimated_runtime_seconds": self.estimated_runtime_seconds,
            "max_runtime_seconds": self.max_runtime_seconds,
            "benchmark_plan": _json_safe(self.benchmark_plan),
            "offload_recommendation": _json_safe(self.offload_recommendation),
        }


@dataclass(slots=True)
class ModelRoleSuggestion:
    role: str
    provider: str
    model: str
    recommendation_id: str
    rank: int
    confidence: float
    fit_score: float
    status: str
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    metrics: dict[str, object] = field(default_factory=dict)
    metadata_factors: dict[str, object] = field(default_factory=dict)

    def as_payload(self) -> dict[str, object]:
        return {
            "role": self.role,
            "provider": self.provider,
            "model": self.model,
            "recommendation_id": self.recommendation_id,
            "rank": self.rank,
            "confidence": round(self.confidence, 4),
            "fit_score": round(self.fit_score, 4),
            "status": self.status,
            "reasons": list(self.reasons),
            "warnings": list(self.warnings),
            "metrics": _json_safe(self.metrics),
            "metadata_factors": _json_safe(self.metadata_factors),
        }


@dataclass(slots=True)
class ModelEvalSummary:
    models: list[str]
    results: list[ModelEvalResult]
    recommendations: dict[str, str]
    providers: list[str] = field(default_factory=list)
    model_metadata: dict[str, dict[str, object]] = field(default_factory=dict)
    model_identification: dict[str, dict[str, object]] = field(default_factory=dict)
    role_suggestions: list[ModelRoleSuggestion] = field(default_factory=list)
    aggregate_rows: list[dict[str, object]] = field(default_factory=list)
    artifacts: dict[str, str] = field(default_factory=dict)
    judge_metadata: dict[str, object] = field(default_factory=dict)
    eval_config: dict[str, object] = field(default_factory=dict)
    role_findings: dict[str, object] = field(default_factory=dict)

    def as_payload(self) -> dict[str, object]:
        return {
            "providers": self.providers,
            "models": self.models,
            "results": [item.as_payload() for item in self.results],
            "model_metadata": _json_safe(self.model_metadata),
            "model_identification": _json_safe(self.model_identification),
            "role_suggestions": [item.as_payload() for item in self.role_suggestions],
            "aggregate_rows": _json_safe(self.aggregate_rows),
            "recommendations": self.recommendations,
            "artifacts": self.artifacts,
            "judge_metadata": _json_safe(self.judge_metadata),
            "eval_config": _json_safe(self.eval_config),
            "role_findings": _json_safe(self.role_findings),
        }


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


class ModelEvaluationService:
    def __init__(
        self,
        ollama: OllamaClient | None = None,
        lmstudio: LMStudioClient | None = None,
        host_metrics_sampler: Callable[[], dict[str, object]] | None = None,
        lmstudio_profile: dict[str, object] | None = None,
    ) -> None:
        self.ollama = ollama
        self.lmstudio = lmstudio
        self.host_metrics_sampler = host_metrics_sampler
        self.lmstudio_profile = lmstudio_profile or {}

    def default_cases(self) -> list[ModelEvalCase]:
        return [ModelEvalCase(**spec) for spec in DEFAULT_MODEL_EVAL_CASE_SPECS]

    def candidate_models(
        self,
        preferred: list[str] | None = None,
        limit: int | None = None,
        providers: list[str] | None = None,
    ) -> list[str]:
        candidates, _errors = self._candidate_pool(providers or ["ollama"])
        if preferred:
            selected = self._select_preferred(candidates, preferred)
        else:
            selected = candidates
        ranked = sorted(selected, key=lambda candidate: self._model_priority_key(candidate.model))
        ids = [candidate.recommendation_id for candidate in ranked]
        return ids[:limit] if limit else ids

    def evaluate(
        self,
        *,
        models: list[str] | None = None,
        limit: int | None = None,
        include_outputs: bool = False,
        num_gpu: int | None = 0,
        timeout_seconds: int = 120,
        providers: list[str] | None = None,
        exhaustive: bool = False,
        max_context: int = 32768,
        temperatures: Iterable[float] | None = None,
        context_sizes: Iterable[int] | None = None,
        judge_model: str | None = None,
        max_model_runtime_seconds: int = DEFAULT_MODEL_BENCHMARK_TIMEOUT_SECONDS,
    ) -> ModelEvalSummary:
        from primordial.core.providers.model_eval_runner import run_model_evaluation

        return run_model_evaluation(
            self,
            result_type=ModelEvalResult,
            summary_type=ModelEvalSummary,
            models=models,
            limit=limit,
            include_outputs=include_outputs,
            num_gpu=num_gpu,
            timeout_seconds=timeout_seconds,
            providers=providers,
            exhaustive=exhaustive,
            max_context=max_context,
            temperatures=temperatures,
            context_sizes=context_sizes,
            judge_model=judge_model,
            max_model_runtime_seconds=max_model_runtime_seconds,
        )

    def write_artifacts(
        self,
        summary: ModelEvalSummary,
        *,
        output_dir: Path,
        csv_path: Path | None = None,
        json_path: Path | None = None,
    ) -> dict[str, str]:
        return write_model_eval_artifacts(
            summary,
            output_dir=output_dir,
            csv_path=csv_path,
            json_path=json_path,
        )

    def persist(self, summary: ModelEvalSummary, store: object) -> None:
        persist_model_eval_summary(summary, store)

    def score_output(
        self,
        *,
        model: str,
        case: ModelEvalCase,
        output: str,
        elapsed_seconds: float | None,
        include_output: bool = False,
        temperature: float = 0.0,
    ) -> ModelEvalResult:
        payload = build_model_eval_score_payload(
            self,
            model=model,
            case=case,
            output=output,
            elapsed_seconds=elapsed_seconds,
            include_output=include_output,
            temperature=temperature,
        )
        return ModelEvalResult(**payload)

    def aggregate(
        self,
        results: list[ModelEvalResult],
        model_metadata: dict[str, dict[str, object]] | None = None,
        *,
        recommendations: dict[str, str] | None = None,
        role_suggestions: list[ModelRoleSuggestion] | None = None,
        model_identification: dict[str, dict[str, object]] | None = None,
    ) -> list[dict[str, object]]:
        return aggregate_model_eval_results(
            self,
            results,
            model_metadata,
            recommendations=recommendations,
            role_suggestions=role_suggestions,
            model_identification=model_identification,
        )

    def role_findings(
        self,
        *,
        recommendations: dict[str, str],
        role_suggestions: list[ModelRoleSuggestion],
        aggregate_rows: list[dict[str, object]],
        model_identification: dict[str, dict[str, object]],
    ) -> dict[str, object]:
        return build_model_eval_role_findings(
            self,
            recommendations=recommendations,
            role_suggestions=role_suggestions,
            aggregate_rows=aggregate_rows,
            model_identification=model_identification,
        )

    def _relative_best_model_for_role(self, role: str, aggregate_rows: list[dict[str, object]]) -> str:
        candidates = self._relative_candidates_for_role(role, aggregate_rows)
        return str(candidates[0]["model"]) if candidates else ""

    def _relative_candidates_for_role(self, role: str, aggregate_rows: list[dict[str, object]]) -> list[dict[str, object]]:
        return relative_candidates_for_model_eval_role(self, role, aggregate_rows)

    def suggest_roles(
        self,
        results: list[ModelEvalResult],
        model_metadata: dict[str, dict[str, object]] | None = None,
    ) -> list[ModelRoleSuggestion]:
        return suggest_model_eval_roles(self, results, model_metadata=model_metadata)

    def identify_models(
        self,
        results: list[ModelEvalResult],
        model_metadata: dict[str, dict[str, object]] | None = None,
        role_suggestions: list[ModelRoleSuggestion] | None = None,
    ) -> dict[str, dict[str, object]]:
        return identify_model_eval_models(
            self,
            results,
            model_metadata=model_metadata,
            role_suggestions=role_suggestions,
        )

    def recommend(
        self,
        results: list[ModelEvalResult],
        *,
        role_suggestions: list[ModelRoleSuggestion] | None = None,
    ) -> dict[str, str]:
        return recommend_model_eval_roles(self, results, role_suggestions=role_suggestions)

    def _role_suggestion(
        self,
        role: str,
        model_id: str,
        model_results: list[ModelEvalResult],
        role_results: list[ModelEvalResult],
        metadata: dict[str, object],
    ) -> ModelRoleSuggestion:
        payload = build_role_suggestion_payload(
            self,
            role=role,
            model_id=model_id,
            model_results=model_results,
            role_results=role_results,
            metadata=metadata,
        )
        return ModelRoleSuggestion(**payload)

    def _role_fit_summary(
        self,
        *,
        recommended_roles: list[str],
        model_suggestions: list[ModelRoleSuggestion],
    ) -> dict[str, object]:
        return build_role_fit_summary(recommended_roles=recommended_roles, model_suggestions=model_suggestions)

    def _role_finding_rationale(self, suggestions: list[ModelRoleSuggestion]) -> list[str]:
        return build_role_finding_rationale(suggestions)

    def _metadata_role_score(self, role: str, model_id: str, metadata: dict[str, object]) -> float:
        return metadata_role_score(self, role, model_id, metadata)

    def _role_speed_weight(self, role: str) -> float:
        return {
            "local_fast": 0.16,
            "local_compact": 0.11,
            "local_code": 0.05,
            "local_deep": 0.03,
        }.get(role, 0.04)

    def _role_context_weight(self, role: str) -> float:
        return {
            "local_deep": 0.10,
            "local_compact": 0.07,
            "local_code": 0.04,
            "local_fast": 0.02,
        }.get(role, 0.03)

    def _speed_score(self, *, avg_latency: float, avg_tokens: float) -> float:
        latency_component = 0.0
        if avg_latency:
            latency_component = self._clamp(1.0 - min(avg_latency, 60.0) / 60.0, 0.0, 1.0)
        token_component = self._clamp(avg_tokens / 45.0, 0.0, 1.0) if avg_tokens else 0.0
        if avg_latency and avg_tokens:
            return (latency_component * 0.65) + (token_component * 0.35)
        return latency_component or token_component

    def _model_family(self, model_id: str, metadata: dict[str, object]) -> str:
        architecture = str(metadata.get("architecture") or "").strip().lower()
        lowered = model_id.lower()
        for family in ("codellama", "codestral", "deepseek", "mixtral", "qwen", "llama", "gemma", "mistral", "phi"):
            if family in architecture or family in lowered:
                return family
        return architecture or "unknown"

    def _size_class(self, params: object) -> str:
        return model_size_class(params)

    def _context_class(self, max_context: object) -> str:
        value = self._optional_positive_int(max_context) or 0
        if value >= 32768:
            return "very_long_context"
        if value >= 16384:
            return "long_context"
        if value >= 8192:
            return "standard_context"
        if value > 0:
            return "short_context"
        return "unknown_context"

    def _max_result_context(self, results: list[ModelEvalResult]) -> int | None:
        contexts = [item.context_length for item in results if isinstance(item.context_length, int)]
        return max(contexts) if contexts else None

    def _runtime_profile(self, results: list[ModelEvalResult]) -> dict[str, object]:
        return build_model_eval_runtime_profile(self, results)

    def _quality_profile(self, results: list[ModelEvalResult]) -> dict[str, object]:
        return build_quality_profile(self, results)

    def _identity_tags(
        self,
        *,
        model_id: str,
        family: str,
        size_class: str,
        context_class: str,
        runtime_profile: dict[str, object],
        quality_profile: dict[str, object],
    ) -> list[str]:
        return build_identity_tags(
            model_id=model_id,
            family=family,
            size_class=size_class,
            context_class=context_class,
            runtime_profile=runtime_profile,
            quality_profile=quality_profile,
        )

    def _clamp(self, value: float, minimum: float, maximum: float) -> float:
        return max(minimum, min(maximum, value))

    def _candidate_pool(self, providers: list[str]) -> tuple[list[ModelCandidate], list[dict[str, str]]]:
        candidates: list[ModelCandidate] = []
        errors: list[dict[str, str]] = []
        adapters = self._adapters(providers)
        for provider in self._normalize_providers(providers):
            adapter = adapters.get(provider)
            if adapter is None:
                errors.append({"provider": provider, "error": f"{provider} provider client is not configured"})
                continue
            try:
                provider_candidates, error = adapter.list_candidates()
            except Exception as exc:  # noqa: BLE001 - benchmark should report provider failures in-band
                errors.append({"provider": provider, "error": str(exc)})
                continue
            candidates.extend(provider_candidates)
            if error:
                errors.append({"provider": provider, "error": error})
        return candidates, errors

    def _judge_metadata(
        self,
        judge_model: str | None,
        recommendations: dict[str, str],
        results: list[ModelEvalResult],
    ) -> dict[str, object]:
        selected = (judge_model or recommendations.get("local_deep") or "").strip()
        if not selected:
            return {
                "selected_model": "",
                "source": "none",
                "status": "not_available",
                "note": "No local_deep recommendation was available for supplemental judging.",
            }
        matching = [item for item in results if item.recommendation_id == selected or item.model == selected]
        source = "operator" if judge_model else "local_deep_recommendation"
        return {
            "selected_model": selected,
            "source": source,
            "status": "metadata_only",
            "deterministic_score_authoritative": True,
            "evaluated_case_count": len(matching),
            "note": (
                "Supplemental judge selection is recorded for auditability; deterministic scenario scoring remains authoritative."
            ),
        }

    def _adapters(self, providers: list[str]) -> dict[str, object]:
        adapters: dict[str, object] = {}
        for provider in self._normalize_providers(providers):
            if provider == "ollama" and self.ollama is not None:
                adapters[provider] = _OllamaAdapter(self.ollama)
            elif provider == "lmstudio" and self.lmstudio is not None:
                adapters[provider] = _LMStudioAdapter(self.lmstudio, performance_profile=self.lmstudio_profile)
        return adapters

    def _adapter_load_config(self, adapter: object, candidate: ModelCandidate) -> dict[str, object]:
        getter = getattr(adapter, "load_config_for", None)
        if not callable(getter):
            return {}
        try:
            value = getter(candidate)
        except Exception:  # noqa: BLE001 - config telemetry must not break evaluation
            return {}
        return dict(value) if isinstance(value, dict) else {}

    def _adapter_profile_applied(self, adapter: object, candidate: ModelCandidate) -> bool:
        getter = getattr(adapter, "profile_applied_for", None)
        if not callable(getter):
            return False
        try:
            return bool(getter(candidate))
        except Exception:  # noqa: BLE001 - config telemetry must not break evaluation
            return False

    def _select_preferred(self, candidates: list[ModelCandidate], preferred: list[str] | None) -> list[ModelCandidate]:
        if not preferred:
            return candidates
        selected: list[ModelCandidate] = []
        by_recommendation = {candidate.recommendation_id: candidate for candidate in candidates}
        by_model = {candidate.model: candidate for candidate in candidates}
        for raw in preferred:
            model = str(raw).strip()
            if not model:
                continue
            candidate = by_recommendation.get(model) or by_model.get(model)
            if candidate and candidate not in selected:
                selected.append(candidate)
        return selected

    def _missing_preferred_models(self, candidates: list[ModelCandidate], preferred: list[str] | None) -> list[str]:
        if not preferred:
            return []
        available = {candidate.recommendation_id for candidate in candidates} | {candidate.model for candidate in candidates}
        missing: list[str] = []
        for raw in preferred:
            model = str(raw).strip()
            if model and model not in available and model not in missing:
                missing.append(model)
        return missing

    def _estimate_model_runtime(
        self,
        candidate: ModelCandidate,
        *,
        contexts: list[int],
        temperatures: list[float],
        case_count: int,
        max_runtime_seconds: int,
    ) -> dict[str, object]:
        return estimate_model_runtime(
            self,
            candidate,
            contexts=contexts,
            temperatures=temperatures,
            case_count=case_count,
            max_runtime_seconds=max_runtime_seconds,
        )

    def _estimated_timeout_result(
        self,
        candidate: ModelCandidate,
        estimate: dict[str, object],
    ) -> ModelEvalResult:
        return estimated_timeout_result(self, ModelEvalResult, candidate, estimate)

    def _runtime_timeout_result_if_needed(
        self,
        candidate: ModelCandidate,
        model_started: float,
        max_runtime_seconds: int,
    ) -> ModelEvalResult | None:
        return runtime_timeout_result_if_needed(self, ModelEvalResult, candidate, model_started, max_runtime_seconds)

    def _lmstudio_profile_entry(self, candidate: ModelCandidate) -> dict[str, object]:
        profile = self.lmstudio_profile if isinstance(self.lmstudio_profile, dict) else {}
        models = profile.get("models")
        if not isinstance(models, dict):
            return {}
        for key in (candidate.recommendation_id, candidate.model, f"lmstudio:{candidate.model}"):
            value = models.get(key)
            if isinstance(value, dict):
                return value
        return {}

    def _estimated_output_tokens(self, context_length: int) -> int:
        return max(128, min(2048, int(context_length) // 8))

    def _offload_recommendation(
        self,
        candidate: ModelCandidate,
        estimated_seconds: float | None,
        max_runtime_seconds: int | None,
    ) -> dict[str, object]:
        return offload_recommendation(candidate, estimated_seconds, max_runtime_seconds)

    def _format_seconds(self, value: object) -> str:
        seconds = self._finite_float(value)
        if seconds is None:
            return "unknown"
        minutes = seconds / 60.0
        return f"{minutes:.1f}m"

    def _failed_context_results(
        self,
        candidate: ModelCandidate,
        context_length: int,
        temperatures: list[float],
        load_state: str,
        load_time: float | None,
        error: str,
    ) -> list[ModelEvalResult]:
        return failed_context_results(
            self,
            ModelEvalResult,
            candidate,
            context_length,
            temperatures,
            load_state,
            load_time,
            error,
        )

    def _contexts_for_model(self, candidate: ModelCandidate, *, exhaustive: bool, max_context: int) -> list[int]:
        cap = self._context_cap(max_context)
        candidate_cap = self._optional_positive_int(candidate.max_context_length)
        if candidate_cap:
            cap = min(cap, max(512, candidate_cap))
        if not exhaustive:
            return [min(8192, cap)]
        contexts = [2048, 4096, 8192, 16384, 32768]
        clipped = [context for context in contexts if context <= cap]
        if cap not in clipped:
            clipped.append(cap)
        return sorted(set(max(512, item) for item in clipped))

    def _normalize_temperatures(self, temperatures: Iterable[float] | None) -> list[float]:
        raw = list(temperatures) if temperatures is not None else [0.0, 0.1]
        values: list[float] = []
        for item in raw:
            parsed = self._finite_float(item)
            if parsed is None:
                continue
            value = round(max(0.0, min(2.0, parsed)), 3)
            if value not in values:
                values.append(value)
        return values or [0.0]

    def _normalize_context_sizes(self, context_sizes: Iterable[int] | None, *, max_context: int) -> list[int]:
        if context_sizes is None:
            return []
        cap = self._context_cap(max_context)
        values: set[int] = set()
        for item in context_sizes:
            parsed_float = self._finite_float(item)
            parsed = int(parsed_float) if parsed_float is not None else None
            if parsed is not None:
                values.add(max(512, min(cap, parsed)))
        values = sorted(values)
        return values

    def _host_metrics_snapshot(self) -> dict[str, object]:
        if self.host_metrics_sampler is None:
            return {}
        try:
            return dict(self.host_metrics_sampler())
        except Exception as exc:  # noqa: BLE001 - telemetry must not break evaluation
            return {"ok": False, "error": str(exc)}

    def _provider_state_snapshot(self, adapter: object, candidate: ModelCandidate) -> dict[str, object]:
        sampler = getattr(adapter, "provider_state", None)
        if not callable(sampler):
            return {}
        try:
            payload = sampler(candidate)
        except Exception as exc:  # noqa: BLE001 - telemetry must not break evaluation
            return {"ok": False, "error": str(exc)}
        return dict(payload) if isinstance(payload, dict) else {"raw": payload}

    def _normalize_providers(self, providers: Iterable[str]) -> list[str]:
        normalized: list[str] = []
        for item in providers:
            for provider in str(item).split(","):
                clean = provider.strip().lower()
                if clean in {"ollama", "lmstudio"} and clean not in normalized:
                    normalized.append(clean)
        return normalized or ["ollama"]

    def _model_priority_key(self, model: str) -> tuple[int, str]:
        lowered = model.lower()
        if lowered.endswith(":cloud"):
            return (99, lowered)
        if "coder" in lowered or "codellama" in lowered:
            return (0, lowered)
        if "phi4" in lowered or "reason" in lowered:
            return (1, lowered)
        if "deepseek" in lowered:
            return (2, lowered)
        if "gemma" in lowered or "qwen" in lowered:
            return (3, lowered)
        return (4, lowered)

    def _looks_structured(self, output: str) -> bool:
        return looks_structured(output)

    def _malformed_json_like(self, output: str) -> bool:
        return malformed_json_like(output)

    def _extract_json_object(self, output: str) -> str:
        return extract_json_object(output)

    def _has_tests_or_validation(self, output: str) -> bool:
        return has_tests_or_validation(output)

    def _has_guardrails(self, output: str) -> bool:
        return has_guardrails(output)

    def _looks_like_refusal(self, output: str) -> bool:
        return looks_like_refusal(output, REFUSAL_PATTERNS)

    def _rejects_prompt_injection(self, output: str) -> bool:
        return rejects_prompt_injection(output, REFUSAL_PATTERNS)

    def _role_scores(self, results: list[ModelEvalResult]) -> dict[str, float]:
        return role_scores(results, self._legacy_role_for_category)

    def _best_context(self, results: list[ModelEvalResult]) -> int | str:
        return best_context(results)

    def _reason_rate(self, results: list[ModelEvalResult], needle: str) -> float:
        return reason_rate(results, needle)

    def _reason_rate_by_context(self, results: list[ModelEvalResult], needle: str) -> dict[str, float]:
        return reason_rate_by_context(results, needle)

    def _reason_rate_by_temperature(self, results: list[ModelEvalResult], needle: str) -> dict[str, float]:
        return reason_rate_by_temperature(results, needle)

    def _average_host_metric(self, results: list[ModelEvalResult], path: tuple[str, str]) -> float | str:
        return average_host_metric(results, path)

    def _correct_refusal_rate(self, results: list[ModelEvalResult]) -> float:
        return correct_refusal_rate(results)

    def _aggregate_notes(self, results: list[ModelEvalResult]) -> str:
        return aggregate_notes(results)

    def _average(self, values: Iterable[float | int | None]) -> float:
        return average(values)

    def _finite_float(self, value: object) -> float | None:
        return finite_float(value)

    def _optional_positive_int(self, value: object) -> int | None:
        return optional_positive_int(value)

    def _context_cap(self, value: object, *, default: int = 32768) -> int:
        return context_cap(value, default=default)

    def _legacy_role_for_category(self, category: str) -> str:
        if category in {"poc_generation", "code_generation"}:
            return "local_code"
        if category == "summarization":
            return "local_compact"
        if category in {"reasoning", "research"}:
            return "local_deep"
        if category in {"triage", "safety"}:
            return "local_fast"
        return ""

    def _legacy_recommend(self, results: list[ModelEvalResult]) -> str:
        return legacy_recommend(
            results,
            lambda avg_score, pass_rate: self._role_results_are_recommendable(
                avg_score=avg_score,
                pass_rate=pass_rate,
            ),
        )

    def _role_results_are_recommendable(self, *, avg_score: float, pass_rate: float) -> bool:
        return avg_score >= 0.62 and pass_rate >= 0.5

    def _case_weight(self, case_id: str) -> float:
        for case in self.default_cases():
            if case.id == case_id:
                return case.weight
        return 1.0
