from __future__ import annotations

from primordial.core.providers.model_eval_deps import (
    DEFAULT_UNSAFE_PATTERNS,
    _json_safe,
    dataclass,
    field,
)


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
