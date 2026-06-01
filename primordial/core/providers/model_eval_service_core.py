from __future__ import annotations

from primordial.core.providers.model_eval_deps import (
    aggregate_model_eval_results,
    build_model_eval_score_payload,
    DEFAULT_MODEL_BENCHMARK_TIMEOUT_SECONDS,
    DEFAULT_MODEL_EVAL_CASE_SPECS,
    Iterable,
    Path,
    persist_model_eval_summary,
    write_model_eval_artifacts,
)

from primordial.core.providers.model_eval_types import (
    ModelEvalCase,
    ModelEvalResult,
    ModelEvalSummary,
    ModelRoleSuggestion,
)

class ModelEvalCoreMixin:
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
