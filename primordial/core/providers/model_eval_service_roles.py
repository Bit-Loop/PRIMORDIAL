from __future__ import annotations

from primordial.core.providers.model_eval_deps import (
    build_identity_tags,
    build_model_eval_role_findings,
    build_model_eval_runtime_profile,
    build_quality_profile,
    build_role_finding_rationale,
    build_role_fit_summary,
    build_role_suggestion_payload,
    identify_model_eval_models,
    metadata_role_score,
    model_size_class,
    recommend_model_eval_roles,
    relative_candidates_for_model_eval_role,
    suggest_model_eval_roles,
)

from primordial.core.providers.model_eval_types import (
    ModelEvalResult,
    ModelRoleSuggestion,
)

class ModelEvalRolesMixin:
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
