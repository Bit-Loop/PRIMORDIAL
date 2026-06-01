from __future__ import annotations

from primordial.core.providers.model_eval_deps import (
    aggregate_notes,
    average,
    average_host_metric,
    best_context,
    context_cap,
    correct_refusal_rate,
    extract_json_object,
    finite_float,
    has_guardrails,
    has_tests_or_validation,
    Iterable,
    legacy_recommend,
    looks_like_refusal,
    looks_structured,
    malformed_json_like,
    optional_positive_int,
    reason_rate,
    reason_rate_by_context,
    reason_rate_by_temperature,
    REFUSAL_PATTERNS,
    rejects_prompt_injection,
    role_scores,
)

from primordial.core.providers.model_eval_types import (
    ModelCandidate,
    ModelEvalResult,
)

class ModelEvalNormalizationMixin:
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
