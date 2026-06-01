from __future__ import annotations

from primordial.core.providers.model_eval_deps import (
    estimate_model_runtime,
    estimated_timeout_result,
    failed_context_results,
    offload_recommendation,
    runtime_timeout_result_if_needed,
)

from primordial.core.providers.model_eval_adapters import (
    _LMStudioAdapter,
    _OllamaAdapter,
)

from primordial.core.providers.model_eval_types import (
    ModelCandidate,
    ModelEvalResult,
)

class ModelEvalCandidatesMixin:
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
