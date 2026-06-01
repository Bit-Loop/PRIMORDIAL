from __future__ import annotations

from typing import Any

from primordial.core.providers.model_eval_constants import ROLE_NAMES


def recommend_model_eval_roles(
    service: Any,
    results: list[Any],
    *,
    role_suggestions: list[Any] | None = None,
) -> dict[str, str]:
    if role_suggestions is not None:
        return _recommend_from_suggestions(role_suggestions)
    eval_results = [item for item in results if item.model and item.stage == "eval"]
    recommendations = _recommend_from_eval_results(service, eval_results)
    if "local_code" not in recommendations:
        legacy = service._legacy_recommend(eval_results)
        if legacy:
            recommendations["local_code"] = legacy
    return recommendations


def _recommend_from_suggestions(role_suggestions: list[Any]) -> dict[str, str]:
    recommendations: dict[str, str] = {}
    for role in ROLE_NAMES:
        candidates = [
            item
            for item in role_suggestions
            if item.role == role and item.status == "recommended" and item.confidence >= 0.52
        ]
        if candidates:
            winner = sorted(candidates, key=lambda item: (item.rank, -item.confidence, item.recommendation_id))[0]
            recommendations[role] = winner.recommendation_id
    return recommendations


def _recommend_from_eval_results(service: Any, eval_results: list[Any]) -> dict[str, str]:
    recommendations: dict[str, str] = {}
    for role in ROLE_NAMES:
        best_model = _best_model_for_role(service, role, eval_results)
        if best_model:
            recommendations[role] = best_model
    return recommendations


def _best_model_for_role(service: Any, role: str, eval_results: list[Any]) -> str:
    role_results = [item for item in eval_results if (item.role_name or item.category) == role]
    if not role_results:
        role_results = [item for item in eval_results if service._legacy_role_for_category(item.category) == role]
    best_model = ""
    best_score = -1.0
    for model_id, model_results in _results_by_model(role_results).items():
        combined = _combined_recommendation_score(service, model_results)
        if combined is None:
            continue
        if combined > best_score or (combined == best_score and model_id < best_model):
            best_model = model_id
            best_score = combined
    return best_model


def _results_by_model(results: list[Any]) -> dict[str, list[Any]]:
    grouped: dict[str, list[Any]] = {}
    for result in results:
        grouped.setdefault(result.recommendation_id, []).append(result)
    return grouped


def _combined_recommendation_score(service: Any, model_results: list[Any]) -> float | None:
    pass_rate = sum(1 for item in model_results if item.passed) / max(1, len(model_results))
    avg_score = sum(item.score for item in model_results) / max(1, len(model_results))
    if not service._role_results_are_recommendable(avg_score=avg_score, pass_rate=pass_rate):
        return None
    avg_latency = service._average(
        [item.elapsed_seconds for item in model_results if isinstance(item.elapsed_seconds, (int, float))]
    )
    hallucination_rate = service._reason_rate(model_results, "hallucinated unsupported facts")
    over_refusal_rate = service._reason_rate(model_results, "over-refusal")
    speed_penalty = min(avg_latency / 600.0, 0.1) if avg_latency else 0.0
    return avg_score + (0.2 * pass_rate) - speed_penalty - (0.2 * hallucination_rate) - (0.15 * over_refusal_rate)
