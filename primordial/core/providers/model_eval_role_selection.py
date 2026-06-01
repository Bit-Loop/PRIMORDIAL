from __future__ import annotations

from typing import Any

from primordial.core.providers.model_eval_constants import ROLE_NAMES


def relative_candidates_for_model_eval_role(
    service: Any,
    role: str,
    aggregate_rows: list[dict[str, object]],
) -> list[dict[str, object]]:
    ranked: list[dict[str, object]] = []
    for row in aggregate_rows:
        candidate = _relative_candidate_payload(service, role, row)
        if candidate:
            ranked.append(candidate)
    ranked.sort(
        key=lambda item: (
            service._finite_float(item.get("role_score")) or 0.0,
            service._finite_float(item.get("aggregate_score")) or 0.0,
            service._finite_float(item.get("avg_tokens_sec")) or 0.0,
        ),
        reverse=True,
    )
    return ranked[:3]


def suggest_model_eval_roles(
    service: Any,
    results: list[Any],
    model_metadata: dict[str, dict[str, object]] | None = None,
) -> list[Any]:
    metadata = model_metadata or {}
    grouped = _eval_results_by_model(results)
    ranked: list[Any] = []
    for role in ROLE_NAMES:
        role_candidates = _role_candidates(service, role, grouped, metadata)
        for index, suggestion in enumerate(role_candidates, start=1):
            suggestion.rank = index
            if index == 1 and suggestion.status == "candidate" and suggestion.confidence >= 0.52:
                suggestion.status = "recommended"
            ranked.append(suggestion)
    return sorted(ranked, key=lambda item: (item.role, item.rank, item.recommendation_id))


def _relative_candidate_payload(service: Any, role: str, row: dict[str, object]) -> dict[str, object]:
    if not isinstance(row, dict):
        return {}
    role_scores = row.get("role_scores", {})
    if not isinstance(role_scores, dict):
        return {}
    score = service._finite_float(role_scores.get(role))
    if score is None:
        return {}
    role_fit = row.get("role_fit_summary") or {}
    return {
        "model": _recommendation_id_from_row(row),
        "role_score": round(score, 4),
        "aggregate_score": row.get("aggregate_score"),
        "avg_tokens_sec": row.get("avg_tokens_sec"),
        "pass_rate": row.get("pass_rate"),
        "cautions": role_fit.get("cautions", []) if isinstance(role_fit, dict) else [],
    }


def _recommendation_id_from_row(row: dict[str, object]) -> str:
    model_id = str(row.get("recommendation_id") or "").strip()
    if model_id:
        return model_id
    provider = str(row.get("provider") or "")
    model = str(row.get("model") or "")
    return model if provider == "ollama" else f"{provider}:{model}"


def _eval_results_by_model(results: list[Any]) -> dict[str, list[Any]]:
    grouped: dict[str, list[Any]] = {}
    for result in results:
        if result.model and result.stage == "eval":
            grouped.setdefault(result.recommendation_id, []).append(result)
    return grouped


def _role_candidates(
    service: Any,
    role: str,
    grouped: dict[str, list[Any]],
    metadata: dict[str, dict[str, object]],
) -> list[Any]:
    candidates = [
        service._role_suggestion(role, model_id, model_results, role_results, metadata.get(model_id, {}))
        for model_id, model_results in grouped.items()
        for role_results in [_results_for_role(service, role, model_results)]
        if role_results
    ]
    candidates.sort(
        key=lambda item: (
            0 if item.status == "candidate" else 1,
            -item.fit_score,
            -item.confidence,
            item.recommendation_id,
        )
    )
    return candidates


def _results_for_role(service: Any, role: str, model_results: list[Any]) -> list[Any]:
    return [
        item
        for item in model_results
        if (item.role_name or item.category) == role or service._legacy_role_for_category(item.category) == role
    ]
