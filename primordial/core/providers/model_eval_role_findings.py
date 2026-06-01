from __future__ import annotations

from typing import Any

from primordial.core.providers.model_eval_constants import ROLE_NAMES


def build_model_eval_role_findings(
    service: Any,
    *,
    recommendations: dict[str, str],
    role_suggestions: list[Any],
    aggregate_rows: list[dict[str, object]],
    model_identification: dict[str, dict[str, object]],
) -> dict[str, object]:
    suggestions_by_role, suggestions_by_model = _suggestions_by_key(role_suggestions)
    roles = _role_findings_by_role(service, recommendations, suggestions_by_role, aggregate_rows)
    models = _role_findings_by_model(
        service,
        recommendations=recommendations,
        suggestions_by_model=suggestions_by_model,
        aggregate_rows=aggregate_rows,
        model_identification=model_identification,
    )
    return {
        "source": "deterministic_model_eval",
        "roles": roles,
        "models": models,
        "note": (
            "recommended_model is populated only when pass-rate and confidence gates are met; "
            "relative_best_model is the best observed model for that role in this run."
        ),
    }


def _suggestions_by_key(role_suggestions: list[Any]) -> tuple[dict[str, list[Any]], dict[str, list[Any]]]:
    suggestions_by_role: dict[str, list[Any]] = {}
    suggestions_by_model: dict[str, list[Any]] = {}
    for suggestion in role_suggestions:
        if suggestion.status not in {"recommended", "candidate"}:
            continue
        suggestions_by_role.setdefault(suggestion.role, []).append(suggestion)
        suggestions_by_model.setdefault(suggestion.recommendation_id, []).append(suggestion)
    return suggestions_by_role, suggestions_by_model


def _role_findings_by_role(
    service: Any,
    recommendations: dict[str, str],
    suggestions_by_role: dict[str, list[Any]],
    aggregate_rows: list[dict[str, object]],
) -> dict[str, object]:
    roles: dict[str, object] = {}
    for role in ROLE_NAMES:
        items = sorted(
            suggestions_by_role.get(role, []),
            key=lambda item: (0 if item.recommendation_id == recommendations.get(role) else 1, item.rank, -item.confidence),
        )
        roles[role] = {
            "recommended_model": recommendations.get(role, ""),
            "recommendation_status": "recommended" if recommendations.get(role) else "relative_only",
            "relative_best_model": service._relative_best_model_for_role(role, aggregate_rows),
            "relative_candidates": service._relative_candidates_for_role(role, aggregate_rows),
            "candidates": [_candidate_payload(item) for item in items[:3]],
        }
    return roles


def _role_findings_by_model(
    service: Any,
    *,
    recommendations: dict[str, str],
    suggestions_by_model: dict[str, list[Any]],
    aggregate_rows: list[dict[str, object]],
    model_identification: dict[str, dict[str, object]],
) -> dict[str, object]:
    models: dict[str, object] = {}
    relative_roles_by_model = _relative_roles_by_model(service, aggregate_rows)
    for row in aggregate_rows:
        if not isinstance(row, dict):
            continue
        model_id = _row_model_id(row)
        suggestions = sorted(
            suggestions_by_model.get(model_id, []),
            key=lambda item: (item.rank, -item.confidence, item.role),
        )
        identity = model_identification.get(model_id, {})
        models[model_id] = {
            "best_for": [role for role, winner in recommendations.items() if winner == model_id],
            "relative_best_for": relative_roles_by_model.get(model_id, []),
            "candidate_for": [item.role for item in suggestions[:4]],
            "aggregate_score": row.get("aggregate_score"),
            "avg_tokens_sec": row.get("avg_tokens_sec"),
            "avg_latency_sec": row.get("avg_latency_sec"),
            "tags": identity.get("tags", []),
            "notes": row.get("notes", ""),
            "rationale": service._role_finding_rationale(suggestions),
        }
    return models


def _relative_roles_by_model(service: Any, aggregate_rows: list[dict[str, object]]) -> dict[str, list[str]]:
    relative_roles: dict[str, list[str]] = {}
    for role in ROLE_NAMES:
        relative_best = service._relative_best_model_for_role(role, aggregate_rows)
        if relative_best:
            relative_roles.setdefault(relative_best, []).append(role)
    return relative_roles


def _candidate_payload(suggestion: Any) -> dict[str, object]:
    return {
        "model": suggestion.recommendation_id,
        "rank": suggestion.rank,
        "confidence": round(suggestion.confidence, 4),
        "fit_score": round(suggestion.fit_score, 4),
        "status": suggestion.status,
        "reasons": list(suggestion.reasons[:3]),
        "warnings": list(suggestion.warnings[:3]),
    }


def _row_model_id(row: dict[str, object]) -> str:
    model_id = str(row.get("recommendation_id") or "").strip()
    if model_id:
        return model_id
    provider = str(row.get("provider") or "")
    model = str(row.get("model") or "")
    return model if provider == "ollama" else f"{provider}:{model}"
