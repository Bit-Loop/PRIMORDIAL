from __future__ import annotations

from typing import Any


def identify_model_eval_models(
    service: Any,
    results: list[Any],
    model_metadata: dict[str, dict[str, object]] | None = None,
    role_suggestions: list[Any] | None = None,
) -> dict[str, dict[str, object]]:
    metadata = model_metadata or {}
    grouped = _eval_results_by_model(results)
    suggestions_by_model = _suggestions_by_model(role_suggestions or [])
    return {
        model_id: _model_identity_payload(service, model_id, model_results, metadata, suggestions_by_model)
        for model_id, model_results in sorted(grouped.items())
    }


def _eval_results_by_model(results: list[Any]) -> dict[str, list[Any]]:
    grouped: dict[str, list[Any]] = {}
    for result in results:
        if result.model and result.stage == "eval":
            grouped.setdefault(result.recommendation_id, []).append(result)
    return grouped


def _suggestions_by_model(role_suggestions: list[Any]) -> dict[str, list[Any]]:
    suggestions: dict[str, list[Any]] = {}
    for suggestion in role_suggestions:
        suggestions.setdefault(suggestion.recommendation_id, []).append(suggestion)
    return suggestions


def _model_identity_payload(
    service: Any,
    model_id: str,
    model_results: list[Any],
    metadata: dict[str, dict[str, object]],
    suggestions_by_model: dict[str, list[Any]],
) -> dict[str, object]:
    meta = metadata.get(model_id, {})
    provider = str(meta.get("provider") or model_results[0].provider)
    model_name = str(meta.get("model") or model_results[0].model)
    traits = _model_traits(service, model_id, model_results, meta)
    model_suggestions = sorted(
        suggestions_by_model.get(model_id, []),
        key=lambda item: (item.rank, -item.confidence, item.role),
    )
    return {
        "provider": provider,
        "model": model_name,
        "recommendation_id": model_id,
        "family": traits["family"],
        "architecture": meta.get("architecture") or "",
        "quantization": meta.get("quantization") or "",
        "params": meta.get("params") or "",
        "size_class": traits["size_class"],
        "context_class": traits["context_class"],
        "max_context_length": traits["max_context_length"],
        "runtime_profile": traits["runtime_profile"],
        "quality_profile": traits["quality_profile"],
        "tags": traits["tags"],
        "suggested_roles": _suggested_roles_payload(model_suggestions),
        "warnings": sorted({warning for item in model_suggestions for warning in item.warnings}),
    }


def _model_traits(service: Any, model_id: str, model_results: list[Any], meta: dict[str, object]) -> dict[str, object]:
    family = service._model_family(model_id, meta)
    size_class = service._size_class(meta.get("params"))
    max_context_length = service._optional_positive_int(meta.get("max_context_length")) or service._max_result_context(
        model_results
    )
    context_class = service._context_class(max_context_length)
    runtime_profile = service._runtime_profile(model_results)
    quality_profile = service._quality_profile(model_results)
    tags = service._identity_tags(
        model_id=model_id,
        family=family,
        size_class=size_class,
        context_class=context_class,
        runtime_profile=runtime_profile,
        quality_profile=quality_profile,
    )
    return {
        "family": family,
        "size_class": size_class,
        "max_context_length": max_context_length,
        "context_class": context_class,
        "runtime_profile": runtime_profile,
        "quality_profile": quality_profile,
        "tags": tags,
    }


def _suggested_roles_payload(model_suggestions: list[Any]) -> list[dict[str, object]]:
    return [
        {
            "role": item.role,
            "rank": item.rank,
            "confidence": round(item.confidence, 4),
            "status": item.status,
        }
        for item in model_suggestions
        if item.status in {"recommended", "candidate"}
    ]
