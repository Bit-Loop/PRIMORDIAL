from __future__ import annotations

from typing import Any


def aggregate_model_eval_results(
    service: Any,
    results: list[Any],
    model_metadata: dict[str, dict[str, object]] | None = None,
    *,
    recommendations: dict[str, str] | None = None,
    role_suggestions: list[Any] | None = None,
    model_identification: dict[str, dict[str, object]] | None = None,
) -> list[dict[str, object]]:
    metadata = model_metadata or {}
    grouped = _eval_results_by_model(results)
    suggestions = role_suggestions if role_suggestions is not None else service.suggest_roles(results, metadata)
    recommendations = recommendations if recommendations is not None else service.recommend(results, role_suggestions=suggestions)
    identification = model_identification or service.identify_models(
        results,
        model_metadata=metadata,
        role_suggestions=suggestions,
    )
    recommended_roles_by_model = _recommended_roles_by_model(recommendations)
    suggestions_by_model = _suggestions_by_model(suggestions)
    return [
        _aggregate_row(
            service,
            model_id=model_id,
            model_results=model_results,
            metadata=metadata.get(model_id, {}),
            model_suggestions=sorted(suggestions_by_model.get(model_id, []), key=lambda item: (item.role, item.rank)),
            model_identity=identification.get(model_id, {}),
            recommended_roles=recommended_roles_by_model.get(model_id, []),
        )
        for model_id, model_results in sorted(grouped.items())
    ]


def _eval_results_by_model(results: list[Any]) -> dict[str, list[Any]]:
    grouped: dict[str, list[Any]] = {}
    for result in results:
        if result.model and result.stage == "eval":
            grouped.setdefault(result.recommendation_id, []).append(result)
    return grouped


def _recommended_roles_by_model(recommendations: dict[str, str]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for role, model_id in recommendations.items():
        grouped.setdefault(model_id, []).append(role)
    return grouped


def _suggestions_by_model(suggestions: list[Any]) -> dict[str, list[Any]]:
    grouped: dict[str, list[Any]] = {}
    for suggestion in suggestions:
        grouped.setdefault(suggestion.recommendation_id, []).append(suggestion)
    return grouped


def _aggregate_row(
    service: Any,
    *,
    model_id: str,
    model_results: list[Any],
    metadata: dict[str, object],
    model_suggestions: list[Any],
    model_identity: dict[str, object],
    recommended_roles: list[str],
) -> dict[str, object]:
    metrics = _model_metric_inputs(service, model_results)
    return {
        "provider": model_results[0].provider,
        "model": model_results[0].model,
        "recommendation_id": model_id,
        "identified_tags": ",".join(str(item) for item in model_identity.get("tags", []) if str(item).strip()),
        "identified_profile": model_identity,
        "role_recommendation": ",".join(sorted(recommended_roles)),
        "role_fit_summary": service._role_fit_summary(
            recommended_roles=recommended_roles,
            model_suggestions=model_suggestions,
        ),
        "suggested_roles": _suggested_role_payloads(model_suggestions),
        "role_confidence": _role_confidence_payload(model_suggestions),
        "aggregate_score": round(metrics["avg_score"] + (0.15 * metrics["pass_rate"]), 4),
        "role_scores": service._role_scores(model_results),
        "pass_rate": round(metrics["pass_rate"], 4),
        **_reason_rate_payload(service, model_results),
        **_performance_payload(service, model_results, metadata, metrics),
        "quantization": metadata.get("quantization") or "",
        "params": metadata.get("params") or "",
        "notes": service._aggregate_notes(model_results),
    }


def _model_metric_inputs(service: Any, model_results: list[Any]) -> dict[str, Any]:
    weights = [service._case_weight(item.case_id) for item in model_results]
    weighted_score = sum(item.score * weight for item, weight in zip(model_results, weights, strict=True))
    return {
        "avg_score": weighted_score / max(1.0, sum(weights)),
        "pass_rate": sum(1 for item in model_results if item.passed) / max(1, len(model_results)),
        "elapsed_values": [item.elapsed_seconds for item in model_results if isinstance(item.elapsed_seconds, (int, float))],
        "token_rates": [
            item.tokens_per_second
            for item in model_results
            if isinstance(item.tokens_per_second, (int, float)) and item.tokens_per_second > 0
        ],
        "prompt_tokens": [item.prompt_tokens for item in model_results if isinstance(item.prompt_tokens, int)],
        "completion_tokens": [item.completion_tokens for item in model_results if isinstance(item.completion_tokens, int)],
        "contexts": [item.context_length for item in model_results if isinstance(item.context_length, int)],
    }


def _suggested_role_payloads(model_suggestions: list[Any]) -> list[dict[str, object]]:
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


def _role_confidence_payload(model_suggestions: list[Any]) -> dict[str, float]:
    return {
        item.role: round(item.confidence, 4)
        for item in model_suggestions
        if item.status in {"recommended", "candidate"}
    }


def _reason_rate_payload(service: Any, model_results: list[Any]) -> dict[str, object]:
    return {
        "hallucination_rate": round(service._reason_rate(model_results, "hallucinated unsupported facts"), 4),
        "context_hallucination_rates": service._reason_rate_by_context(model_results, "hallucinated unsupported facts"),
        "temperature_hallucination_rates": service._reason_rate_by_temperature(
            model_results,
            "hallucinated unsupported facts",
        ),
        "over_refusal_rate": round(service._reason_rate(model_results, "over-refusal"), 4),
        "correct_refusal_rate": round(service._correct_refusal_rate(model_results), 4),
        "safety_warning_rate": round(service._reason_rate(model_results, "guardrails included"), 4),
    }


def _performance_payload(
    service: Any,
    model_results: list[Any],
    metadata: dict[str, object],
    metrics: dict[str, Any],
) -> dict[str, object]:
    contexts = metrics["contexts"]
    return {
        "avg_tokens_sec": round(service._average(metrics["token_rates"]), 4) if metrics["token_rates"] else "",
        "avg_latency_sec": round(service._average(metrics["elapsed_values"]), 4) if metrics["elapsed_values"] else "",
        "avg_cpu_percent": service._average_host_metric(model_results, ("cpu", "percent")),
        "avg_gpu_percent": service._average_host_metric(model_results, ("gpu", "percent")),
        "avg_gpu_memory_percent": service._average_host_metric(model_results, ("gpu", "memory_percent")),
        "best_context_length": service._best_context(model_results),
        "max_context_length": metadata.get("max_context_length") or (max(contexts) if contexts else ""),
        "prompt_tokens_avg": round(service._average(metrics["prompt_tokens"]), 2) if metrics["prompt_tokens"] else "",
        "completion_tokens_avg": (
            round(service._average(metrics["completion_tokens"]), 2) if metrics["completion_tokens"] else ""
        ),
    }
