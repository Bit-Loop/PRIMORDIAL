from __future__ import annotations

from typing import Any


def build_role_suggestion_payload(
    service: Any,
    *,
    role: str,
    model_id: str,
    model_results: list[Any],
    role_results: list[Any],
    metadata: dict[str, object],
) -> dict[str, object]:
    scores = _role_suggestion_scores(service, role, model_id, model_results, role_results, metadata)
    reasons, warnings = _role_suggestion_messages(
        service,
        role=role,
        model_id=model_id,
        model_results=model_results,
        role_results=role_results,
        metadata=metadata,
        scores=scores,
    )
    recommendable = service._role_results_are_recommendable(
        avg_score=scores["avg_score"],
        pass_rate=scores["pass_rate"],
    )
    if scores["hallucination_rate"] > 0.25 or scores["over_refusal_rate"] > 0.35:
        recommendable = False
    confidence = service._clamp(scores["fit_score"], 0.0, 1.0)
    status = "candidate" if recommendable and confidence >= 0.42 else "rejected"
    provider = str(metadata.get("provider") or (role_results[0].provider if role_results else ""))
    model_name = str(metadata.get("model") or (role_results[0].model if role_results else model_id))
    return {
        "role": role,
        "provider": provider,
        "model": model_name,
        "recommendation_id": model_id,
        "rank": 0,
        "confidence": round(confidence, 4),
        "fit_score": round(scores["fit_score"], 4),
        "status": status,
        "reasons": reasons or ["benchmark score supports role fit"],
        "warnings": warnings,
        "metrics": _role_suggestion_metrics(scores, role_results),
        "metadata_factors": _role_suggestion_metadata_factors(scores, metadata),
    }


def _role_suggestion_scores(
    service: Any,
    role: str,
    model_id: str,
    model_results: list[Any],
    role_results: list[Any],
    metadata: dict[str, object],
) -> dict[str, Any]:
    avg_score = sum(item.score for item in role_results) / max(1, len(role_results))
    pass_rate = sum(1 for item in role_results if item.passed) / max(1, len(role_results))
    hallucination_rate = service._reason_rate(role_results, "hallucinated unsupported facts")
    over_refusal_rate = service._reason_rate(role_results, "over-refusal")
    avg_latency = service._average(
        [item.elapsed_seconds for item in role_results if isinstance(item.elapsed_seconds, (int, float))]
    )
    avg_tokens = service._average(
        [item.tokens_per_second for item in role_results if isinstance(item.tokens_per_second, (int, float))]
    )
    context_cap = service._optional_positive_int(metadata.get("max_context_length")) or service._max_result_context(
        model_results
    )
    context_score = min(float(context_cap or 0) / 32768.0, 1.0) if context_cap else 0.0
    speed_score = service._speed_score(avg_latency=avg_latency, avg_tokens=avg_tokens)
    metadata_score = service._metadata_role_score(role, model_id, metadata)
    fit_score = (
        (avg_score * 0.52)
        + (pass_rate * 0.26)
        + (speed_score * service._role_speed_weight(role))
        + (context_score * service._role_context_weight(role))
        + metadata_score
        - (hallucination_rate * 0.22)
        - (over_refusal_rate * 0.16)
    )
    return {
        "avg_score": avg_score,
        "pass_rate": pass_rate,
        "hallucination_rate": hallucination_rate,
        "over_refusal_rate": over_refusal_rate,
        "avg_latency": avg_latency,
        "avg_tokens": avg_tokens,
        "best_context": service._best_context(role_results),
        "family": service._model_family(model_id, metadata),
        "context_cap": context_cap,
        "context_score": context_score,
        "speed_score": speed_score,
        "metadata_score": metadata_score,
        "fit_score": fit_score,
    }


def _role_suggestion_messages(
    service: Any,
    *,
    role: str,
    model_id: str,
    model_results: list[Any],
    role_results: list[Any],
    metadata: dict[str, object],
    scores: dict[str, Any],
) -> tuple[list[str], list[str]]:
    reasons: list[str] = []
    warnings: list[str] = []
    _append_rate_messages(reasons, warnings, scores)
    if scores["speed_score"] >= 0.75 and role in {"local_fast", "local_compact"}:
        reasons.append("fast runtime fit")
    if scores["metadata_score"] > 0:
        reasons.append("metadata matches role")
    if scores["context_score"] >= 0.5 and role in {"local_deep", "local_compact"}:
        reasons.append("context capacity supports role")
    if scores["avg_latency"] and role == "local_fast" and scores["avg_latency"] > 12:
        warnings.append("latency is high for hot-path use")
    if role == "local_code" and not _has_code_identity(service, model_id, model_results, metadata, scores):
        warnings.append("code fit is score-driven rather than metadata-driven")
    return reasons, warnings


def _append_rate_messages(reasons: list[str], warnings: list[str], scores: dict[str, Any]) -> None:
    if scores["pass_rate"] >= 0.8:
        reasons.append("high pass rate for role scenarios")
    elif scores["pass_rate"] < 0.5:
        warnings.append("low pass rate for role scenarios")
    if scores["hallucination_rate"]:
        warnings.append(f"hallucination_rate={scores['hallucination_rate']:.2f}")
    if scores["over_refusal_rate"]:
        warnings.append(f"over_refusal_rate={scores['over_refusal_rate']:.2f}")


def _has_code_identity(
    service: Any,
    model_id: str,
    model_results: list[Any],
    metadata: dict[str, object],
    scores: dict[str, Any],
) -> bool:
    tags = service._identity_tags(
        model_id=model_id,
        family=scores["family"],
        size_class=service._size_class(metadata.get("params")),
        context_class=service._context_class(scores["context_cap"]),
        runtime_profile=service._runtime_profile(model_results),
        quality_profile=service._quality_profile(model_results),
    )
    return "code" in tags


def _role_suggestion_metrics(scores: dict[str, Any], role_results: list[Any]) -> dict[str, object]:
    return {
        "avg_score": round(scores["avg_score"], 4),
        "pass_rate": round(scores["pass_rate"], 4),
        "hallucination_rate": round(scores["hallucination_rate"], 4),
        "over_refusal_rate": round(scores["over_refusal_rate"], 4),
        "avg_latency_sec": round(scores["avg_latency"], 4) if scores["avg_latency"] else "",
        "avg_tokens_sec": round(scores["avg_tokens"], 4) if scores["avg_tokens"] else "",
        "best_context_length": scores["best_context"],
        "evaluated_cases": len(role_results),
    }


def _role_suggestion_metadata_factors(scores: dict[str, Any], metadata: dict[str, object]) -> dict[str, object]:
    return {
        "family": scores["family"],
        "architecture": metadata.get("architecture") or "",
        "quantization": metadata.get("quantization") or "",
        "params": metadata.get("params") or "",
        "max_context_length": scores["context_cap"] or "",
        "metadata_score": round(scores["metadata_score"], 4),
        "speed_score": round(scores["speed_score"], 4),
        "context_score": round(scores["context_score"], 4),
    }
