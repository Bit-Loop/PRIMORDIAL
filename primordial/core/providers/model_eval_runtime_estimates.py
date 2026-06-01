from __future__ import annotations

from typing import Any


def estimate_model_runtime(
    service: Any,
    candidate: Any,
    *,
    contexts: list[int],
    temperatures: list[float],
    case_count: int,
    max_runtime_seconds: int,
) -> dict[str, object]:
    profile = service._lmstudio_profile_entry(candidate) if candidate.provider == "lmstudio" else {}
    tokens_per_second = service._finite_float(profile.get("tokens_per_second")) if profile else None
    load_time_seconds = service._finite_float(profile.get("load_time_seconds")) if profile else None
    if tokens_per_second is None or tokens_per_second <= 0:
        return _unavailable_runtime_estimate(
            candidate,
            contexts=contexts,
            temperatures=temperatures,
            case_count=case_count,
            max_runtime_seconds=max_runtime_seconds,
        )

    context_estimates, total_seconds = _context_runtime_estimates(
        service,
        contexts=contexts,
        tokens_per_second=tokens_per_second,
        load_time_seconds=load_time_seconds,
        temperatures=temperatures,
        case_count=case_count,
    )
    total_seconds = round(total_seconds, 4)
    action = "skip_remote_offload" if total_seconds > max_runtime_seconds else "run"
    return {
        "provider": candidate.provider,
        "model": candidate.model,
        "recommendation_id": candidate.recommendation_id,
        "source": "lmstudio_tuning_profile",
        "action": action,
        "tokens_per_second": round(tokens_per_second, 4),
        "load_time_seconds": load_time_seconds,
        "contexts": list(contexts),
        "temperatures": list(temperatures),
        "case_count": case_count,
        "context_estimates": context_estimates,
        "estimated_seconds": total_seconds,
        "max_runtime_seconds": max_runtime_seconds,
        "offload_recommendation": service._offload_recommendation(candidate, total_seconds, max_runtime_seconds)
        if action == "skip_remote_offload"
        else {},
    }


def _unavailable_runtime_estimate(
    candidate: Any,
    *,
    contexts: list[int],
    temperatures: list[float],
    case_count: int,
    max_runtime_seconds: int,
) -> dict[str, object]:
    return {
        "provider": candidate.provider,
        "model": candidate.model,
        "recommendation_id": candidate.recommendation_id,
        "source": "unavailable",
        "action": "run_unestimated",
        "reason": "no tuning tokens_per_second was available",
        "contexts": list(contexts),
        "temperatures": list(temperatures),
        "case_count": case_count,
        "max_runtime_seconds": max_runtime_seconds,
    }


def _context_runtime_estimates(
    service: Any,
    *,
    contexts: list[int],
    tokens_per_second: float,
    load_time_seconds: float | None,
    temperatures: list[float],
    case_count: int,
) -> tuple[list[dict[str, object]], float]:
    context_estimates: list[dict[str, object]] = []
    total_seconds = 0.0
    for context in contexts:
        output_tokens = service._estimated_output_tokens(context)
        generation_seconds = (
            (output_tokens / tokens_per_second)
            * max(1, case_count)
            * max(1, len(temperatures))
        )
        context_seconds = generation_seconds + (load_time_seconds or 0.0)
        total_seconds += context_seconds
        context_estimates.append(
            {
                "context_length": context,
                "estimated_output_tokens_per_case": output_tokens,
                "estimated_seconds": round(context_seconds, 4),
            }
        )
    return context_estimates, total_seconds
