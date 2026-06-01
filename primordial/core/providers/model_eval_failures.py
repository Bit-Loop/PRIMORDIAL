from __future__ import annotations

import time
from typing import Any

from primordial.core.providers.model_eval_constants import REMOTE_OFFLOAD_TARGETS


def estimated_timeout_result(
    service: Any,
    result_type: type,
    candidate: Any,
    estimate: dict[str, object],
) -> Any:
    estimated_seconds = service._finite_float(estimate.get("estimated_seconds"))
    max_runtime = service._optional_positive_int(estimate.get("max_runtime_seconds"))
    offload = estimate.get("offload_recommendation")
    offload_payload = dict(offload) if isinstance(offload, dict) else offload_recommendation(
        candidate,
        estimated_seconds,
        max_runtime,
    )
    return result_type(
        provider=candidate.provider,
        model=candidate.model,
        case_id="estimated_runtime_timeout",
        category="benchmark_planning",
        role_name="benchmark_planning",
        score=0.0,
        passed=False,
        elapsed_seconds=None,
        reasons=[
            (
                f"estimated runtime {service._format_seconds(estimated_seconds)} exceeds "
                f"max model runtime {service._format_seconds(max_runtime)}"
            ),
            "defer to remote premium model instead of running locally",
        ],
        stage="planning",
        error="skipped_estimated_timeout",
        load_state="skipped_estimated_timeout",
        estimated_runtime_seconds=estimated_seconds,
        max_runtime_seconds=max_runtime,
        benchmark_plan=dict(estimate),
        offload_recommendation=offload_payload,
    )


def runtime_timeout_result_if_needed(
    service: Any,
    result_type: type,
    candidate: Any,
    model_started: float,
    max_runtime_seconds: int,
) -> Any | None:
    elapsed = time.monotonic() - model_started
    if elapsed <= max_runtime_seconds:
        return None
    return result_type(
        provider=candidate.provider,
        model=candidate.model,
        case_id="model_runtime_timeout",
        category="benchmark_runtime",
        role_name="benchmark_runtime",
        score=0.0,
        passed=False,
        elapsed_seconds=elapsed,
        reasons=[
            (
                f"model runtime {service._format_seconds(elapsed)} exceeded "
                f"max model runtime {service._format_seconds(max_runtime_seconds)}"
            ),
            "defer remaining work to remote premium model instead of continuing locally",
        ],
        stage="runtime_timeout",
        error="model_runtime_timeout",
        load_state="runtime_timeout",
        max_runtime_seconds=max_runtime_seconds,
        offload_recommendation=offload_recommendation(candidate, elapsed, max_runtime_seconds),
    )


def failed_context_results(
    service: Any,
    result_type: type,
    candidate: Any,
    context_length: int,
    temperatures: list[float],
    load_state: str,
    load_time: float | None,
    error: str,
) -> list[Any]:
    failed: list[Any] = []
    for temperature in temperatures:
        for case in service.default_cases():
            failed.append(
                result_type(
                    provider=candidate.provider,
                    model=candidate.model,
                    case_id=case.id,
                    category=case.category,
                    role_name=case.role_name or case.category,
                    score=0.0,
                    passed=False,
                    elapsed_seconds=None,
                    reasons=[error],
                    stage="eval",
                    context_length=context_length,
                    temperature=temperature,
                    scenario_group=case.scenario_group or case.category,
                    load_state=load_state,
                    load_time_seconds=load_time,
                    error=error,
                )
            )
    return failed


def offload_recommendation(
    candidate: Any,
    estimated_seconds: float | None,
    max_runtime_seconds: int | None,
) -> dict[str, object]:
    return {
        "recommended": True,
        "targets": list(REMOTE_OFFLOAD_TARGETS),
        "reason": "local runtime estimate exceeds benchmark cutoff",
        "model": candidate.recommendation_id,
        "estimated_seconds": estimated_seconds,
        "max_runtime_seconds": max_runtime_seconds,
    }
