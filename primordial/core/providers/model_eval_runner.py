from __future__ import annotations

import time
from typing import Any, Iterable

from primordial.core.providers.model_eval_artifacts import json_safe as _json_safe
from primordial.core.providers.model_eval_constants import DEFAULT_MODEL_BENCHMARK_TIMEOUT_SECONDS


def run_model_evaluation(
    service: Any,
    *,
    result_type: type,
    summary_type: type,
    models: list[str] | None = None,
    limit: int | None = None,
    include_outputs: bool = False,
    num_gpu: int | None = 0,
    timeout_seconds: int = 120,
    providers: list[str] | None = None,
    exhaustive: bool = False,
    max_context: int = 32768,
    temperatures: Iterable[float] | None = None,
    context_sizes: Iterable[int] | None = None,
    judge_model: str | None = None,
    max_model_runtime_seconds: int = DEFAULT_MODEL_BENCHMARK_TIMEOUT_SECONDS,
) -> Any:
    provider_names = service._normalize_providers(providers or ["ollama"])
    temperature_values = service._normalize_temperatures(temperatures)
    context_overrides = service._normalize_context_sizes(context_sizes, max_context=max_context)
    max_runtime_seconds = max(1, int(max_model_runtime_seconds or DEFAULT_MODEL_BENCHMARK_TIMEOUT_SECONDS))
    candidates, provider_errors = service._candidate_pool(provider_names)
    selected = service._select_preferred(candidates, models) if models else candidates
    missing_models = service._missing_preferred_models(candidates, models) if models else []
    selected = sorted(selected, key=lambda candidate: (candidate.provider, service._model_priority_key(candidate.model)))
    if limit:
        selected = selected[:limit]

    results = _initial_results(result_type, provider_errors, missing_models)
    runtime_estimates: dict[str, dict[str, object]] = {}
    _evaluate_selected_candidates(
        service,
        result_type=result_type,
        selected=selected,
        provider_names=provider_names,
        results=results,
        runtime_estimates=runtime_estimates,
        temperature_values=temperature_values,
        context_overrides=context_overrides,
        max_context=max_context,
        exhaustive=exhaustive,
        max_runtime_seconds=max_runtime_seconds,
        include_outputs=include_outputs,
        num_gpu=num_gpu,
        timeout_seconds=timeout_seconds,
    )
    return _build_summary(
        service,
        summary_type=summary_type,
        provider_names=provider_names,
        selected=selected,
        results=results,
        judge_model=judge_model,
        exhaustive=exhaustive,
        max_context=max_context,
        context_overrides=context_overrides,
        temperature_values=temperature_values,
        max_runtime_seconds=max_runtime_seconds,
        runtime_estimates=runtime_estimates,
    )


def _initial_results(result_type: type, provider_errors: list[dict[str, str]], missing_models: list[str]) -> list[Any]:
    results: list[Any] = []
    for error in provider_errors:
        results.append(
            result_type(
                provider=error["provider"],
                model="",
                case_id="provider_list",
                category="provider",
                role_name="provider",
                score=0.0,
                passed=False,
                elapsed_seconds=None,
                reasons=[str(error["error"])],
                error=str(error["error"]),
                stage="provider",
            )
        )
    for model in missing_models:
        results.append(_missing_model_result(result_type, model))
    return results


def _missing_model_result(result_type: type, model: str) -> Any:
    return result_type(
        provider="selection",
        model=model,
        case_id="model_selection",
        category="selection",
        role_name="selection",
        score=0.0,
        passed=False,
        elapsed_seconds=None,
        reasons=["requested model was not available from selected providers"],
        error="requested model was not available from selected providers",
        stage="selection",
    )


def _evaluate_selected_candidates(
    service: Any,
    *,
    result_type: type,
    selected: list[Any],
    provider_names: list[str],
    results: list[Any],
    runtime_estimates: dict[str, dict[str, object]],
    temperature_values: list[float],
    context_overrides: list[int],
    max_context: int,
    exhaustive: bool,
    max_runtime_seconds: int,
    include_outputs: bool,
    num_gpu: int | None,
    timeout_seconds: int,
) -> None:
    adapters = service._adapters(provider_names)
    for candidate in selected:
        adapter = adapters.get(candidate.provider)
        if adapter is None:
            continue
        _evaluate_candidate(
            service,
            result_type=result_type,
            adapter=adapter,
            candidate=candidate,
            results=results,
            runtime_estimates=runtime_estimates,
            temperature_values=temperature_values,
            context_overrides=context_overrides,
            max_context=max_context,
            exhaustive=exhaustive,
            max_runtime_seconds=max_runtime_seconds,
            include_outputs=include_outputs,
            num_gpu=num_gpu,
            timeout_seconds=timeout_seconds,
        )


def _evaluate_candidate(
    service: Any,
    *,
    result_type: type,
    adapter: Any,
    candidate: Any,
    results: list[Any],
    runtime_estimates: dict[str, dict[str, object]],
    temperature_values: list[float],
    context_overrides: list[int],
    max_context: int,
    exhaustive: bool,
    max_runtime_seconds: int,
    include_outputs: bool,
    num_gpu: int | None,
    timeout_seconds: int,
) -> None:
    contexts = _candidate_contexts(service, candidate, context_overrides, exhaustive=exhaustive, max_context=max_context)
    runtime_estimate = service._estimate_model_runtime(
        candidate,
        contexts=contexts,
        temperatures=temperature_values,
        case_count=len(service.default_cases()),
        max_runtime_seconds=max_runtime_seconds,
    )
    runtime_estimates[candidate.recommendation_id] = runtime_estimate
    if runtime_estimate.get("action") == "skip_remote_offload":
        results.append(service._estimated_timeout_result(candidate, runtime_estimate))
        return

    model_started = time.monotonic()
    for context_length in contexts:
        timeout_result = service._runtime_timeout_result_if_needed(candidate, model_started, max_runtime_seconds)
        if timeout_result is not None:
            results.append(timeout_result)
            break
        if _evaluate_context(
            service,
            result_type=result_type,
            adapter=adapter,
            candidate=candidate,
            context_length=context_length,
            results=results,
            runtime_estimate=runtime_estimate,
            temperature_values=temperature_values,
            max_runtime_seconds=max_runtime_seconds,
            include_outputs=include_outputs,
            num_gpu=num_gpu,
            timeout_seconds=timeout_seconds,
            model_started=model_started,
        ):
            break
    _append_cleanup_result(result_type, adapter, candidate, results)


def _candidate_contexts(
    service: Any,
    candidate: Any,
    context_overrides: list[int],
    *,
    exhaustive: bool,
    max_context: int,
) -> list[int]:
    contexts = context_overrides or service._contexts_for_model(candidate, exhaustive=exhaustive, max_context=max_context)
    candidate_context_cap = service._optional_positive_int(candidate.max_context_length)
    if context_overrides and candidate_context_cap:
        cap = max(512, candidate_context_cap)
        return sorted({max(512, min(cap, int(context))) for context in contexts})
    return contexts


def _evaluate_context(
    service: Any,
    *,
    result_type: type,
    adapter: Any,
    candidate: Any,
    context_length: int,
    results: list[Any],
    runtime_estimate: dict[str, object],
    temperature_values: list[float],
    max_runtime_seconds: int,
    include_outputs: bool,
    num_gpu: int | None,
    timeout_seconds: int,
    model_started: float,
) -> bool:
    load_state, load_time, load_error = _load_for_context(adapter, candidate, context_length)
    if load_error:
        results.extend(
            service._failed_context_results(
                candidate,
                context_length,
                temperature_values,
                load_state,
                load_time,
                f"model load failed: {load_error}",
            )
        )
        return False

    load_config = service._adapter_load_config(adapter, candidate)
    tuned_profile_applied = service._adapter_profile_applied(adapter, candidate)
    for temperature in temperature_values:
        for case in service.default_cases():
            timeout_result = service._runtime_timeout_result_if_needed(candidate, model_started, max_runtime_seconds)
            if timeout_result is not None:
                results.append(timeout_result)
                return True
            results.append(
                _evaluate_case(
                    service,
                    result_type=result_type,
                    adapter=adapter,
                    candidate=candidate,
                    case=case,
                    temperature=temperature,
                    context_length=context_length,
                    load_state=load_state,
                    load_time=load_time,
                    load_config=load_config,
                    tuned_profile_applied=tuned_profile_applied,
                    runtime_estimate=runtime_estimate,
                    max_runtime_seconds=max_runtime_seconds,
                    include_outputs=include_outputs,
                    num_gpu=num_gpu,
                    timeout_seconds=timeout_seconds,
                )
            )
    return False


def _load_for_context(adapter: Any, candidate: Any, context_length: int) -> tuple[str, float | None, str | None]:
    try:
        return adapter.load_for_context(candidate, context_length)
    except Exception as exc:  # noqa: BLE001 - provider lifecycle failures must not abort the suite
        return "load_failed", None, str(exc)


def _evaluate_case(
    service: Any,
    *,
    result_type: type,
    adapter: Any,
    candidate: Any,
    case: Any,
    temperature: float,
    context_length: int,
    load_state: str,
    load_time: float | None,
    load_config: dict[str, object],
    tuned_profile_applied: bool,
    runtime_estimate: dict[str, object],
    max_runtime_seconds: int,
    include_outputs: bool,
    num_gpu: int | None,
    timeout_seconds: int,
) -> Any:
    host_before = service._host_metrics_snapshot()
    provider_before = service._provider_state_snapshot(adapter, candidate)
    try:
        result = _generated_case_result(
            service,
            adapter=adapter,
            candidate=candidate,
            case=case,
            temperature=temperature,
            context_length=context_length,
            include_outputs=include_outputs,
            num_gpu=num_gpu,
            timeout_seconds=timeout_seconds,
        )
    except Exception as exc:  # noqa: BLE001 - model eval should continue across model failures
        result = _generation_failure_result(result_type, candidate, case, context_length, temperature, load_state, load_time, exc)
    result.temperature = temperature
    result.scenario_group = case.scenario_group or case.category
    result.load_config = dict(load_config)
    result.tuned_profile_applied = tuned_profile_applied
    result.benchmark_plan = dict(runtime_estimate)
    result.estimated_runtime_seconds = service._finite_float(runtime_estimate.get("estimated_seconds"))
    result.max_runtime_seconds = max_runtime_seconds
    result.host_metrics_before = host_before
    result.host_metrics_after = service._host_metrics_snapshot()
    result.provider_state_before = provider_before
    result.provider_state_after = service._provider_state_snapshot(adapter, candidate)
    return result


def _generated_case_result(
    service: Any,
    *,
    adapter: Any,
    candidate: Any,
    case: Any,
    temperature: float,
    context_length: int,
    include_outputs: bool,
    num_gpu: int | None,
    timeout_seconds: int,
) -> Any:
    response = adapter.generate(
        candidate=candidate,
        system=case.system,
        prompt=case.prompt,
        temperature=temperature,
        context_length=context_length,
        num_gpu=num_gpu,
        timeout_seconds=timeout_seconds,
    )
    result = service.score_output(
        model=candidate.model,
        case=case,
        output=response.text,
        elapsed_seconds=response.elapsed_seconds,
        include_output=include_outputs,
        temperature=temperature,
    )
    result.provider = candidate.provider
    result.context_length = context_length
    result.prompt_tokens = response.prompt_tokens
    result.completion_tokens = response.completion_tokens
    result.tokens_per_second = response.tokens_per_second
    result.ttft_seconds = response.ttft_seconds
    result.reasoning_content_excerpt = response.reasoning_content[:600]
    result.finish_reason = response.finish_reason
    if not response.text and response.reasoning_content:
        result.reasons.append("reasoning-only response with no final content")
        result.passed = False
    result.role_name = case.role_name or case.category
    result.stage = "eval"
    return result


def _generation_failure_result(
    result_type: type,
    candidate: Any,
    case: Any,
    context_length: int,
    temperature: float,
    load_state: str,
    load_time: float | None,
    exc: Exception,
) -> Any:
    return result_type(
        provider=candidate.provider,
        model=candidate.model,
        case_id=case.id,
        category=case.category,
        role_name=case.role_name or case.category,
        score=0.0,
        passed=False,
        elapsed_seconds=None,
        reasons=[f"generation failed: {exc}"],
        stage="eval",
        context_length=context_length,
        temperature=temperature,
        scenario_group=case.scenario_group or case.category,
        load_state=load_state,
        load_time_seconds=load_time,
        error=str(exc),
    )


def _append_cleanup_result(result_type: type, adapter: Any, candidate: Any, results: list[Any]) -> None:
    try:
        cleanup_state, cleanup_error = adapter.cleanup(candidate)
    except Exception as exc:  # noqa: BLE001 - provider lifecycle failures must not abort the suite
        cleanup_state, cleanup_error = "cleanup_failed", str(exc)
    if cleanup_error:
        results.append(
            result_type(
                provider=candidate.provider,
                model=candidate.model,
                case_id="provider_cleanup",
                category="provider",
                role_name="provider",
                score=0.0,
                passed=False,
                elapsed_seconds=None,
                reasons=[f"{cleanup_state}: {cleanup_error}"],
                stage="cleanup",
                error=cleanup_error,
            )
        )


def _build_summary(
    service: Any,
    *,
    summary_type: type,
    provider_names: list[str],
    selected: list[Any],
    results: list[Any],
    judge_model: str | None,
    exhaustive: bool,
    max_context: int,
    context_overrides: list[int],
    temperature_values: list[float],
    max_runtime_seconds: int,
    runtime_estimates: dict[str, dict[str, object]],
) -> Any:
    model_metadata = {candidate.recommendation_id: candidate.as_payload() for candidate in selected}
    role_suggestions = service.suggest_roles(results, model_metadata=model_metadata)
    recommendations = service.recommend(results, role_suggestions=role_suggestions)
    model_identification = service.identify_models(
        results,
        model_metadata=model_metadata,
        role_suggestions=role_suggestions,
    )
    aggregate_rows = service.aggregate(
        results,
        model_metadata,
        recommendations=recommendations,
        role_suggestions=role_suggestions,
        model_identification=model_identification,
    )
    role_findings = service.role_findings(
        recommendations=recommendations,
        role_suggestions=role_suggestions,
        aggregate_rows=aggregate_rows,
        model_identification=model_identification,
    )
    return summary_type(
        providers=provider_names,
        models=[candidate.recommendation_id for candidate in selected],
        results=results,
        model_metadata=model_metadata,
        model_identification=model_identification,
        role_suggestions=role_suggestions,
        aggregate_rows=aggregate_rows,
        recommendations=recommendations,
        judge_metadata=service._judge_metadata(judge_model, recommendations, results),
        role_findings=role_findings,
        eval_config={
            "exhaustive": exhaustive,
            "max_context": max_context,
            "context_sizes": context_overrides,
            "temperatures": temperature_values,
            "case_count": len(service.default_cases()),
            "lmstudio_profile_applied": bool(service.lmstudio_profile),
            "max_model_runtime_seconds": max_runtime_seconds,
            "runtime_estimates": _json_safe(runtime_estimates),
        },
    )
