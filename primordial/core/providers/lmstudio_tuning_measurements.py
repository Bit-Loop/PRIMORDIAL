from __future__ import annotations

from typing import Protocol

from primordial.core.providers.lmstudio import LMStudioClient, LMStudioLoadResult, LMStudioModelInfo, LMStudioResponse
from primordial.core.providers.lmstudio_tuning_types import (
    HostMetricsSampler,
    LMStudioTuningConfig,
    MEMORY_ERROR_RE,
    _float,
    _json_safe,
)


class _TunerLike(Protocol):
    client: LMStudioClient
    SYSTEM_PROMPT: str
    PROMPT: str


def _initial_measure_row(
    model: LMStudioModelInfo,
    config: LMStudioTuningConfig,
    *,
    context_length: int,
    max_tokens: int,
    temperature: float,
    repeat: bool,
) -> dict[str, object]:
    return {
        "provider": "lmstudio",
        "model": model.id,
        "context_length": context_length,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "repeat": repeat,
        "config": config.as_payload(),
        "status": "started",
    }


def _unload_loaded_models(client: LMStudioClient, *, timeout_seconds: int) -> None:
    unload = getattr(client, "unload_loaded_models", None)
    if not callable(unload):
        return
    try:
        unload(timeout_seconds=timeout_seconds)
    except Exception:
        pass


def _metrics_snapshot(host_metrics_sampler: HostMetricsSampler | None) -> dict[str, object]:
    if host_metrics_sampler is None:
        return {}
    try:
        return dict(host_metrics_sampler())
    except Exception as exc:  # noqa: BLE001 - metrics should not kill a tuning row
        return {"ok": False, "error": str(exc)}


def _cpu_available_mb(metrics: dict[str, object]) -> float | None:
    cpu = metrics.get("cpu")
    if not isinstance(cpu, dict):
        return None
    direct = _float(cpu.get("memory_available_mb"))
    if direct is not None:
        return direct
    memory = cpu.get("memory")
    if isinstance(memory, dict):
        return _float(memory.get("available_mb"))
    return None


def _vram_free_mb(metrics: dict[str, object]) -> float | None:
    gpu = metrics.get("gpu")
    if not isinstance(gpu, dict) or not bool(gpu.get("available")):
        return None
    return _float(gpu.get("memory_free_mb"))


def _cpu_reserve_abort(
    row: dict[str, object],
    metrics: dict[str, object],
    cpu_reserve_mb: int,
) -> tuple[dict[str, object], str | None] | None:
    cpu_available = _cpu_available_mb(metrics)
    if cpu_available is None or cpu_available >= cpu_reserve_mb:
        return None
    row["status"] = "aborted_cpu_reserve"
    error = f"CPU RAM available {cpu_available:.0f} MB is below reserve {cpu_reserve_mb:.0f} MB"
    row["error"] = error
    return _json_safe(row), error  # type: ignore[return-value]


def _load_tuning_model(
    tuner: _TunerLike,
    row: dict[str, object],
    model: LMStudioModelInfo,
    config: LMStudioTuningConfig,
    *,
    context_length: int,
    timeout_seconds: int,
) -> tuple[LMStudioLoadResult, tuple[dict[str, object], str | None] | None]:
    load = tuner.client.load_model(
        model=model.id,
        context_length=context_length,
        eval_batch_size=config.eval_batch_size,
        flash_attention=config.flash_attention,
        offload_kv_cache_to_gpu=config.offload_kv_cache_to_gpu,
        num_experts=config.num_experts,
        timeout_seconds=timeout_seconds,
    )
    row["load_time_seconds"] = load.elapsed_seconds
    row["load_config"] = load.load_config or config.as_payload()
    if load.ok:
        return load, None
    row["status"] = "load_failed"
    row["error"] = load.error or "LM Studio load failed"
    row["memory_failure"] = _is_memory_failure(row["error"])
    return load, (_json_safe(row), None)  # type: ignore[return-value]


def _run_tuning_generation(
    tuner: _TunerLike,
    model: LMStudioModelInfo,
    *,
    context_length: int,
    max_tokens: int,
    temperature: float,
    timeout_seconds: int,
) -> LMStudioResponse:
    tuner.client.chat(
        model=model.id,
        system=tuner.SYSTEM_PROMPT,
        prompt=tuner.PROMPT,
        temperature=temperature,
        num_ctx=context_length,
        max_tokens=max(16, min(max_tokens, 64)),
        timeout_seconds=timeout_seconds,
    )
    return tuner.client.chat(
        model=model.id,
        system=tuner.SYSTEM_PROMPT,
        prompt=tuner.PROMPT,
        temperature=temperature,
        num_ctx=context_length,
        max_tokens=max_tokens,
        timeout_seconds=timeout_seconds,
    )


def _record_successful_measurement(row: dict[str, object], response: LMStudioResponse) -> None:
    tokens_per_second = response.tokens_per_second
    if tokens_per_second is None and response.completion_tokens and response.elapsed_seconds:
        tokens_per_second = float(response.completion_tokens) / max(0.001, response.elapsed_seconds)
    row.update(
        {
            "status": "ok",
            "elapsed_seconds": response.elapsed_seconds,
            "prompt_tokens": response.prompt_tokens,
            "completion_tokens": response.completion_tokens,
            "tokens_per_second": tokens_per_second,
            "ttft_seconds": response.ttft_seconds,
            "finish_reason": response.finish_reason,
            "content_chars": len(response.text or ""),
            "reasoning_content_chars": len(response.reasoning_content or ""),
        }
    )


def _generation_failed_measurement(
    row: dict[str, object],
    exc: Exception,
) -> tuple[dict[str, object], str | None]:
    row["status"] = "generation_failed"
    row["error"] = str(exc)
    row["memory_failure"] = _is_memory_failure(str(exc))
    return _json_safe(row), None  # type: ignore[return-value]


def _unload_measured_model(
    tuner: _TunerLike,
    model: LMStudioModelInfo,
    load: LMStudioLoadResult | None,
) -> None:
    if load is None or not getattr(load, "ok", False):
        return
    try:
        tuner.client.unload_model(model=model.id, instance_id=getattr(load, "instance_id", None))
    except Exception:
        pass


def _is_memory_failure(text: object) -> bool:
    return bool(MEMORY_ERROR_RE.search(str(text or "")))
