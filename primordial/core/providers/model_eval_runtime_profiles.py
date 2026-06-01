from __future__ import annotations

from typing import Any


def build_model_eval_runtime_profile(service: Any, results: list[Any]) -> dict[str, object]:
    latencies = [item.elapsed_seconds for item in results if isinstance(item.elapsed_seconds, (int, float))]
    token_rates = [
        item.tokens_per_second
        for item in results
        if isinstance(item.tokens_per_second, (int, float)) and item.tokens_per_second > 0
    ]
    avg_latency = service._average(latencies)
    avg_tokens = service._average(token_rates)
    avg_cpu = service._average_host_metric(results, ("cpu", "percent"))
    avg_gpu = service._average_host_metric(results, ("gpu", "percent"))
    avg_gpu_memory = service._average_host_metric(results, ("gpu", "memory_percent"))
    avg_cpu_value = service._finite_float(avg_cpu)
    avg_gpu_value = service._finite_float(avg_gpu)
    return {
        "runtime_class": _runtime_class(avg_latency=avg_latency, avg_tokens=avg_tokens),
        "avg_latency_sec": round(avg_latency, 4) if avg_latency else "",
        "avg_tokens_sec": round(avg_tokens, 4) if avg_tokens else "",
        "avg_cpu_percent": avg_cpu,
        "avg_gpu_percent": avg_gpu,
        "avg_gpu_memory_percent": avg_gpu_memory,
        "residency_hint": _residency_hint(avg_cpu_value=avg_cpu_value, avg_gpu_value=avg_gpu_value),
    }


def _runtime_class(*, avg_latency: float, avg_tokens: float) -> str:
    if not avg_latency:
        return "unknown"
    if avg_latency <= 4 or avg_tokens >= 30:
        return "fast"
    if avg_latency <= 15 or avg_tokens >= 12:
        return "balanced"
    return "slow"


def _residency_hint(*, avg_cpu_value: float | None, avg_gpu_value: float | None) -> str:
    if avg_cpu_value is None or avg_gpu_value is None:
        return "unknown"
    if avg_gpu_value >= avg_cpu_value + 10:
        return "gpu_weighted"
    if avg_cpu_value >= avg_gpu_value + 10:
        return "cpu_weighted"
    return "mixed_cpu_gpu"
