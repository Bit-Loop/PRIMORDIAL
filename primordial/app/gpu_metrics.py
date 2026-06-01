from __future__ import annotations

import shutil
import subprocess
from typing import Callable


NVIDIA_SMI_QUERY_ARGS = [
    "--query-gpu=utilization.gpu,utilization.memory,memory.used,memory.total,temperature.gpu",
    "--format=csv,noheader,nounits",
]


def unavailable_gpu_metrics(error: str) -> dict[str, object]:
    return {
        "available": False,
        "percent": 0.0,
        "memory_percent": 0.0,
        "memory_used_mb": None,
        "memory_free_mb": None,
        "memory_total_mb": None,
        "temperature_c": None,
        "error": error,
    }


def parse_nvidia_smi_gpu_metrics(stdout: str) -> dict[str, object]:
    line = next((item.strip() for item in stdout.splitlines() if item.strip()), "")
    if not line:
        return unavailable_gpu_metrics("nvidia-smi returned no GPU data")
    parts = [segment.strip() for segment in line.split(",")]
    try:
        utilization = float(parts[0])
        memory_utilization = float(parts[1])
        memory_used = float(parts[2])
        memory_total = float(parts[3])
        temperature = float(parts[4])
    except (IndexError, ValueError):
        return unavailable_gpu_metrics(f"unexpected nvidia-smi output: {line}")
    return available_gpu_metrics(
        utilization=utilization,
        memory_utilization=memory_utilization,
        memory_used=memory_used,
        memory_total=memory_total,
        temperature=temperature,
    )


def available_gpu_metrics(
    *,
    utilization: float,
    memory_utilization: float,
    memory_used: float,
    memory_total: float,
    temperature: float,
) -> dict[str, object]:
    memory_percent = max(0.0, min(100.0, memory_utilization))
    if memory_total > 0:
        memory_percent = max(0.0, min(100.0, (memory_used / memory_total) * 100.0))
    return {
        "available": True,
        "percent": round(max(0.0, min(100.0, utilization)), 1),
        "memory_percent": round(memory_percent, 1),
        "memory_used_mb": round(memory_used, 1),
        "memory_free_mb": round(max(0.0, memory_total - memory_used), 1),
        "memory_total_mb": round(memory_total, 1),
        "temperature_c": round(temperature, 1),
        "error": None,
    }


def read_gpu_metrics(
    *,
    which: Callable[[str], str | None] = shutil.which,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, object]:
    nvidia_smi = which("nvidia-smi")
    if not nvidia_smi:
        return unavailable_gpu_metrics("nvidia-smi not found")
    try:
        result = run(
            [nvidia_smi, *NVIDIA_SMI_QUERY_ARGS],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return unavailable_gpu_metrics(str(exc))
    if result.returncode != 0:
        return unavailable_gpu_metrics(result.stderr.strip() or result.stdout.strip() or "nvidia-smi failed")
    return parse_nvidia_smi_gpu_metrics(result.stdout)
