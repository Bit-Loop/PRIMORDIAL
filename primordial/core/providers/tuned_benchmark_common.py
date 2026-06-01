from __future__ import annotations

import json
import subprocess
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any


def parse_csv_ints(value: str) -> list[int]:
    return [int(item.strip()) for item in value.split(",") if item.strip()]


def parse_csv_floats(value: str) -> list[float]:
    return [float(item.strip()) for item in value.split(",") if item.strip()]


def json_safe(value: object) -> object:
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value):
        return json_safe(asdict(value))
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_safe(item) for item in value]
    return str(value)


def shell(args: list[str], timeout: int = 15) -> dict[str, object]:
    try:
        proc = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        return {"returncode": proc.returncode, "stdout": proc.stdout.strip(), "stderr": proc.stderr.strip()}
    except subprocess.TimeoutExpired:
        return {"returncode": 124, "stdout": "", "stderr": "timeout"}


def nvidia_metrics() -> dict[str, object]:
    result = shell(
        [
            "nvidia-smi",
            "--query-gpu=utilization.gpu,utilization.memory,memory.used,memory.free,memory.total,temperature.gpu",
            "--format=csv,noheader,nounits",
        ],
        timeout=10,
    )
    if result["returncode"] != 0 or not result["stdout"]:
        return {"available": False, "error": result.get("stderr") or result.get("stdout") or "nvidia-smi unavailable"}
    parts = [part.strip() for part in str(result["stdout"]).splitlines()[0].split(",")]
    try:
        util, mem_util, used, free, total, temp = [float(part) for part in parts[:6]]
    except Exception:
        return {"available": False, "raw": result["stdout"]}
    return {
        "available": True,
        "percent": util,
        "memory_utilization_percent": mem_util,
        "memory_used_mb": used,
        "memory_free_mb": free,
        "memory_total_mb": total,
        "memory_percent": round((used / total) * 100.0, 4) if total else None,
        "temperature_c": temp,
    }


try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover - optional host telemetry
    psutil = None


def host_metrics() -> dict[str, object]:
    cpu = None
    memory: dict[str, object] = {}
    if psutil:
        vm = psutil.virtual_memory()
        cpu = psutil.cpu_percent(interval=0.02)
        memory = {
            "percent": vm.percent,
            "total_mb": round(vm.total / (1024 * 1024), 2),
            "available_mb": round(vm.available / (1024 * 1024), 2),
        }
    return {"cpu": {"percent": cpu}, "memory": memory, "gpu": nvidia_metrics()}


def is_timeout(message: str) -> bool:
    lowered = message.lower()
    return "timed out" in lowered or "timeout" in lowered


def is_offload_or_load_failure(message: str) -> bool:
    lowered = message.lower()
    return any(
        term in lowered
        for term in (
            "http 500",
            "internal server error",
            "out of memory",
            "cuda",
            "vram",
            "memory",
            "alloc",
            "failed to load",
            "llama",
        )
    )


def fallback_candidates(selected: int | None) -> list[int | None]:
    values: list[int | None] = [selected]
    if selected is None:
        pass
    elif selected >= 999:
        values.extend([64, 48, 32, 24, 16, 8, 0])
    elif selected > 48:
        values.extend([48, 32, 24, 16, 8, 0])
    elif selected > 32:
        values.extend([32, 24, 16, 8, 0])
    elif selected > 24:
        values.extend([24, 16, 8, 0])
    elif selected > 16:
        values.extend([16, 8, 0])
    elif selected > 8:
        values.extend([8, 4, 0])
    elif selected > 4:
        values.extend([4, 2, 0])
    elif selected > 0:
        values.extend([2, 0])
    else:
        values.append(0)
    out: list[int | None] = []
    for value in values:
        if value not in out:
            out.append(value)
    return out


class EventSink:
    def __init__(self, path: Path) -> None:
        self.path = path

    def append(self, event: dict[str, object]) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(json_safe(event), sort_keys=True) + "\n")

    def counts(self) -> dict[str, dict[str, int]]:
        counts: dict[str, dict[str, int]] = {}
        if not self.path.exists():
            return counts
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            provider = str(event.get("provider") or "unknown")
            status = str(event.get("status") or event.get("event") or "unknown")
            counts.setdefault(provider, {}).setdefault(status, 0)
            counts[provider][status] += 1
        return counts
