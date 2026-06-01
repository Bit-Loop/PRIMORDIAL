from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
import math
from pathlib import Path
import re
from typing import Callable


HostMetricsSampler = Callable[[], dict[str, object]]
DEFAULT_BENCHMARK_HEAD_MAX_MODEL_RUNTIME_SECONDS = 30 * 60
BENCHMARK_HEAD_OFFLOAD_TARGETS: tuple[str, ...] = ("claude", "gpt")
MEMORY_ERROR_RE = re.compile(r"(out of memory|oom|vram|cuda|memory|ram|allocat)", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class LMStudioTuningConfig:
    eval_batch_size: int = 512
    flash_attention: bool = True
    offload_kv_cache_to_gpu: bool = True
    num_experts: int | None = None

    def as_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "eval_batch_size": self.eval_batch_size,
            "flash_attention": self.flash_attention,
            "offload_kv_cache_to_gpu": self.offload_kv_cache_to_gpu,
        }
        if self.num_experts is not None:
            payload["num_experts"] = self.num_experts
        return payload

    def key(self) -> str:
        return json.dumps(self.as_payload(), sort_keys=True)


def _json_safe(value: object) -> object:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    return str(value)


def _positive_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value > 0:
        return value
    if isinstance(value, float) and value > 0:
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        parsed = int(value.strip())
        return parsed if parsed > 0 else None
    return None


def _float(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None
