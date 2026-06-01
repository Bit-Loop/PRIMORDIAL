from __future__ import annotations

from datetime import datetime, timezone
import json
import re

from primordial.core.providers.lmstudio import LMStudioModelInfo
from primordial.core.providers.lmstudio_tuning_types import (
    BENCHMARK_HEAD_OFFLOAD_TARGETS,
    DEFAULT_BENCHMARK_HEAD_MAX_MODEL_RUNTIME_SECONDS,
    LMStudioTuningConfig,
    _float,
    _positive_int,
)


def _initial_tuning_payload(
    *,
    context_length: int,
    max_tokens: int,
    temperature: float,
    cpu_reserve_mb: int,
    vram_soft_reserve_mb: int,
    benchmark_head: dict[str, object],
) -> dict[str, object]:
    return {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "provider": "lmstudio",
        "status": "ok",
        "settings": {
            "context_length": int(context_length),
            "max_tokens": int(max_tokens),
            "temperature": float(temperature),
            "cpu_reserve_mb": int(cpu_reserve_mb),
            "vram_soft_reserve_mb": int(vram_soft_reserve_mb),
            "top_config_remeasure": True,
        },
        "warnings": [],
        "rows": [],
        "models": {},
        "benchmark_head": benchmark_head,
    }


def _profile_for_model(model: LMStudioModelInfo, rows: list[dict[str, object]]) -> dict[str, object] | None:
    ok_rows = [row for row in rows if row.get("status") == "ok" and _float(row.get("tokens_per_second"))]
    if not ok_rows:
        return None
    grouped: dict[str, list[dict[str, object]]] = {}
    for row in ok_rows:
        config = row.get("config")
        if not isinstance(config, dict):
            continue
        grouped.setdefault(json.dumps(config, sort_keys=True), []).append(row)
    if not grouped:
        return None
    best_key = max(grouped, key=lambda key: _average_tps(grouped[key]))
    best_rows = grouped[best_key]
    best_config = json.loads(best_key)
    best_row = max(best_rows, key=lambda row: _float(row.get("tokens_per_second")) or 0.0)
    return {
        "model": model.id,
        "best_config": best_config,
        "measured_context_length": best_row.get("context_length"),
        "tokens_per_second": round(_average_tps(best_rows), 4),
        "best_observed_tokens_per_second": best_row.get("tokens_per_second"),
        "ttft_seconds": best_row.get("ttft_seconds"),
        "load_time_seconds": best_row.get("load_time_seconds"),
        "quantization": model.quantization,
        "params": model.params,
        "architecture": model.architecture,
        "successful_rows": len(best_rows),
        "tested_rows": len(rows),
    }


def _candidate_configs(model: LMStudioModelInfo) -> list[LMStudioTuningConfig]:
    expert_options = [None, 4, 8] if _looks_like_moe(model) else [None]
    configs: list[LMStudioTuningConfig] = []
    for num_experts in expert_options:
        for eval_batch_size in (256, 512, 1024):
            for offload_kv_cache_to_gpu in (True, False):
                configs.append(
                    LMStudioTuningConfig(
                        eval_batch_size=eval_batch_size,
                        flash_attention=True,
                        offload_kv_cache_to_gpu=offload_kv_cache_to_gpu,
                        num_experts=num_experts,
                    )
                )
        configs.append(
            LMStudioTuningConfig(
                eval_batch_size=512,
                flash_attention=False,
                offload_kv_cache_to_gpu=True,
                num_experts=num_experts,
            )
        )
    return configs


def _select_models(models: list[LMStudioModelInfo], selected_names: list[str]) -> list[LMStudioModelInfo]:
    if not selected_names:
        return list(models)
    by_id = {model.id: model for model in models}
    selected: list[LMStudioModelInfo] = []
    for name in selected_names:
        model = by_id.get(name) or by_id.get(name.removeprefix("lmstudio:"))
        if model and model not in selected:
            selected.append(model)
    return selected


def _benchmark_head_payload() -> dict[str, object]:
    return {
        "max_model_runtime_seconds": DEFAULT_BENCHMARK_HEAD_MAX_MODEL_RUNTIME_SECONDS,
        "estimate_source": "ai_tuning_tokens_per_second",
        "skip_stage": "planning",
        "skip_error": "skipped_estimated_timeout",
        "offload_targets": list(BENCHMARK_HEAD_OFFLOAD_TARGETS),
        "policy": "skip local model scopes estimated over the cutoff and record remote offload recommendation",
    }


def _performance_role_findings(models: object) -> dict[str, object]:
    if not isinstance(models, dict):
        return {"source": "lmstudio_tuning_performance", "roles": {}, "models": {}}
    profiles = [
        profile
        for key, profile in models.items()
        if isinstance(key, str) and not key.startswith("lmstudio:") and isinstance(profile, dict)
    ]
    if not profiles:
        return {"source": "lmstudio_tuning_performance", "roles": {}, "models": {}}

    def speed(profile: dict[str, object]) -> float:
        return _float(profile.get("tokens_per_second")) or 0.0

    def model_name(profile: dict[str, object]) -> str:
        return str(profile.get("model") or "")

    sorted_by_speed = sorted(profiles, key=speed, reverse=True)
    compact_candidates = [
        profile
        for profile in sorted_by_speed
        if _model_size_billions(profile.get("params")) is not None
        and (_model_size_billions(profile.get("params")) or 99.0) <= 9.5
    ] or sorted_by_speed
    deep_candidates = sorted(profiles, key=lambda profile: (_depth_score(profile), speed(profile)), reverse=True)
    code_candidates = sorted(profiles, key=lambda profile: (_code_score(profile), speed(profile)), reverse=True)
    return _role_findings_payload(profiles, sorted_by_speed, compact_candidates, deep_candidates, code_candidates)


def _role_findings_payload(
    profiles: list[dict[str, object]],
    sorted_by_speed: list[dict[str, object]],
    compact_candidates: list[dict[str, object]],
    deep_candidates: list[dict[str, object]],
    code_candidates: list[dict[str, object]],
) -> dict[str, object]:
    def speed(profile: dict[str, object]) -> float:
        return _float(profile.get("tokens_per_second")) or 0.0

    def model_name(profile: dict[str, object]) -> str:
        return str(profile.get("model") or "")

    role_candidates = {
        "local_fast": sorted_by_speed,
        "local_compact": compact_candidates,
        "local_deep": deep_candidates,
        "local_code": code_candidates,
    }
    roles: dict[str, object] = {}
    model_roles: dict[str, list[str]] = {model_name(profile): [] for profile in profiles}
    for role, candidates in role_candidates.items():
        top = candidates[:3]
        recommended = model_name(top[0]) if top else ""
        if recommended:
            model_roles.setdefault(recommended, []).append(role)
        roles[role] = _role_payload(role, top, recommended, speed, model_name)
    return {
        "source": "lmstudio_tuning_performance",
        "roles": roles,
        "models": {
            model_name(profile): {
                "best_for": model_roles.get(model_name(profile), []),
                "tokens_per_second": round(speed(profile), 4),
                "params": profile.get("params"),
                "architecture": profile.get("architecture"),
                "best_config": profile.get("best_config", {}),
            }
            for profile in profiles
        },
        "note": "Performance findings rank load/profile fit only; deterministic scenario evaluation remains authoritative for quality.",
    }


def _role_payload(
    role: str,
    top: list[dict[str, object]],
    recommended: str,
    speed: object,
    model_name: object,
) -> dict[str, object]:
    speed_fn = speed if callable(speed) else (lambda _profile: 0.0)
    model_name_fn = model_name if callable(model_name) else (lambda _profile: "")
    return {
        "recommended_model": recommended,
        "candidates": [
            {
                "model": model_name_fn(profile),
                "tokens_per_second": round(speed_fn(profile), 4),
                "params": profile.get("params"),
                "architecture": profile.get("architecture"),
                "rationale": _performance_rationale(role, profile),
            }
            for profile in top
        ],
        "source": "performance_profile",
    }


def _looks_like_moe(model: LMStudioModelInfo) -> bool:
    text = " ".join(
        str(item or "")
        for item in (model.id, model.architecture, model.params, model.raw.get("architecture"))
    ).lower()
    return bool("moe" in text or "mixtral" in text or "gpt-oss" in text or re.search(r"\ba\d+b\b", text))


def _performance_rationale(role: str, profile: dict[str, object]) -> list[str]:
    name = str(profile.get("model") or "").lower()
    params = str(profile.get("params") or "")
    reasons = [f"{_float(profile.get('tokens_per_second')) or 0.0:.1f} tok/s at tuning context"]
    if role in {"local_fast", "local_compact"}:
        reasons.append("highest-throughput small-context profile")
    if role == "local_deep" and any(term in name for term in ("reasoning", "gpt-oss", "35b", "27b")):
        reasons.append("metadata indicates deeper reasoning or larger/specialized model")
    if role == "local_code" and any(term in name for term in ("cyber", "code", "gpt-oss", "qwen")):
        reasons.append("metadata indicates security/code utility")
    if params:
        reasons.append(f"params={params}")
    return reasons[:4]


def _depth_score(profile: dict[str, object]) -> float:
    name = str(profile.get("model") or "").lower()
    params = _model_size_billions(profile.get("params")) or 0.0
    speed = _float(profile.get("tokens_per_second")) or 0.0
    score = min(params / 35.0, 1.0) + min(speed / 100.0, 1.0) * 0.35
    if "reasoning" in name:
        score += 0.3
    if "gpt-oss" in name or "cyber" in name:
        score += 0.15
    if "a3b" in name or "moe" in str(profile.get("architecture") or "").lower():
        score += 0.15
    return score


def _code_score(profile: dict[str, object]) -> float:
    name = str(profile.get("model") or "").lower()
    speed = _float(profile.get("tokens_per_second")) or 0.0
    score = min(speed / 100.0, 1.0) * 0.35
    if "cyber" in name or "gpt-oss" in name:
        score += 0.5
    if "qwen" in name:
        score += 0.25
    if "code" in name or "coder" in name:
        score += 0.35
    if "reasoning" in name:
        score += 0.1
    return score


def _model_size_billions(value: object) -> float | None:
    text = str(value or "").lower()
    match = re.search(r"(\d+(?:\.\d+)?)\s*b", text)
    if not match:
        return None
    try:
        return float(match.group(1))
    except ValueError:
        return None


def _average_tps(rows: list[dict[str, object]]) -> float:
    values = [_float(row.get("tokens_per_second")) for row in rows]
    values = [value for value in values if value is not None]
    return sum(values) / max(1, len(values))


def _config_from_payload(value: object) -> LMStudioTuningConfig | None:
    if not isinstance(value, dict):
        return None
    eval_batch_size = _positive_int(value.get("eval_batch_size")) or 512
    num_experts = _positive_int(value.get("num_experts"))
    return LMStudioTuningConfig(
        eval_batch_size=eval_batch_size,
        flash_attention=bool(value.get("flash_attention", True)),
        offload_kv_cache_to_gpu=bool(value.get("offload_kv_cache_to_gpu", True)),
        num_experts=num_experts,
    )
