from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import re
from typing import Callable, Iterable

from primordial.core.providers.lmstudio import LMStudioClient, LMStudioModelInfo


HostMetricsSampler = Callable[[], dict[str, object]]
DEFAULT_BENCHMARK_HEAD_MAX_MODEL_RUNTIME_SECONDS = 30 * 60
BENCHMARK_HEAD_OFFLOAD_TARGETS: tuple[str, ...] = ("claude", "gpt")


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


class LMStudioPerformanceTuner:
    MEMORY_ERROR_RE = re.compile(r"(out of memory|oom|vram|cuda|memory|ram|allocat)", re.IGNORECASE)
    SYSTEM_PROMPT = "You are a local benchmark model. Return concise JSON only."
    PROMPT = (
        "Return JSON with keys summary, checks, safety_notes. Summarize a synthetic recon-only target with "
        "IIS 10.0, LDAP, Kerberos, no credentials, no shell, and public PoC execution blocked."
    )

    def __init__(
        self,
        client: LMStudioClient,
        *,
        host_metrics_sampler: HostMetricsSampler | None = None,
    ) -> None:
        self.client = client
        self.host_metrics_sampler = host_metrics_sampler

    def tune(
        self,
        *,
        models: Iterable[str] | None = None,
        context_length: int = 1024,
        max_tokens: int = 128,
        temperature: float = 0.0,
        cpu_reserve_mb: int = 4096,
        vram_soft_reserve_mb: int = 128,
        timeout_seconds: int = 120,
    ) -> dict[str, object]:
        selected_names = [str(item).strip() for item in (models or []) if str(item).strip()]
        listed = self.client.list_models()
        created_at = datetime.now(timezone.utc).isoformat()
        payload: dict[str, object] = {
            "created_at": created_at,
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
            "benchmark_head": self._benchmark_head_payload(),
        }
        if not listed.ok:
            payload["status"] = "error"
            payload["error"] = listed.error or "LM Studio model listing failed"
            return payload

        candidates = self._select_models(listed.models, selected_names)
        selected_keys = {item.id for item in candidates} | {f"lmstudio:{item.id}" for item in candidates}
        missing = [name for name in selected_names if name not in selected_keys]
        if missing:
            payload["warnings"].append("requested models not found: " + ", ".join(missing))
        if not candidates:
            payload["status"] = "error"
            payload["error"] = "no LM Studio LLM models were available for tuning"
            return payload

        for model in candidates:
            before = self._metrics_snapshot()
            cpu_available = self._cpu_available_mb(before)
            if cpu_available is not None and cpu_available < cpu_reserve_mb:
                payload["status"] = "aborted"
                payload["error"] = (
                    f"CPU RAM available {cpu_available:.0f} MB is below reserve {cpu_reserve_mb:.0f} MB"
                )
                break
            vram_free = self._vram_free_mb(before)
            if vram_free is not None and vram_free < vram_soft_reserve_mb:
                payload["warnings"].append(
                    f"{model.id}: GPU VRAM free {vram_free:.0f} MB is below soft reserve "
                    f"{vram_soft_reserve_mb:.0f} MB"
                )

            model_rows, model_profile, aborted_error = self._tune_model(
                model,
                context_length=int(context_length),
                max_tokens=int(max_tokens),
                temperature=float(temperature),
                cpu_reserve_mb=int(cpu_reserve_mb),
                timeout_seconds=int(timeout_seconds),
            )
            payload["rows"].extend(model_rows)
            if model_profile:
                payload["models"][model.id] = model_profile
                payload["models"][f"lmstudio:{model.id}"] = model_profile
            if aborted_error:
                payload["status"] = "aborted"
                payload["error"] = aborted_error
                break

        if not payload["models"] and payload.get("status") == "ok":
            payload["status"] = "error"
            payload["error"] = "no successful LM Studio tuning rows were recorded"
        payload["role_findings"] = self._performance_role_findings(payload.get("models", {}))
        return _json_safe(payload)  # type: ignore[return-value]

    def write_artifacts(
        self,
        tuning_payload: dict[str, object],
        *,
        output_dir: Path,
        profile_path: Path,
        json_path: Path | None = None,
    ) -> dict[str, str]:
        output_dir.mkdir(parents=True, exist_ok=True)
        profile_path.parent.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        details_path = json_path or output_dir / f"lmstudio_tuning_{stamp}.json"
        details_path.parent.mkdir(parents=True, exist_ok=True)
        profile = {
            "created_at": tuning_payload.get("created_at"),
            "provider": "lmstudio",
            "settings": tuning_payload.get("settings", {}),
            "models": tuning_payload.get("models", {}),
            "role_findings": tuning_payload.get("role_findings", {}),
            "benchmark_head": tuning_payload.get("benchmark_head", self._benchmark_head_payload()),
        }
        with details_path.open("w", encoding="utf-8") as handle:
            json.dump(_json_safe(tuning_payload), handle, indent=2, sort_keys=True)
        with profile_path.open("w", encoding="utf-8") as handle:
            json.dump(_json_safe(profile), handle, indent=2, sort_keys=True)
        return {"json_path": str(details_path), "profile_path": str(profile_path)}

    def _tune_model(
        self,
        model: LMStudioModelInfo,
        *,
        context_length: int,
        max_tokens: int,
        temperature: float,
        cpu_reserve_mb: int,
        timeout_seconds: int,
    ) -> tuple[list[dict[str, object]], dict[str, object] | None, str | None]:
        rows: list[dict[str, object]] = []
        memory_failures = 0
        for config in self._candidate_configs(model):
            row, aborted_error = self._measure_config(
                model,
                config,
                context_length=context_length,
                max_tokens=max_tokens,
                temperature=temperature,
                cpu_reserve_mb=cpu_reserve_mb,
                timeout_seconds=timeout_seconds,
                repeat=False,
            )
            rows.append(row)
            if aborted_error:
                return rows, self._profile_for_model(model, rows), aborted_error
            if row.get("memory_failure"):
                memory_failures += 1
                if memory_failures >= 2:
                    break
            elif row.get("status") == "ok":
                memory_failures = 0

        ok_rows = [row for row in rows if row.get("status") == "ok" and self._float(row.get("tokens_per_second"))]
        for row in sorted(ok_rows, key=lambda item: self._float(item.get("tokens_per_second")) or 0.0, reverse=True)[:2]:
            config = self._config_from_payload(row.get("config"))
            if config is None:
                continue
            repeat_row, aborted_error = self._measure_config(
                model,
                config,
                context_length=context_length,
                max_tokens=max_tokens,
                temperature=temperature,
                cpu_reserve_mb=cpu_reserve_mb,
                timeout_seconds=timeout_seconds,
                repeat=True,
            )
            rows.append(repeat_row)
            if aborted_error:
                return rows, self._profile_for_model(model, rows), aborted_error
        return rows, self._profile_for_model(model, rows), None

    def _measure_config(
        self,
        model: LMStudioModelInfo,
        config: LMStudioTuningConfig,
        *,
        context_length: int,
        max_tokens: int,
        temperature: float,
        cpu_reserve_mb: int,
        timeout_seconds: int,
        repeat: bool,
    ) -> tuple[dict[str, object], str | None]:
        row: dict[str, object] = {
            "provider": "lmstudio",
            "model": model.id,
            "context_length": context_length,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "repeat": repeat,
            "config": config.as_payload(),
            "status": "started",
        }
        before = self._metrics_snapshot()
        row["host_metrics_before"] = before
        cpu_available = self._cpu_available_mb(before)
        if cpu_available is not None and cpu_available < cpu_reserve_mb:
            row["status"] = "aborted_cpu_reserve"
            error = f"CPU RAM available {cpu_available:.0f} MB is below reserve {cpu_reserve_mb:.0f} MB"
            row["error"] = error
            return _json_safe(row), error  # type: ignore[return-value]

        self._unload_loaded_models(timeout_seconds=timeout_seconds)
        load = None
        try:
            load = self.client.load_model(
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
            if not load.ok:
                row["status"] = "load_failed"
                row["error"] = load.error or "LM Studio load failed"
                row["memory_failure"] = self._is_memory_failure(row["error"])
                return _json_safe(row), None  # type: ignore[return-value]

            after_load = self._metrics_snapshot()
            row["host_metrics_after_load"] = after_load
            cpu_after_load = self._cpu_available_mb(after_load)
            if cpu_after_load is not None and cpu_after_load < cpu_reserve_mb:
                row["status"] = "aborted_cpu_reserve"
                error = f"CPU RAM available {cpu_after_load:.0f} MB is below reserve {cpu_reserve_mb:.0f} MB"
                row["error"] = error
                return _json_safe(row), error  # type: ignore[return-value]

            self.client.chat(
                model=model.id,
                system=self.SYSTEM_PROMPT,
                prompt=self.PROMPT,
                temperature=temperature,
                num_ctx=context_length,
                max_tokens=max(16, min(max_tokens, 64)),
                timeout_seconds=timeout_seconds,
            )
            response = self.client.chat(
                model=model.id,
                system=self.SYSTEM_PROMPT,
                prompt=self.PROMPT,
                temperature=temperature,
                num_ctx=context_length,
                max_tokens=max_tokens,
                timeout_seconds=timeout_seconds,
            )
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
            after = self._metrics_snapshot()
            row["host_metrics_after"] = after
            cpu_after = self._cpu_available_mb(after)
            if cpu_after is not None and cpu_after < cpu_reserve_mb:
                row["status"] = "aborted_cpu_reserve"
                error = f"CPU RAM available {cpu_after:.0f} MB is below reserve {cpu_reserve_mb:.0f} MB"
                row["error"] = error
                return _json_safe(row), error  # type: ignore[return-value]
            return _json_safe(row), None  # type: ignore[return-value]
        except Exception as exc:  # noqa: BLE001 - failed configs are benchmark data
            row["status"] = "generation_failed"
            row["error"] = str(exc)
            row["memory_failure"] = self._is_memory_failure(str(exc))
            return _json_safe(row), None  # type: ignore[return-value]
        finally:
            if load is not None and getattr(load, "ok", False):
                try:
                    self.client.unload_model(model=model.id, instance_id=getattr(load, "instance_id", None))
                except Exception:
                    pass

    def _profile_for_model(self, model: LMStudioModelInfo, rows: list[dict[str, object]]) -> dict[str, object] | None:
        ok_rows = [row for row in rows if row.get("status") == "ok" and self._float(row.get("tokens_per_second"))]
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
        best_key = max(grouped, key=lambda key: self._average_tps(grouped[key]))
        best_rows = grouped[best_key]
        best_config = json.loads(best_key)
        best_row = max(best_rows, key=lambda row: self._float(row.get("tokens_per_second")) or 0.0)
        return {
            "model": model.id,
            "best_config": best_config,
            "measured_context_length": best_row.get("context_length"),
            "tokens_per_second": round(self._average_tps(best_rows), 4),
            "best_observed_tokens_per_second": best_row.get("tokens_per_second"),
            "ttft_seconds": best_row.get("ttft_seconds"),
            "load_time_seconds": best_row.get("load_time_seconds"),
            "quantization": model.quantization,
            "params": model.params,
            "architecture": model.architecture,
            "successful_rows": len(best_rows),
            "tested_rows": len(rows),
        }

    def _candidate_configs(self, model: LMStudioModelInfo) -> list[LMStudioTuningConfig]:
        expert_options = [None, 4, 8] if self._looks_like_moe(model) else [None]
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

    def _select_models(self, models: list[LMStudioModelInfo], selected_names: list[str]) -> list[LMStudioModelInfo]:
        if not selected_names:
            return list(models)
        by_id = {model.id: model for model in models}
        selected: list[LMStudioModelInfo] = []
        for name in selected_names:
            model = by_id.get(name) or by_id.get(name.removeprefix("lmstudio:"))
            if model and model not in selected:
                selected.append(model)
        return selected

    def _benchmark_head_payload(self) -> dict[str, object]:
        return {
            "max_model_runtime_seconds": DEFAULT_BENCHMARK_HEAD_MAX_MODEL_RUNTIME_SECONDS,
            "estimate_source": "ai_tuning_tokens_per_second",
            "skip_stage": "planning",
            "skip_error": "skipped_estimated_timeout",
            "offload_targets": list(BENCHMARK_HEAD_OFFLOAD_TARGETS),
            "policy": "skip local model scopes estimated over the cutoff and record remote offload recommendation",
        }

    def _performance_role_findings(self, models: object) -> dict[str, object]:
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
            return self._float(profile.get("tokens_per_second")) or 0.0

        def model_name(profile: dict[str, object]) -> str:
            return str(profile.get("model") or "")

        sorted_by_speed = sorted(profiles, key=speed, reverse=True)
        compact_candidates = [
            profile
            for profile in sorted_by_speed
            if self._model_size_billions(profile.get("params")) is not None
            and (self._model_size_billions(profile.get("params")) or 99.0) <= 9.5
        ] or sorted_by_speed
        deep_candidates = sorted(
            profiles,
            key=lambda profile: (self._depth_score(profile), speed(profile)),
            reverse=True,
        )
        code_candidates = sorted(
            profiles,
            key=lambda profile: (self._code_score(profile), speed(profile)),
            reverse=True,
        )
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
            roles[role] = {
                "recommended_model": recommended,
                "candidates": [
                    {
                        "model": model_name(profile),
                        "tokens_per_second": round(speed(profile), 4),
                        "params": profile.get("params"),
                        "architecture": profile.get("architecture"),
                        "rationale": self._performance_rationale(role, profile),
                    }
                    for profile in top
                ],
                "source": "performance_profile",
            }
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

    def _unload_loaded_models(self, *, timeout_seconds: int) -> None:
        unload = getattr(self.client, "unload_loaded_models", None)
        if not callable(unload):
            return
        try:
            unload(timeout_seconds=timeout_seconds)
        except Exception:
            pass

    def _metrics_snapshot(self) -> dict[str, object]:
        if self.host_metrics_sampler is None:
            return {}
        try:
            return dict(self.host_metrics_sampler())
        except Exception as exc:  # noqa: BLE001 - metrics should not kill a tuning row
            return {"ok": False, "error": str(exc)}

    def _cpu_available_mb(self, metrics: dict[str, object]) -> float | None:
        cpu = metrics.get("cpu")
        if not isinstance(cpu, dict):
            return None
        direct = self._float(cpu.get("memory_available_mb"))
        if direct is not None:
            return direct
        memory = cpu.get("memory")
        if isinstance(memory, dict):
            return self._float(memory.get("available_mb"))
        return None

    def _vram_free_mb(self, metrics: dict[str, object]) -> float | None:
        gpu = metrics.get("gpu")
        if not isinstance(gpu, dict) or not bool(gpu.get("available")):
            return None
        return self._float(gpu.get("memory_free_mb"))

    def _looks_like_moe(self, model: LMStudioModelInfo) -> bool:
        text = " ".join(
            str(item or "")
            for item in (model.id, model.architecture, model.params, model.raw.get("architecture"))
        ).lower()
        return bool("moe" in text or "mixtral" in text or "gpt-oss" in text or re.search(r"\ba\d+b\b", text))

    def _is_memory_failure(self, text: object) -> bool:
        return bool(self.MEMORY_ERROR_RE.search(str(text or "")))

    def _performance_rationale(self, role: str, profile: dict[str, object]) -> list[str]:
        name = str(profile.get("model") or "").lower()
        params = str(profile.get("params") or "")
        reasons = [f"{self._float(profile.get('tokens_per_second')) or 0.0:.1f} tok/s at tuning context"]
        if role in {"local_fast", "local_compact"}:
            reasons.append("highest-throughput small-context profile")
        if role == "local_deep" and any(term in name for term in ("reasoning", "gpt-oss", "35b", "27b")):
            reasons.append("metadata indicates deeper reasoning or larger/specialized model")
        if role == "local_code" and any(term in name for term in ("cyber", "code", "gpt-oss", "qwen")):
            reasons.append("metadata indicates security/code utility")
        if params:
            reasons.append(f"params={params}")
        return reasons[:4]

    def _depth_score(self, profile: dict[str, object]) -> float:
        name = str(profile.get("model") or "").lower()
        params = self._model_size_billions(profile.get("params")) or 0.0
        speed = self._float(profile.get("tokens_per_second")) or 0.0
        score = min(params / 35.0, 1.0) + min(speed / 100.0, 1.0) * 0.35
        if "reasoning" in name:
            score += 0.3
        if "gpt-oss" in name or "cyber" in name:
            score += 0.15
        if "a3b" in name or "moe" in str(profile.get("architecture") or "").lower():
            score += 0.15
        return score

    def _code_score(self, profile: dict[str, object]) -> float:
        name = str(profile.get("model") or "").lower()
        speed = self._float(profile.get("tokens_per_second")) or 0.0
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

    def _model_size_billions(self, value: object) -> float | None:
        text = str(value or "").lower()
        match = re.search(r"(\d+(?:\.\d+)?)\s*b", text)
        if not match:
            return None
        try:
            return float(match.group(1))
        except ValueError:
            return None

    def _average_tps(self, rows: list[dict[str, object]]) -> float:
        values = [self._float(row.get("tokens_per_second")) for row in rows]
        values = [value for value in values if value is not None]
        return sum(values) / max(1, len(values))

    def _config_from_payload(self, value: object) -> LMStudioTuningConfig | None:
        if not isinstance(value, dict):
            return None
        eval_batch_size = self._positive_int(value.get("eval_batch_size")) or 512
        num_experts = self._positive_int(value.get("num_experts"))
        return LMStudioTuningConfig(
            eval_batch_size=eval_batch_size,
            flash_attention=bool(value.get("flash_attention", True)),
            offload_kv_cache_to_gpu=bool(value.get("offload_kv_cache_to_gpu", True)),
            num_experts=num_experts,
        )

    def _positive_int(self, value: object) -> int | None:
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

    def _float(self, value: object) -> float | None:
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
