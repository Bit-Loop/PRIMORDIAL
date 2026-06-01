from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Iterable

from primordial.core.providers.lmstudio import LMStudioClient, LMStudioLoadResult, LMStudioModelInfo
from primordial.core.providers.lmstudio_tuning_measurements import (
    _cpu_available_mb,
    _cpu_reserve_abort,
    _initial_measure_row,
    _load_tuning_model,
    _metrics_snapshot,
    _record_successful_measurement,
    _run_tuning_generation,
    _unload_loaded_models,
    _unload_measured_model,
    _vram_free_mb,
    _generation_failed_measurement,
)
from primordial.core.providers.lmstudio_tuning_profiles import (
    _benchmark_head_payload,
    _candidate_configs,
    _config_from_payload,
    _float,
    _initial_tuning_payload,
    _performance_role_findings,
    _profile_for_model,
    _select_models,
)
from primordial.core.providers.lmstudio_tuning_types import (
    HostMetricsSampler,
    LMStudioTuningConfig,
    MEMORY_ERROR_RE as LMSTUDIO_MEMORY_ERROR_RE,
    _json_safe,
)


class LMStudioPerformanceTuner:
    MEMORY_ERROR_RE = LMSTUDIO_MEMORY_ERROR_RE
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
        payload = _initial_tuning_payload(
            context_length=context_length,
            max_tokens=max_tokens,
            temperature=temperature,
            cpu_reserve_mb=cpu_reserve_mb,
            vram_soft_reserve_mb=vram_soft_reserve_mb,
            benchmark_head=_benchmark_head_payload(),
        )
        if not listed.ok:
            payload["status"] = "error"
            payload["error"] = listed.error or "LM Studio model listing failed"
            return payload

        candidates = _select_models(listed.models, selected_names)
        selected_keys = {item.id for item in candidates} | {f"lmstudio:{item.id}" for item in candidates}
        missing = [name for name in selected_names if name not in selected_keys]
        if missing:
            payload["warnings"].append("requested models not found: " + ", ".join(missing))
        if not candidates:
            payload["status"] = "error"
            payload["error"] = "no LM Studio LLM models were available for tuning"
            return payload

        for model in candidates:
            before = _metrics_snapshot(self.host_metrics_sampler)
            cpu_available = _cpu_available_mb(before)
            if cpu_available is not None and cpu_available < cpu_reserve_mb:
                payload["status"] = "aborted"
                payload["error"] = (
                    f"CPU RAM available {cpu_available:.0f} MB is below reserve {cpu_reserve_mb:.0f} MB"
                )
                break
            vram_free = _vram_free_mb(before)
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
        payload["role_findings"] = _performance_role_findings(payload.get("models", {}))
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
            "benchmark_head": tuning_payload.get("benchmark_head", _benchmark_head_payload()),
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
        for config in _candidate_configs(model):
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
                return rows, _profile_for_model(model, rows), aborted_error
            if row.get("memory_failure"):
                memory_failures += 1
                if memory_failures >= 2:
                    break
            elif row.get("status") == "ok":
                memory_failures = 0

        ok_rows = [row for row in rows if row.get("status") == "ok" and _float(row.get("tokens_per_second"))]
        for row in sorted(ok_rows, key=lambda item: _float(item.get("tokens_per_second")) or 0.0, reverse=True)[:2]:
            config = _config_from_payload(row.get("config"))
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
                return rows, _profile_for_model(model, rows), aborted_error
        return rows, _profile_for_model(model, rows), None

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
        row = _initial_measure_row(
            model,
            config,
            context_length=context_length,
            max_tokens=max_tokens,
            temperature=temperature,
            repeat=repeat,
        )
        before = _metrics_snapshot(self.host_metrics_sampler)
        row["host_metrics_before"] = before
        reserve_abort = _cpu_reserve_abort(row, before, cpu_reserve_mb)
        if reserve_abort is not None:
            return reserve_abort

        _unload_loaded_models(self.client, timeout_seconds=timeout_seconds)
        load: LMStudioLoadResult | None = None
        try:
            load, load_failure = _load_tuning_model(
                self,
                row,
                model,
                config,
                context_length=context_length,
                timeout_seconds=timeout_seconds,
            )
            if load_failure is not None:
                return load_failure

            after_load = _metrics_snapshot(self.host_metrics_sampler)
            row["host_metrics_after_load"] = after_load
            reserve_abort = _cpu_reserve_abort(row, after_load, cpu_reserve_mb)
            if reserve_abort is not None:
                return reserve_abort

            response = _run_tuning_generation(
                self,
                model,
                context_length=context_length,
                max_tokens=max_tokens,
                temperature=temperature,
                timeout_seconds=timeout_seconds,
            )
            _record_successful_measurement(row, response)
            after = _metrics_snapshot(self.host_metrics_sampler)
            row["host_metrics_after"] = after
            reserve_abort = _cpu_reserve_abort(row, after, cpu_reserve_mb)
            if reserve_abort is not None:
                return reserve_abort
            return _json_safe(row), None  # type: ignore[return-value]
        except Exception as exc:  # noqa: BLE001 - failed configs are benchmark data
            return _generation_failed_measurement(row, exc)
        finally:
            _unload_measured_model(self, model, load)
