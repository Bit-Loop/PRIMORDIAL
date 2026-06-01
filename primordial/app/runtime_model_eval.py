from __future__ import annotations

from primordial.app.runtime_deps import (
    EventRecord,
    EventType,
    json,
    LMStudioClient,
    LMStudioPerformanceTuner,
    model_eval_service,
    normalize_model_eval_processor,
    normalize_model_eval_providers,
    Path,
    record_model_eval_payload,
    utc_now,
)

class RuntimeModelEvalMixin:
    def evaluate_models(
        self,
        *,
        models: list[str] | None = None,
        limit: int | None = None,
        include_outputs: bool = False,
        processor: str = "cpu",
        providers: list[str] | None = None,
        exhaustive: bool = False,
        max_context: int = 32768,
        context_sizes: list[int] | None = None,
        temperatures: list[float] | None = None,
        judge_model: str | None = None,
        csv_path: str | Path | None = None,
        json_out: str | Path | None = None,
        lmstudio_profile_path: str | Path | None = None,
        use_lmstudio_profile: bool = True,
        max_model_runtime_seconds: int = 1800,
    ) -> dict[str, object]:
        selected_processor = normalize_model_eval_processor(processor)
        normalized_providers = normalize_model_eval_providers(providers)
        lmstudio = LMStudioClient() if "lmstudio" in normalized_providers else None
        lmstudio_profile = (
            self._load_lmstudio_profile(lmstudio_profile_path)
            if lmstudio is not None and use_lmstudio_profile
            else {}
        )
        evaluator = model_eval_service(
            self.ollama,
            lmstudio=lmstudio,
            host_metrics_sampler=lambda: self.system_metrics_payload(force_refresh=True),
            lmstudio_profile=lmstudio_profile,
        )
        summary = evaluator.evaluate(
            models=models,
            limit=limit,
            include_outputs=include_outputs,
            num_gpu=self._processor_num_gpu(selected_processor),
            providers=normalized_providers,
            exhaustive=exhaustive,
            max_context=max_context,
            context_sizes=context_sizes,
            temperatures=temperatures,
            judge_model=judge_model,
            max_model_runtime_seconds=max_model_runtime_seconds,
        )
        artifacts = evaluator.write_artifacts(
            summary,
            output_dir=self.config.artifacts_dir / "model_eval",
            csv_path=Path(csv_path) if csv_path else None,
            json_path=Path(json_out) if json_out else None,
        )
        payload = summary.as_payload()
        record_model_eval_payload(
            self.store,
            payload=payload,
            artifacts=artifacts,
            processor=selected_processor,
            providers=normalized_providers,
            max_context=max_context,
            context_sizes=context_sizes,
            exhaustive=exhaustive,
            temperatures=temperatures,
            judge_model=judge_model,
            max_model_runtime_seconds=max_model_runtime_seconds,
            lmstudio_profile_path=lmstudio_profile_path,
            default_lmstudio_profile_path=self._lmstudio_profile_path(),
            lmstudio_profile=lmstudio_profile,
        )
        return payload

    def tune_lmstudio_models(
        self,
        *,
        models: list[str] | None = None,
        context_length: int = 1024,
        max_tokens: int = 128,
        temperature: float = 0.0,
        cpu_reserve_mb: int = 4096,
        vram_soft_reserve_mb: int = 128,
        timeout_seconds: int = 120,
        profile_out: str | Path | None = None,
        json_out: str | Path | None = None,
    ) -> dict[str, object]:
        client = LMStudioClient()
        tuner = LMStudioPerformanceTuner(
            client,
            host_metrics_sampler=lambda: self.system_metrics_payload(force_refresh=True),
        )
        payload = tuner.tune(
            models=models,
            context_length=context_length,
            max_tokens=max_tokens,
            temperature=temperature,
            cpu_reserve_mb=cpu_reserve_mb,
            vram_soft_reserve_mb=vram_soft_reserve_mb,
            timeout_seconds=timeout_seconds,
        )
        stamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
        artifacts = tuner.write_artifacts(
            payload,
            output_dir=self.config.artifacts_dir / "model_eval" / f"lmstudio_tuning_{stamp}",
            profile_path=Path(profile_out) if profile_out else self._lmstudio_profile_path(),
            json_path=Path(json_out) if json_out else None,
        )
        payload["artifacts"] = artifacts
        self.store.insert_event(
            EventRecord(
                type=EventType.BOOTSTRAP,
                summary="LM Studio performance tuning completed",
                metadata={
                    "status": payload.get("status"),
                    "models": sorted(str(key) for key in payload.get("models", {}).keys())
                    if isinstance(payload.get("models"), dict)
                    else [],
                    "artifacts": artifacts,
                    "settings": payload.get("settings", {}),
                },
            )
        )
        return payload

    def _lmstudio_profile_path(self) -> Path:
        return self.config.runtime_dir / "model_eval" / "lmstudio_performance_profile.json"

    def _load_lmstudio_profile(self, profile_path: str | Path | None = None) -> dict[str, object]:
        target = Path(profile_path) if profile_path else self._lmstudio_profile_path()
        try:
            if not target.exists():
                return {}
            with target.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return {}
        return payload if isinstance(payload, dict) else {}
