from __future__ import annotations

from primordial.app.runtime_deps import (
    AgentRole,
    EventRecord,
    EventType,
    json_ready,
    MethodologyName,
    MethodologyPhase,
    re,
    RiskTier,
    Task,
    TaskKind,
    TaskStatus,
    time,
    utc_now,
)

class RuntimeExecutionControlMixin:
    def execution_mode_payload(self) -> dict[str, object]:
        mode = str(self.store.get_setting(self.EXECUTION_MODE_SETTING, "tick")).strip().lower()
        if mode not in self.EXECUTION_MODES:
            mode = "tick"
        interval = self.store.get_setting(
            self.EXECUTION_MODE_INTERVAL_SETTING,
            self.DEFAULT_EXECUTION_INTERVAL_SECONDS,
        )
        try:
            interval_seconds = max(2, int(interval))
        except (TypeError, ValueError):
            interval_seconds = self.DEFAULT_EXECUTION_INTERVAL_SECONDS
        return {
            "mode": mode,
            "continuous": mode == "continuous",
            "interval_seconds": interval_seconds,
            "available_modes": ["tick", "continuous"],
        }

    def runtime_tuning_payload(self) -> dict[str, object]:
        raw = self.store.get_setting(self.RUNTIME_TUNING_SETTING, {})
        if not isinstance(raw, dict):
            raw = {}
        gpu_timeout = self._bounded_int(
            raw.get("gpu_ai_timeout_seconds"),
            default=self.DEFAULT_WORKER_AI_TIMEOUT_SECONDS_GPU,
            minimum=self.MIN_GPU_AI_TIMEOUT_SECONDS,
        )
        cpu_timeout = self._bounded_int(
            raw.get("cpu_ai_timeout_seconds"),
            default=self.DEFAULT_WORKER_AI_TIMEOUT_SECONDS_CPU,
            minimum=self.MIN_CPU_AI_TIMEOUT_SECONDS,
        )
        stale_timeout = self._bounded_int(
            raw.get("stale_run_timeout_seconds"),
            default=self.DEFAULT_STALE_RUN_TIMEOUT_SECONDS,
            minimum=self.MIN_STALE_RUN_TIMEOUT_SECONDS,
        )
        min_free_cpu_ram = self._bounded_int(
            raw.get("min_free_cpu_ram_mb"),
            default=self.DEFAULT_MIN_FREE_CPU_RAM_MB,
            minimum=self.MIN_FREE_CPU_RAM_MB,
        )
        min_free_gpu_ram = self._bounded_int(
            raw.get("min_free_gpu_ram_mb"),
            default=self.DEFAULT_MIN_FREE_GPU_RAM_MB,
            minimum=self.MIN_FREE_GPU_RAM_MB,
        )
        return {
            "gpu_ai_timeout_seconds": gpu_timeout,
            "cpu_ai_timeout_seconds": cpu_timeout,
            "stale_run_timeout_seconds": stale_timeout,
            "min_free_cpu_ram_mb": min_free_cpu_ram,
            "min_free_gpu_ram_mb": min_free_gpu_ram,
            "defaults": {
                "gpu_ai_timeout_seconds": self.DEFAULT_WORKER_AI_TIMEOUT_SECONDS_GPU,
                "cpu_ai_timeout_seconds": self.DEFAULT_WORKER_AI_TIMEOUT_SECONDS_CPU,
                "stale_run_timeout_seconds": self.DEFAULT_STALE_RUN_TIMEOUT_SECONDS,
                "min_free_cpu_ram_mb": self.DEFAULT_MIN_FREE_CPU_RAM_MB,
                "min_free_gpu_ram_mb": self.DEFAULT_MIN_FREE_GPU_RAM_MB,
            },
            "minimums": {
                "gpu_ai_timeout_seconds": self.MIN_GPU_AI_TIMEOUT_SECONDS,
                "cpu_ai_timeout_seconds": self.MIN_CPU_AI_TIMEOUT_SECONDS,
                "stale_run_timeout_seconds": self.MIN_STALE_RUN_TIMEOUT_SECONDS,
                "min_free_cpu_ram_mb": self.MIN_FREE_CPU_RAM_MB,
                "min_free_gpu_ram_mb": self.MIN_FREE_GPU_RAM_MB,
            },
        }

    def resource_reserve_payload(self) -> dict[str, object]:
        tuning = self.runtime_tuning_payload()
        return {
            "min_free_cpu_ram_mb": int(tuning["min_free_cpu_ram_mb"]),
            "min_free_gpu_ram_mb": int(tuning["min_free_gpu_ram_mb"]),
        }

    def update_runtime_tuning(
        self,
        *,
        gpu_ai_timeout_seconds: int | None = None,
        cpu_ai_timeout_seconds: int | None = None,
        stale_run_timeout_seconds: int | None = None,
        min_free_cpu_ram_mb: int | None = None,
        min_free_gpu_ram_mb: int | None = None,
    ) -> dict[str, object]:
        current = self.runtime_tuning_payload()
        updated = {
            "gpu_ai_timeout_seconds": self._bounded_int(
                gpu_ai_timeout_seconds,
                default=int(current["gpu_ai_timeout_seconds"]),
                minimum=self.MIN_GPU_AI_TIMEOUT_SECONDS,
            ),
            "cpu_ai_timeout_seconds": self._bounded_int(
                cpu_ai_timeout_seconds,
                default=int(current["cpu_ai_timeout_seconds"]),
                minimum=self.MIN_CPU_AI_TIMEOUT_SECONDS,
            ),
            "stale_run_timeout_seconds": self._bounded_int(
                stale_run_timeout_seconds,
                default=int(current["stale_run_timeout_seconds"]),
                minimum=self.MIN_STALE_RUN_TIMEOUT_SECONDS,
            ),
            "min_free_cpu_ram_mb": self._bounded_int(
                min_free_cpu_ram_mb,
                default=int(current["min_free_cpu_ram_mb"]),
                minimum=self.MIN_FREE_CPU_RAM_MB,
            ),
            "min_free_gpu_ram_mb": self._bounded_int(
                min_free_gpu_ram_mb,
                default=int(current["min_free_gpu_ram_mb"]),
                minimum=self.MIN_FREE_GPU_RAM_MB,
            ),
        }
        self.store.set_setting(self.RUNTIME_TUNING_SETTING, updated)
        self._apply_runtime_tuning()
        payload = self.runtime_tuning_payload()
        self.store.insert_event(
            EventRecord(
                type=EventType.BOOTSTRAP,
                summary="Runtime tuning updated",
                metadata=payload,
            )
        )
        return payload

    def system_metrics_payload(self, *, force_refresh: bool = False) -> dict[str, object]:
        with self._metrics_lock:
            now = time.monotonic()
            if (
                not force_refresh
                and self._system_metrics_cache is not None
                and (now - self._system_metrics_cache_at) < self.METRICS_CACHE_TTL_SECONDS
            ):
                return dict(self._system_metrics_cache)
            payload = {
                "updated_at": utc_now().isoformat(),
                "cpu": self._read_cpu_metrics(),
                "gpu": self._read_gpu_metrics(),
                "network": self._read_network_metrics(now),
            }
            self._system_metrics_cache = payload
            self._system_metrics_cache_at = now
            return dict(payload)

    def update_execution_mode(self, mode: str, *, interval_seconds: int | None = None) -> dict[str, object]:
        selected = str(mode).strip().lower()
        if selected not in self.EXECUTION_MODES:
            raise ValueError(f"unsupported execution mode: {mode}")
        self.store.set_setting(self.EXECUTION_MODE_SETTING, selected)
        if interval_seconds is not None:
            self.store.set_setting(self.EXECUTION_MODE_INTERVAL_SETTING, max(2, int(interval_seconds)))
        payload = self.execution_mode_payload()
        self.store.insert_event(
            EventRecord(
                type=EventType.BOOTSTRAP,
                summary=f"Execution mode set to {payload['mode']}",
                metadata=payload,
            )
        )
        return payload

    def create_ui_command_proposal(
        self,
        command: str,
        payload: dict[str, object] | None = None,
    ) -> dict[str, object]:
        command_name = re.sub(r"[^a-z0-9_.:-]+", "-", str(command).strip().lower()).strip("-")
        if not command_name:
            raise ValueError("command is required")
        body = dict(payload or {})
        target_handle = str(body.get("target") or body.get("target_handle") or "").strip()
        target = self.store.get_target_by_handle(target_handle) if target_handle else None
        intent = self.active_operator_intent()
        title = str(body.get("title") or command_name.replace("-", " ").replace("_", " ").title()).strip()
        summary = str(
            body.get("summary")
            or f"Web console requested `{command_name}`. This is a proposal only and will not execute automatically."
        )
        task = Task(
            target_id=target.id if target else None,
            phase=MethodologyPhase.ANALYSIS,
            kind=TaskKind.ANALYZE_EVIDENCE,
            title=title,
            summary=summary,
            role=AgentRole.ORCHESTRATOR,
            methodology=MethodologyName.WEB_APP_CORE,
            metadata={
                "ui_command": command_name,
                "ui_payload": json_ready(body),
                "proposal_only": True,
                "operator_intent_id": intent.id,
            },
            status=TaskStatus.NEEDS_APPROVAL,
            priority=10,
            risk_tier=RiskTier.MODERATE,
            requires_approval=True,
        )
        self.store.insert_task(task)
        self.store.insert_event(
            EventRecord(
                type=EventType.TASK_NEEDS_APPROVAL,
                summary=f"UI command proposal: {title}",
                target_id=task.target_id,
                task_id=task.id,
                metadata={"ui_command": command_name, "operator_intent_id": intent.id},
            )
        )
        return {
            "proposal": task.as_payload(),
            "target": target.as_payload() if target else None,
            "operator_intent": intent.as_payload(),
        }

    def _apply_runtime_tuning(self) -> None:
        tuning = self.runtime_tuning_payload()
        self.WORKER_AI_TIMEOUT_SECONDS_GPU = int(tuning["gpu_ai_timeout_seconds"])
        self.WORKER_AI_TIMEOUT_SECONDS_CPU = int(tuning["cpu_ai_timeout_seconds"])
        self.workflow.stale_run_max_age_seconds = int(tuning["stale_run_timeout_seconds"])

    def _bounded_int(self, raw: object, *, default: int, minimum: int) -> int:
        try:
            value = int(raw) if raw is not None else default
        except (TypeError, ValueError):
            value = default
        return max(minimum, value)
