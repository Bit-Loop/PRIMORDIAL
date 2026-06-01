from __future__ import annotations

from primordial.core.orchestration.workflow_deps import (
    EventRecord,
    EventType,
    OrchestrationReport,
    RuntimeSignal,
    Target,
    Task,
    TaskRun,
    TaskRunStatus,
    TaskStatus,
    utc_now,
)

class WorkflowExecutionRunningMixin:
    def _escalate_dispatch_defers(
        self,
        task: Task,
        dispatch,
        defer_count: int,
        report: OrchestrationReport,
    ) -> None:
        task.status = TaskStatus.NEEDS_APPROVAL
        task.metadata["defer_escalation_reason"] = f"deferred {defer_count} times without dispatch: {dispatch.reason}"
        self.store.insert_task(task)
        report.events.append(
            EventRecord(
                type=EventType.TASK_FAILED,
                summary=f"Task escalated to NEEDS_APPROVAL after {defer_count} defers: {task.title}",
                target_id=task.target_id,
                task_id=task.id,
                metadata={"defer_count": defer_count, "reason": dispatch.reason},
            )
        )

    def _start_dispatched_execution(self, task: Task, run: TaskRun, dispatch) -> None:
        run.status = TaskRunStatus.RUNNING
        run.metadata.update(self._dispatch_metadata(dispatch))
        if dispatch.worker_contract:
            task.metadata["worker_contract"] = dispatch.worker_contract
        self.store.insert_task_run(run)
        self.store.insert_event(
            EventRecord(
                type=EventType.TASK_STARTED,
                summary=task.title,
                target_id=task.target_id,
                task_id=task.id,
                metadata={"runner_id": dispatch.runner_id, "lane": dispatch.lane},
            )
        )
        self._emit_task_started(task, run, dispatch)

    def _emit_task_started(self, task: Task, run: TaskRun, dispatch) -> None:
        if self.event_bus is None:
            return
        self.event_bus.emit(
            RuntimeSignal.TASK_STARTED,
            {
                "task_id": task.id,
                "target_id": task.target_id,
                "run_id": run.id,
                "runner_id": dispatch.runner_id,
            },
        )

    def _execute_dispatched_task(
        self,
        task: Task,
        run: TaskRun,
        dispatch,
        context,
        report: OrchestrationReport,
    ) -> None:
        try:
            result = self.worker_broker.execute(dispatch, task, context)
            if result is None:
                self._defer_vanished_worker_assignment(task, run, dispatch)
                return
            self._persist_execution_result(task, run, result, report)
        except Exception as exc:  # noqa: BLE001 - finalize brokered runs even when execution crashes
            self._persist_execution_exception(task, run, exc, report)

    def _defer_vanished_worker_assignment(self, task: Task, run: TaskRun, dispatch) -> None:
        run.status = TaskRunStatus.CANCELLED
        run.error = "worker assignment vanished before execution"
        run.finished_at = utc_now()
        self.store.insert_task_run(run)
        self.resume_tracker.defer_task(
            task,
            "worker assignment vanished before execution",
            delay_seconds=self.autonomy.defer_retry_seconds,
            metadata={"runner_id": dispatch.runner_id, "lane": dispatch.lane},
        )

    def _resource_reserve_block(self, task: Task) -> dict[str, object] | None:
        if self.resource_status_loader is None or self.resource_reserve_loader is None:
            return None
        metrics = self.resource_status_loader()
        reserves = self.resource_reserve_loader()
        cpu = metrics.get("cpu", {}) if isinstance(metrics, dict) else {}
        gpu = metrics.get("gpu", {}) if isinstance(metrics, dict) else {}
        min_cpu = self._metric_float(reserves.get("min_free_cpu_ram_mb"), 0.0) if isinstance(reserves, dict) else 0.0
        min_gpu = self._metric_float(reserves.get("min_free_gpu_ram_mb"), 0.0) if isinstance(reserves, dict) else 0.0
        observed_cpu = self._metric_float(cpu.get("memory_available_mb"), None) if isinstance(cpu, dict) else None
        observed_gpu = self._metric_float(gpu.get("memory_free_mb"), None) if isinstance(gpu, dict) else None
        blockers: list[str] = []
        if min_cpu > 0 and observed_cpu is not None and observed_cpu < min_cpu:
            blockers.append(f"CPU RAM available {observed_cpu:.0f} MB is below reserve {min_cpu:.0f} MB")
        if (
            min_gpu > 0
            and isinstance(gpu, dict)
            and bool(gpu.get("available"))
            and observed_gpu is not None
            and observed_gpu < min_gpu
        ):
            blockers.append(f"GPU VRAM free {observed_gpu:.0f} MB is below reserve {min_gpu:.0f} MB")
        if not blockers:
            return None
        reason = "resource reserve guard: " + "; ".join(blockers)
        return {
            "reason": reason,
            "metadata": {
                "resource_reserve_guard": True,
                "task_kind": task.kind.value,
                "provider_route": task.provider_route.value if task.provider_route else None,
                "min_free_cpu_ram_mb": min_cpu,
                "min_free_gpu_ram_mb": min_gpu,
                "observed_cpu_memory_available_mb": observed_cpu,
                "observed_gpu_memory_free_mb": observed_gpu,
            },
        }

    def _metric_float(self, raw: object, default: float | None) -> float | None:
        try:
            return float(raw) if raw is not None else default
        except (TypeError, ValueError):
            return default

    def _execution_target_is_invalid(self, task: Task, target: Target | None, report: OrchestrationReport) -> bool:
        if task.target_id is None:
            return False
        reason = ""
        if target is None:
            reason = "target record is missing"
        elif not target.handle.strip():
            reason = "target handle is empty"
        elif not target.in_scope:
            reason = "target is out of scope"
        if not reason:
            return False
        task.status = TaskStatus.BLOCKED
        task.updated_at = utc_now()
        task.metadata["invalid_target"] = True
        task.metadata["invalid_target_reason"] = reason
        self.store.guarded_update_task(task, from_statuses=[TaskStatus.RUNNING])
        event = EventRecord(
            type=EventType.TASK_BLOCKED,
            summary=f"Task blocked before execution: {reason}",
            target_id=task.target_id,
            task_id=task.id,
            metadata={"invalid_target": True, "reason": reason},
        )
        self.store.insert_event(event)
        report.events.append(event)
        return True
