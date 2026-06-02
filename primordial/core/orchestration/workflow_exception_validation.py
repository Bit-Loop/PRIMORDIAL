from __future__ import annotations

from primordial.core.orchestration.workflow_deps import (
    AgentTrace,
    CheckpointKind,
    CheckpointRecord,
    EventRecord,
    EventType,
    json,
    OrchestrationReport,
    PolicyVerdict,
    PrimitiveManifest,
    primitives_for_hint,
    RuntimeSignal,
    subprocess,
    Task,
    TaskKind,
    TaskRun,
    TaskRunStatus,
    TaskStatus,
    traceback,
    utc_now,
    ValidationStage,
)
from primordial.core.sensitive_text import redact_sensitive_text

class WorkflowExceptionValidationMixin:
    @staticmethod
    def _is_transient_exception(exc: Exception) -> bool:
        # OSError covers socket/network/IO errors; TimeoutError is a subclass of OSError.
        # urllib errors are also OSError subclasses on Python 3.3+.
        # These failures are infrastructure-level — the task logic was never exercised,
        # so burning a retry budget on them is incorrect.
        return isinstance(exc, (OSError, TimeoutError))

    @staticmethod
    def _is_timeout_exception(exc: Exception) -> bool:
        return isinstance(exc, (TimeoutError, subprocess.TimeoutExpired))

    @staticmethod
    def _result_timed_out(result) -> bool:
        text = " ".join(str(item or "") for item in (getattr(result, "error", None), getattr(result, "summary", None))).lower()
        return "timed out" in text or "timeout" in text

    def _persist_execution_exception(
        self,
        task: Task,
        run: TaskRun,
        exc: Exception,
        report: OrchestrationReport,
    ) -> None:
        now = utc_now()
        exception_type = type(exc).__name__
        error_text = self._redact_exception_text(str(exc))
        traceback_text = self._redact_exception_text(
            "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        )
        timed_out, transient = self._execution_exception_flags(exc)
        if timed_out:
            task.attempts += 1
            task.status = TaskStatus.PENDING if task.attempts < task.max_attempts else TaskStatus.FAILED
        elif transient:
            # Network/IO glitch: reset to PENDING without consuming retry budget.
            task.status = TaskStatus.PENDING
        else:
            task.attempts += 1
            task.status = TaskStatus.PENDING if task.attempts < task.max_attempts else TaskStatus.FAILED
        task.updated_at = now
        task.metadata["execution_exception"] = error_text
        task.metadata["exception_type"] = exception_type
        task.metadata["traceback"] = traceback_text
        task.metadata["last_exception_transient"] = transient
        if timed_out:
            task.metadata["last_run_timed_out"] = True
        run.status = TaskRunStatus.TIMED_OUT if timed_out else TaskRunStatus.FAILED
        run.error = error_text
        run.trace_summary = f"execution crashed: {error_text}"
        run.finished_at = now
        run.heartbeat_at = now
        run.metadata["execution_exception"] = True
        run.metadata["exception_type"] = exception_type
        run.metadata["traceback"] = traceback_text
        if timed_out:
            run.metadata["timed_out"] = True
        self.store.insert_trace(
            AgentTrace(
                task_id=task.id,
                role=task.role,
                status="failed",
                summary=f"Execution crashed before result persistence: {error_text}",
                metadata={
                    "execution_exception": True,
                    "error": error_text,
                    "exception_type": exception_type,
                    "traceback": traceback_text,
                    "model": task.provider_model,
                },
            )
        )
        self.store.guarded_update_task_run(run, from_statuses=[TaskRunStatus.RUNNING])
        self.store.guarded_update_task(task, from_statuses=[TaskStatus.RUNNING])
        self._write_checkpoint(
            task,
            run,
            summary="execution exception checkpoint",
            payload={
                "task": task.as_payload(),
                "run": run.as_payload(),
                "error": error_text,
                "exception_type": exception_type,
                "traceback": traceback_text,
            },
            phase="exception",
        )
        event = self._execution_exception_event(task, exc, exception_type, traceback_text)
        self.store.insert_event(event)
        report.events.append(event)
        report.completed_runs.append(run)

    def _execution_exception_flags(self, exc: Exception) -> tuple[bool, bool]:
        timed_out = self._is_timeout_exception(exc)
        transient = False if timed_out else self._is_transient_exception(exc)
        return timed_out, transient

    def _execution_exception_event(
        self,
        task: Task,
        exc: Exception,
        exception_type: str,
        traceback_text: str,
    ) -> EventRecord:
        return EventRecord(
            type=EventType.TASK_FAILED,
            summary=f"Execution crashed: {task.title}",
            target_id=task.target_id,
            task_id=task.id,
            metadata={
                "error": self._redact_exception_text(str(exc)),
                "execution_exception": True,
                "exception_type": exception_type,
                "traceback": traceback_text,
            },
        )

    def _redact_exception_text(self, value: object) -> str:
        return redact_sensitive_text(str(value or "")).strip()

    def _annotate_result_metadata(self, task: Task, metadata: dict[str, object]) -> None:
        if task.metadata.get("active_ip_generation") is not None:
            metadata.setdefault("active_ip_generation", task.metadata["active_ip_generation"])
        if task.metadata.get("active_ip"):
            metadata.setdefault("active_ip", task.metadata["active_ip"])

    def _verifier_signal_already_handled(self, signal) -> bool:
        for task in self.store.list_tasks(target_id=signal.target_id, limit=200):
            if task.kind != TaskKind.VERIFY_AGENT_BEHAVIOR:
                continue
            if task.summary != signal.reason:
                continue
            if task.status in {
                TaskStatus.PENDING,
                TaskStatus.RUNNING,
                TaskStatus.WAITING,
                TaskStatus.NEEDS_APPROVAL,
                TaskStatus.SUCCEEDED,
            }:
                return True
        return False

    def _write_checkpoint(self, task: Task, run: TaskRun, summary: str, payload: dict[str, object], *, phase: str = "checkpoint") -> None:
        task_dir = self.checkpoints_dir / (task.id or "task")
        task_dir.mkdir(parents=True, exist_ok=True)
        path = task_dir / f"{run.id}-{phase}.json"
        path.write_text(json.dumps(payload, indent=2, sort_keys=True))
        checkpoint = CheckpointRecord(
            task_id=task.id,
            run_id=run.id,
            kind=CheckpointKind.TASK,
            path=str(path),
            summary=summary,
        )
        self.store.insert_checkpoint(checkpoint)
        self.store.insert_event(
            EventRecord(
                type=EventType.TASK_CHECKPOINTED,
                summary=summary,
                target_id=task.target_id,
                task_id=task.id,
            )
        )
        if self.event_bus is not None:
            self.event_bus.emit(
                RuntimeSignal.TASK_CHECKPOINTED,
                {"task_id": task.id, "run_id": run.id, "path": str(path)},
            )

    def _evaluate_primitives(self, task: Task, primitives: list[PrimitiveManifest]):
        target = self.store.get_target(task.target_id)
        for primitive in primitives:
            decision = self.policy_engine.evaluate_primitive(task, target, primitive)
            if decision.verdict != PolicyVerdict.ALLOW:
                return decision
        return None

    def _memory_service(self) -> MemoryServiceProtocol:
        return self.memory_service_loader()

    def _primitive_resolver(self) -> PrimitiveResolverProtocol:
        return self.primitive_resolver_loader()

    def _stored_primitives_for_task(self, task: Task) -> list[PrimitiveManifest]:
        selected: dict[str, PrimitiveManifest] = {}
        manifests = self.store.list_primitives()
        hinted = primitives_for_hint(manifests, task.metadata.get("primitive_hint"))
        if hinted:
            return hinted
        for capability in task.required_capabilities:
            for manifest in manifests:
                if capability in manifest.capability_tags:
                    selected.setdefault(manifest.name, manifest)
        return list(selected.values())

    def _apply_validation_annotations(self, task: Task, issues) -> None:
        if not issues:
            return
        warnings = [issue for issue in issues if not issue.blocks_progress]
        errors = [issue for issue in issues if issue.blocks_progress]
        if warnings:
            task.metadata["validation_warnings"] = [self._validation_payload(issue) for issue in warnings]
        if errors:
            task.metadata["validation_errors"] = [self._validation_payload(issue) for issue in errors]

    def _record_validation_failure(
        self,
        task: Task,
        issues,
        report: OrchestrationReport,
        *,
        stage: ValidationStage,
        track_created: bool = False,
    ) -> None:
        task.status = TaskStatus.BLOCKED
        self.store.insert_task(task)
        if track_created:
            report.created_tasks.append(task)
        event = EventRecord(
            type=EventType.TASK_BLOCKED,
            summary=issues[0].message,
            target_id=task.target_id,
            task_id=task.id,
            metadata={
                "stage": stage.value,
                "validation_issues": [self._validation_payload(issue) for issue in issues],
            },
        )
        self.store.insert_event(event)
        report.events.append(event)

    def _validation_payload(self, issue) -> dict[str, object]:
        return {
            "code": issue.code,
            "message": issue.message,
            "severity": issue.severity.value,
            "metadata": dict(issue.metadata),
        }
