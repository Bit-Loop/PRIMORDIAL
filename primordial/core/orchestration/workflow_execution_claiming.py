from __future__ import annotations

from primordial.core.orchestration.workflow_deps import (
    EventRecord,
    EventType,
    OrchestrationReport,
    PolicyVerdict,
    PrimitiveManifest,
    Target,
    Task,
    TaskRun,
    TaskRunStatus,
    TaskStatus,
    timedelta,
    utc_now,
    ValidationContext,
    ValidationStage,
)

class WorkflowExecutionClaimingMixin:
    def _execute_ready_tasks(self, report: OrchestrationReport, max_executions: int) -> None:
        for _ in range(max_executions):
            task = self.store.claim_next_pending_task()
            if not task:
                return
            self._execute_claimed_task(task, report)

    def _execute_claimed_task(self, task: Task, report: OrchestrationReport) -> None:
        target = self.store.get_target(task.target_id)
        if self._execution_target_is_invalid(task, target, report):
            return
        if self._task_policy_blocks_execution(task, target, report):
            return
        if self._defer_for_resource_reserve(task):
            return
        selection, scheduler_decision = self._execution_route_and_schedule(task)
        if self._defer_for_scheduler(task, selection, scheduler_decision):
            return
        context = self._execution_context(task)
        primitives = self._primitive_resolver().resolve_primitives(task)
        if self._execution_validation_blocks(task, target, primitives, report):
            return
        if self._primitive_policy_blocks_execution(task, primitives):
            return
        run = self._create_execution_run(task, selection, scheduler_decision)
        self._persist_claimed_execution(task, run, selection)
        dispatch = self.worker_broker.dispatch(task, selection)
        if not dispatch.accepted:
            self._handle_dispatch_rejection(task, run, dispatch, report)
            return
        self._start_dispatched_execution(task, run, dispatch)
        self._execute_dispatched_task(task, run, dispatch, context, report)

    def _task_policy_blocks_execution(self, task: Task, target: Target | None, report: OrchestrationReport) -> bool:
        task_decision = self.policy_engine.evaluate_task(task, target)
        self.store.insert_policy_decision(task_decision)
        if task_decision.verdict == PolicyVerdict.ALLOW:
            return False
        self.policy_engine.apply_decision_to_task(task, task_decision)
        task.updated_at = utc_now()
        self.store.guarded_update_task(task, from_statuses=[TaskStatus.RUNNING])
        event_type = (
            EventType.TASK_NEEDS_APPROVAL
            if task_decision.verdict == PolicyVerdict.NEEDS_APPROVAL
            else EventType.TASK_BLOCKED
        )
        event = EventRecord(
            type=event_type,
            summary=f"Task gated before execution: {task_decision.reason}",
            target_id=task.target_id,
            task_id=task.id,
            metadata={"reason": task_decision.reason, "pre_dispatch_policy_recheck": True},
        )
        self.store.insert_event(event)
        report.events.append(event)
        return True

    def _defer_for_resource_reserve(self, task: Task) -> bool:
        resource_block = self._resource_reserve_block(task)
        if resource_block is None:
            return False
        self.resume_tracker.defer_task(
            task,
            str(resource_block["reason"]),
            delay_seconds=self.autonomy.defer_retry_seconds,
            metadata=dict(resource_block["metadata"]),
        )
        return True

    def _execution_route_and_schedule(self, task: Task):
        selection = self.provider_router.select_route(task)
        scheduler_decision = self.model_scheduler.evaluate(
            task,
            selection,
            active_runs=self.store.list_running_task_runs(),
        )
        return selection, scheduler_decision

    def _defer_for_scheduler(self, task: Task, selection, scheduler_decision) -> bool:
        if scheduler_decision.granted:
            return False
        self.resume_tracker.defer_task(
            task,
            scheduler_decision.reason,
            delay_seconds=scheduler_decision.defer_seconds,
            metadata={"lane": scheduler_decision.lane, "route": selection.route.value},
        )
        return True

    def _execution_context(self, task: Task):
        if not task.target_id:
            return None
        return self._memory_service().build_context_slice(task.target_id, task.role)

    def _execution_validation_blocks(
        self,
        task: Task,
        target: Target | None,
        primitives: list[PrimitiveManifest],
        report: OrchestrationReport,
    ) -> bool:
        validation_issues = self.validation_registry.validate(
            ValidationStage.EXECUTION_PREFLIGHT,
            ValidationContext(task=task, target=target, store=self.store, primitives=primitives),
        )
        self._apply_validation_annotations(task, validation_issues)
        if not any(issue.blocks_progress for issue in validation_issues):
            return False
        self._record_validation_failure(
            task,
            validation_issues,
            report,
            stage=ValidationStage.EXECUTION_PREFLIGHT,
        )
        return True

    def _primitive_policy_blocks_execution(self, task: Task, primitives: list[PrimitiveManifest]) -> bool:
        primitive_decision = self._evaluate_primitives(task, primitives)
        if primitive_decision is None:
            return False
        self.store.insert_policy_decision(primitive_decision)
        if primitive_decision.verdict == PolicyVerdict.NEEDS_APPROVAL:
            self._mark_task_needs_primitive_approval(task, primitive_decision.reason)
            return True
        if primitive_decision.verdict == PolicyVerdict.DENY:
            self._block_task_for_primitive_policy(task, primitive_decision.reason)
            return True
        return False

    def _mark_task_needs_primitive_approval(self, task: Task, reason: str) -> None:
        task.status = TaskStatus.NEEDS_APPROVAL
        task.requires_approval = True
        self.store.insert_task(task)
        self.store.insert_event(
            EventRecord(
                type=EventType.TASK_NEEDS_APPROVAL,
                summary=reason,
                target_id=task.target_id,
                task_id=task.id,
            )
        )

    def _block_task_for_primitive_policy(self, task: Task, reason: str) -> None:
        task.status = TaskStatus.BLOCKED
        self.store.insert_task(task)
        self.store.insert_event(
            EventRecord(
                type=EventType.TASK_BLOCKED,
                summary=reason,
                target_id=task.target_id,
                task_id=task.id,
            )
        )

    def _create_execution_run(self, task: Task, selection, scheduler_decision) -> TaskRun:
        now = utc_now()
        return TaskRun(
            task_id=task.id,
            status=TaskRunStatus.CLAIMED,
            attempt_number=task.attempts + 1,
            role=task.role,
            provider_route=selection.route,
            model_name=selection.model_name,
            cold_path=selection.cold_path,
            heartbeat_at=now,
            lease_expires_at=now + timedelta(minutes=5),
            trace_summary="task claimed for brokered execution",
            metadata={
                "rationale": selection.rationale,
                "risk_tier": task.risk_tier.value,
                "scheduler_lane": scheduler_decision.lane,
            },
        )

    def _persist_claimed_execution(self, task: Task, run: TaskRun, selection) -> None:
        task.latest_run_id = run.id
        task.provider_route = selection.route
        task.provider_model = selection.model_name
        self.store.insert_task_run(run)
        self.store.insert_task(task)
        self._write_checkpoint(task, run, summary="pre-execution checkpoint", payload={"task": task.as_payload()}, phase="pre")

    def _handle_dispatch_rejection(self, task: Task, run: TaskRun, dispatch, report: OrchestrationReport) -> None:
        run.status = TaskRunStatus.CANCELLED
        run.error = dispatch.reason
        run.finished_at = utc_now()
        run.metadata.update(self._dispatch_metadata(dispatch))
        self.store.insert_task_run(run)
        defer_count = int(task.metadata.get("defer_count", 0)) + 1
        task.metadata["defer_count"] = defer_count
        if defer_count >= self.autonomy.max_defer_count:
            self._escalate_dispatch_defers(task, dispatch, defer_count, report)
            return
        self.resume_tracker.defer_task(
            task,
            dispatch.reason,
            delay_seconds=dispatch.defer_seconds,
            metadata={
                "lane": dispatch.lane,
                "runner_id": dispatch.runner_id,
                "offer_count": dispatch.offer_count,
                "defer_count": defer_count,
            },
        )

    def _dispatch_metadata(self, dispatch) -> dict[str, object]:
        return {
            "worker_lane": dispatch.lane,
            "runner_id": dispatch.runner_id,
            "offer_id": dispatch.offer_id,
            "offer_count": dispatch.offer_count,
            "worker_contract": dispatch.worker_contract,
            "suitability_score": dispatch.suitability_score,
        }
