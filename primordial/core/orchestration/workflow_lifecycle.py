from __future__ import annotations

from primordial.core.orchestration.workflow_deps import (
    AgentRole,
    AgentTrace,
    EventRecord,
    EventType,
    OrchestrationReport,
    PolicyVerdict,
    Target,
    TargetMethodologyState,
    Task,
    TaskKind,
    TaskRunStatus,
    TaskStatus,
    utc_now,
)

class WorkflowLifecycleMixin:
    def preview_target_state(self, target: Target) -> TargetMethodologyState:
        return self._evaluate_target_methodology_state(target)

    def recover_stale_execution_state(self, *, limit: int = 500) -> int:
        recovered = 0
        now = utc_now()
        tasks_by_id = {task.id: task for task in self.store.list_tasks(limit=limit)}
        for run in self.store.list_task_runs(limit=limit):
            if run.status not in {TaskRunStatus.CLAIMED, TaskRunStatus.RUNNING} or run.finished_at is not None:
                continue
            task = tasks_by_id.get(run.task_id)
            reason = self._stale_run_reason(task, run, now)
            if reason is None:
                continue
            next_task_status = None
            if task is not None:
                if task.status == TaskStatus.RUNNING:
                    next_task_status = TaskStatus.PENDING if task.attempts < task.max_attempts else TaskStatus.FAILED
            trace = AgentTrace(
                task_id=run.task_id,
                role=task.role if task is not None else AgentRole.ORCHESTRATOR,
                status="failed",
                summary=f"Recovered stale execution state: {reason}",
                metadata={"recovered_stale_execution": True, "recovery_reason": reason},
            )
            event = EventRecord(
                type=EventType.TASK_FAILED,
                summary=f"Recovered stale execution state for {task.title if task else run.task_id}",
                target_id=task.target_id if task is not None else None,
                task_id=run.task_id,
                metadata={"reason": reason, "recovered_stale_execution": True},
            )
            if self.store.recover_stale_task_run(
                run=run,
                task=task,
                task_status=next_task_status,
                reason=reason,
                trace=trace,
                event=event,
            ):
                recovered += 1
        return recovered

    def tick(self, max_executions: int = 3) -> OrchestrationReport:
        report = OrchestrationReport()
        self.recover_stale_execution_state(limit=500)
        self.store.expire_handoffs()
        self.resume_tracker.resume_due_tasks(limit=200)
        targets = self.store.list_targets()
        active_session = self.store.get_active_session()

        for target in targets:
            self._plan_target(target, active_session.id if active_session else None, report)

        signals = self.verifier.inspect(
            tasks=self.store.list_tasks(limit=500),
            traces=self.store.list_traces(limit=200),
            evidence=self.store.list_evidence(limit=200),
            targets=targets,
            interests=self.store.list_interests(limit=200),
            findings=self.store.list_findings(limit=100),
            events=self.store.list_events(limit=200),
        )
        for signal in signals:
            if self._verifier_signal_already_handled(signal):
                continue
            if self.store.has_active_task(signal.target_id, TaskKind.VERIFY_AGENT_BEHAVIOR):
                continue
            self._register_task(
                self._build_task(
                    target_id=signal.target_id,
                    kind=TaskKind.VERIFY_AGENT_BEHAVIOR,
                    title="Review agent behavior",
                    summary=signal.reason,
                    session_id=active_session.id if active_session else None,
                ),
                self.store.get_target(signal.target_id),
                report,
            )

        self._execute_ready_tasks(report, max_executions=max_executions)
        return report

    def approve_task(self, task_id: str, approved: bool) -> Task | None:
        task = self.store.get_task(task_id)
        if not task or task.status != TaskStatus.NEEDS_APPROVAL:
            return task
        action = "approved" if approved else "denied"
        if task.metadata.get("proposal_only"):
            task.status = TaskStatus.SUCCEEDED if approved else TaskStatus.CANCELLED
            task.requires_approval = False
            task.updated_at = utc_now()
            task.metadata = {
                **task.metadata,
                "proposal_resolved": True,
                "proposal_approved": bool(approved),
                "proposal_resolved_at": task.updated_at.isoformat(),
            }
            event_type = EventType.APPROVAL_GRANTED if approved else EventType.APPROVAL_DENIED
            updated = self.store.update_task_status(
                task.id,
                from_statuses=[TaskStatus.NEEDS_APPROVAL],
                to_status=task.status,
                metadata_patch=task.metadata,
                requires_approval=False,
            )
            if updated is not None:
                task = updated
            self.store.insert_event(
                EventRecord(
                    type=event_type,
                    summary=f"UI command proposal {action}: {task.title}",
                    target_id=task.target_id,
                    task_id=task.id,
                    metadata={"proposal_only": True, "ui_command": task.metadata.get("ui_command")},
                )
            )
            return task
        if approved and task.kind == TaskKind.CREDENTIALED_ACCESS_CHECK:
            target = self.store.get_target(task.target_id) if task.target_id else None
            block_reason = self._credentialed_access_task_block_reason(task, target)
            if block_reason:
                self._invalidate_task(task, block_reason, event_summary=f"Task approval blocked: {task.title}")
                return task
        if approved and task.kind == TaskKind.REVIEW_PREMIUM_ESCALATION:
            if task.metadata.get("remote_premium_policy_approval_required"):
                task.metadata["remote_premium_operator_approved"] = True
                task.metadata["remote_premium_operator_approved_at"] = utc_now().isoformat()
        if approved:
            task.updated_at = utc_now()
            task.metadata = {
                **task.metadata,
                "operator_approved": True,
                "operator_approved_at": task.updated_at.isoformat(),
            }
            task.status = TaskStatus.PENDING
            task.requires_approval = False
            event_type = EventType.APPROVAL_GRANTED
        else:
            task.status = TaskStatus.CANCELLED
            event_type = EventType.APPROVAL_DENIED
        updated = self.store.update_task_status(
            task.id,
            from_statuses=[TaskStatus.NEEDS_APPROVAL],
            to_status=task.status,
            metadata_patch=task.metadata,
            requires_approval=False,
        )
        if updated is not None:
            task = updated
        self.store.insert_event(
            EventRecord(
                type=event_type,
                summary=f"Task {action}: {task.title}",
                target_id=task.target_id,
                task_id=task.id,
            )
        )
        return task

    def approve_all_safe_tasks(self, *, limit: int = 200) -> dict[str, object]:
        approved: list[str] = []
        skipped: list[dict[str, str]] = []
        for task in self.store.list_tasks(statuses=[TaskStatus.NEEDS_APPROVAL], limit=limit):
            if task.metadata.get("proposal_only"):
                skipped.append({"task_id": task.id, "reason": "proposal-only UI command requires explicit approval"})
                continue
            target = self.store.get_target(task.target_id) if task.target_id else None
            decision = self.policy_engine.evaluate_task(task, target)
            self.store.insert_policy_decision(decision)
            if decision.verdict != PolicyVerdict.ALLOW:
                skipped.append({"task_id": task.id, "reason": decision.reason})
                continue
            task.status = TaskStatus.PENDING
            task.requires_approval = False
            task.updated_at = utc_now()
            task.metadata = {
                **task.metadata,
                "batch_safe_approved": True,
                "batch_safe_approved_at": task.updated_at.isoformat(),
                "batch_safe_approval_reason": decision.reason,
            }
            self.store.insert_task(task)
            self.store.insert_event(
                EventRecord(
                    type=EventType.APPROVAL_GRANTED,
                    summary=f"Safe task batch-approved: {task.title}",
                    target_id=task.target_id,
                    task_id=task.id,
                    metadata={"batch_safe_approved": True, "reason": decision.reason},
                )
            )
            approved.append(task.id)
        return {"approved": approved, "skipped": skipped, "approved_count": len(approved), "skipped_count": len(skipped)}
