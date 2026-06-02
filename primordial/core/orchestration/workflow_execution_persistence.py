from __future__ import annotations

from primordial.core.orchestration.workflow_deps import (
    AgentRole,
    AgentTrace,
    EscalationPackage,
    EventRecord,
    EventType,
    ExternalSyncJob,
    ExternalSyncKind,
    Note,
    NotificationChannel,
    NotificationRecord,
    NotificationStatus,
    OrchestrationReport,
    ProviderRoute,
    RuntimeSignal,
    Task,
    TaskKind,
    TaskRun,
    TaskRunStatus,
    TaskStatus,
    utc_now,
)
from primordial.core.sensitive_text import redact_sensitive_text

class WorkflowExecutionPersistenceMixin:
    def _persist_execution_result(self, task: Task, run: TaskRun, result, report: OrchestrationReport) -> None:
        self._persist_result_traces(task, result)
        self._persist_result_records(task, result, report)
        self._handle_result_escalation_package(task, result, report)
        self._apply_result_status(task, run, result)
        self._finalize_persisted_execution_result(task, run, result, report)

    def _persist_result_traces(self, task: Task, result) -> None:
        for trace in result.traces:
            self.store.insert_trace(trace)
        if not result.traces:
            self.store.insert_trace(
                AgentTrace(
                    task_id=task.id,
                    role=task.role,
                    status="completed" if result.success else "failed",
                    summary=result.summary or task.summary,
                    metadata={"summary_key": task.kind.value},
                )
            )

    def _persist_result_records(self, task: Task, result, report: OrchestrationReport) -> None:
        for artifact in result.artifacts:
            self.store.insert_artifact(artifact)
        for evidence in result.evidence:
            self._annotate_result_metadata(task, evidence.metadata)
            self.store.insert_evidence(evidence)
        for note in result.notes:
            self._annotate_result_metadata(task, note.metadata)
            self.store.insert_note(note)
        for interest in result.interests:
            self._annotate_result_metadata(task, interest.metadata)
            self.store.insert_interest(interest)
        self._persist_result_findings(task, result)
        self._persist_result_handoffs(task, result)
        self._persist_result_notifications(result)
        self._persist_result_sync_jobs(task, result)
        self._queue_notion_sync_for_meaningful_updates(task, result)
        self._persist_result_next_tasks_and_events(task, result, report)

    def _persist_result_findings(self, task: Task, result) -> None:
        for finding in result.findings:
            self._annotate_result_metadata(task, finding.metadata)
            self.store.insert_finding(finding)
            self.store.insert_event(
                EventRecord(
                    type=EventType.FINDING_UPDATED,
                    summary=finding.title,
                    target_id=finding.target_id,
                    task_id=task.id,
                )
            )
            if finding.confidence >= 0.8 or finding.severity.value in {"high", "critical"}:
                self.store.insert_notification(
                    NotificationRecord(
                        channel=NotificationChannel.DISCORD,
                        event_type="finding_candidate",
                        summary=f"{finding.severity.value.upper()}: {finding.title}",
                        target_id=finding.target_id,
                        task_id=task.id,
                        finding_id=finding.id,
                        urgency="high",
                        dedupe_key=f"finding:{finding.title}",
                    )
                )

    def _persist_result_handoffs(self, task: Task, result) -> None:
        for handoff in result.handoffs:
            self.store.insert_handoff(handoff)
            self.store.insert_event(
                EventRecord(
                    type=EventType.HANDOFF_CREATED,
                    summary=handoff.reason,
                    task_id=task.id,
                    target_id=task.target_id,
                )
            )

    def _persist_result_notifications(self, result) -> None:
        for notification in result.notifications:
            existing = notification.dedupe_key and self.store.find_latest_notification_by_dedupe(notification.dedupe_key)
            if existing and existing.status in {NotificationStatus.PENDING, NotificationStatus.DELIVERED}:
                continue
            self.store.insert_notification(notification)

    def _persist_result_sync_jobs(self, task: Task, result) -> None:
        for sync_job in result.sync_jobs:
            if sync_job.kind == ExternalSyncKind.NOTION and self._notion_sync_auth_blocked():
                self.store.insert_event(
                    EventRecord(
                        type=EventType.SYNC_FAILED,
                        summary="Notion sync suppressed after authentication failure",
                        target_id=sync_job.target_id,
                        task_id=task.id,
                        metadata={"kind": sync_job.kind.value, "auth_blocked": True},
                    )
                )
                continue
            self.store.insert_external_sync_job(sync_job)
            self.store.insert_event(
                EventRecord(
                    type=EventType.SYNC_QUEUED,
                    summary=sync_job.summary,
                    target_id=sync_job.target_id,
                    task_id=task.id,
                    metadata={"kind": sync_job.kind.value},
                )
            )

    def _queue_notion_sync_for_meaningful_updates(self, task: Task, result) -> None:
        if not task.target_id or not (result.notes or result.findings):
            return
        sync_job = ExternalSyncJob(
            kind=ExternalSyncKind.NOTION,
            target_id=task.target_id,
            summary="Sync meaningful note/finding updates to Notion",
            payload={"target_id": task.target_id, "task_id": task.id, "kind": task.kind.value},
        )
        if self._notion_sync_auth_blocked():
            self.store.insert_event(
                EventRecord(
                    type=EventType.SYNC_FAILED,
                    summary="Notion sync suppressed after authentication failure",
                    target_id=task.target_id,
                    task_id=task.id,
                    metadata={"kind": sync_job.kind.value, "auth_blocked": True, "automatic": True},
                )
            )
            return
        self.store.insert_external_sync_job(sync_job)
        self.store.insert_event(
            EventRecord(
                type=EventType.SYNC_QUEUED,
                summary=sync_job.summary,
                target_id=task.target_id,
                task_id=task.id,
                metadata={"kind": sync_job.kind.value, "automatic": True},
            )
        )

    def _persist_result_next_tasks_and_events(self, task: Task, result, report: OrchestrationReport) -> None:
        for next_task in result.next_tasks:
            target = self.store.get_target(next_task.target_id)
            self._register_task(next_task, target, report)
        for event in result.events:
            self.store.insert_event(event)
            report.events.append(event)

    def _handle_result_escalation_package(self, task: Task, result, report: OrchestrationReport) -> None:
        if result.escalation_package:
            local_wrapper_available = self._agent_chat_premium_runner_available()
            if not self.autonomy.allow_remote_premium and not local_wrapper_available:
                self._record_suppressed_premium_escalation(task, result.escalation_package)
            elif not self.store.has_active_task(task.target_id, TaskKind.REVIEW_PREMIUM_ESCALATION):
                self._register_premium_escalation_task(task, result.escalation_package, report)

    def _agent_chat_premium_runner_available(self) -> bool:
        return self.worker_broker.has_runner_for(
            route=ProviderRoute.REMOTE_PREMIUM,
            kind=TaskKind.REVIEW_PREMIUM_ESCALATION,
            role=AgentRole.CLAUDE_REVIEWER,
            runner_id="agent-chat-premium-runner",
        )

    def _record_suppressed_premium_escalation(self, task: Task, escalation_package: EscalationPackage) -> None:
        note = Note(
            target_id=task.target_id,
            task_id=task.id,
            title="Premium escalation suppressed (allow_remote_premium=False)",
            body=(
                "An escalation package was generated but remote premium review is "
                f"policy-disabled. Reason: {escalation_package.reason}. "
                "Enable PRIMORDIAL_ALLOW_REMOTE_PREMIUM to activate premium routing."
            ),
            confidence=0.95,
            freshness=1.0,
            metadata={"escalation_suppressed": True, "reason": escalation_package.reason},
        )
        self.store.insert_note(note)

    def _register_premium_escalation_task(
        self,
        task: Task,
        escalation_package: EscalationPackage,
        report: OrchestrationReport,
    ) -> None:
        escalation_task = self._build_task(
            target_id=task.target_id,
            kind=TaskKind.REVIEW_PREMIUM_ESCALATION,
            title="Premium review requested",
            summary=escalation_package.reason,
            session_id=task.session_id,
        )
        escalation_task.evidence_refs = escalation_package.evidence_refs
        escalation_task.metadata["escalation_package"] = escalation_package.as_payload()
        self._mark_agent_chat_wrapper_review(escalation_task)
        if not self.autonomy.allow_remote_premium and not escalation_task.metadata.get("remote_premium_local_wrapper"):
            escalation_task.metadata["remote_premium_policy_approval_required"] = True
        self._register_task(escalation_task, self.store.get_target(task.target_id), report)

    def _apply_result_status(self, task: Task, run: TaskRun, result) -> None:
        result_timed_out = self._result_timed_out(result)
        if result.success:
            task.status = TaskStatus.SUCCEEDED
            run.status = TaskRunStatus.SUCCEEDED
            run.trace_summary = result.summary
            task.attempts += 1
            if task.target_id and self._memory_service().needs_compaction(task.target_id):
                self._memory_service().compact_target(task.target_id)
                self._memory_service().apply_freshness_decay(task.target_id)
        else:
            task.attempts += 1
            if task.attempts < task.max_attempts:
                task.status = TaskStatus.PENDING
                run.status = TaskRunStatus.TIMED_OUT if result_timed_out else TaskRunStatus.FAILED
                self.store.insert_event(
                    EventRecord(
                        type=EventType.TASK_RETRIED,
                        summary=f"Retry scheduled for {task.title}",
                        target_id=task.target_id,
                        task_id=task.id,
                    )
                )
            else:
                task.status = TaskStatus.FAILED
                run.status = TaskRunStatus.TIMED_OUT if result_timed_out else TaskRunStatus.FAILED
            run.error = self._redact_result_error(result.error)
            run.trace_summary = run.error or result.summary
            if result_timed_out:
                run.metadata["timed_out"] = True
                task.metadata["last_run_timed_out"] = True

    def _finalize_persisted_execution_result(self, task: Task, run: TaskRun, result, report: OrchestrationReport) -> None:
        run.finished_at = utc_now()
        run.heartbeat_at = utc_now()
        self.store.guarded_update_task_run(run, from_statuses=[TaskRunStatus.RUNNING])
        task.updated_at = utc_now()
        self.store.guarded_update_task(task, from_statuses=[TaskStatus.RUNNING])
        self._write_checkpoint(
            task,
            run,
            summary="post-execution checkpoint",
            payload={"task": task.as_payload(), "run": run.as_payload(), "summary": result.summary},
            phase="post",
        )
        self.store.insert_event(
            EventRecord(
                type=EventType.TASK_SUCCEEDED if result.success else EventType.TASK_FAILED,
                summary=(result.summary if result.success else self._redact_result_error(result.error) or result.summary)
                or task.title,
                target_id=task.target_id,
                task_id=task.id,
                metadata={"error": self._redact_result_error(result.error)} if result.error else {},
            )
        )
        if self.event_bus is not None:
            self.event_bus.emit(
                RuntimeSignal.TASK_FINISHED,
                {
                    "task_id": task.id,
                    "target_id": task.target_id,
                    "run_id": run.id,
                    "success": result.success,
                },
            )
        report.completed_runs.append(run)

    def _redact_result_error(self, value: object) -> str:
        return redact_sensitive_text(str(value or "")).strip()
