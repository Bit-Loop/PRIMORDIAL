from __future__ import annotations

from primordial.core.orchestration.workflow_deps import (
    EventRecord,
    EventType,
    json,
    OrchestrationReport,
    Target,
    TargetMethodologyState,
    Task,
    TaskKind,
    TaskStatus,
    utc_now,
)

class WorkflowMethodologyPersistenceMixin:
    def _persist_target_methodology_state(
        self,
        target: Target,
        state: TargetMethodologyState,
        report: OrchestrationReport,
    ) -> None:
        previous_state = target.metadata.get("methodology_state", {})
        previous_payload = previous_state if isinstance(previous_state, dict) else {}
        payload = state.as_payload()
        payload["planner_version"] = 2
        payload["fingerprint"] = json.dumps(
            {
                "phase": payload["phase"],
                "subphase": payload["subphase"],
                "completion": payload["completion"],
                "candidate_actions": payload["candidate_actions"],
                "blockers": payload["blockers"],
                "no_progress_reason": payload["no_progress_reason"],
            },
            sort_keys=True,
        )
        target.metadata["methodology_state"] = payload
        target.updated_at = utc_now()
        self.store.insert_target(target)
        if previous_payload.get("fingerprint") != payload["fingerprint"]:
            event = EventRecord(
                type=EventType.TASK_PLANNED,
                summary=f"Methodology state updated: {state.phase.value}/{state.subphase}",
                target_id=target.id,
                metadata={
                    "phase": state.phase.value,
                    "subphase": state.subphase,
                    "completion": state.completion,
                    "candidate_actions": len(state.candidate_actions),
                },
            )
            self.store.insert_event(event)
            report.events.append(event)

    def _record_no_progress_state(
        self,
        target: Target,
        state: TargetMethodologyState,
        report: OrchestrationReport,
    ) -> None:
        current_state = target.metadata.get("methodology_state", {})
        if not isinstance(current_state, dict):
            return
        no_progress_key = json.dumps(
            {
                "reason": state.no_progress_reason,
                "next_unblock_action": state.next_unblock_action,
                "phase": state.phase.value,
                "subphase": state.subphase,
            },
            sort_keys=True,
        )
        if current_state.get("last_no_progress_key") == no_progress_key:
            return
        current_state["last_no_progress_key"] = no_progress_key
        target.metadata["methodology_state"] = current_state
        target.updated_at = utc_now()
        self.store.insert_target(target)
        event = EventRecord(
            type=EventType.NO_PROGRESS,
            summary=state.no_progress_reason or "No admissible methodology transition is currently available.",
            target_id=target.id,
            metadata={
                "phase": state.phase.value,
                "subphase": state.subphase,
                "next_unblock_action": state.next_unblock_action,
                "blockers": list(state.blockers),
            },
        )
        self.store.insert_event(event)
        report.events.append(event)

    def _record_invalid_target_block(self, target: Target, report: OrchestrationReport) -> None:
        if target.metadata.get("planner_invalid_target_blocked"):
            return
        target.metadata["planner_invalid_target_blocked"] = True
        target.updated_at = utc_now()
        self.store.insert_target(target)
        event = EventRecord(
            type=EventType.TASK_BLOCKED,
            summary="Planner skipped invalid target: target handle is empty",
            target_id=target.id,
            metadata={
                "invalid_target": True,
                "reason": "target handle is empty",
            },
        )
        self.store.insert_event(event)
        report.events.append(event)

    def _invalidate_contradicted_credentialed_access_tasks(
        self,
        target: Target,
        report: OrchestrationReport,
    ) -> list[dict[str, object]]:
        invalidated: list[dict[str, object]] = []
        for task in self.store.list_tasks(target_id=target.id, limit=500):
            if task.kind != TaskKind.CREDENTIALED_ACCESS_CHECK:
                continue
            if task.status not in {TaskStatus.PENDING, TaskStatus.WAITING, TaskStatus.NEEDS_APPROVAL}:
                continue
            reason = self._credentialed_access_task_block_reason(task, target)
            if not reason:
                continue
            event = self._invalidate_task(
                task,
                reason,
                event_summary=f"Credentialed access task invalidated: {task.title}",
            )
            report.events.append(event)
            invalidated.append(
                {
                    "task_id": task.id,
                    "title": task.title,
                    "status": task.status.value,
                    "reason": reason,
                }
            )
        return invalidated

    def _credentialed_access_task_block_reason(self, task: Task, target: Target | None) -> str:
        if target is None:
            return "target record is missing"
        active_generation = self._target_active_generation(target)
        if active_generation is not None:
            task_generation = task.metadata.get("active_ip_generation")
            if str(task_generation or "") != active_generation:
                return "task was planned for a stale target evidence generation"
        policy = self._active_intent_policy()
        if policy is not None and not policy.credential_policy.credential_validation_allowed:
            return "active operator intent does not allow credential validation"
        surface = self._current_credentialed_access_surface(target)
        if not surface.eligible:
            return surface.blocked_reason or "current evidence does not support Windows SMB/WinRM credential validation"
        task_protocols = {
            str(item).strip().lower()
            for item in task.metadata.get("protocols", [])
            if str(item).strip()
        } if isinstance(task.metadata.get("protocols"), list) else set()
        if task_protocols and not task_protocols.intersection(surface.protocols):
            return "task protocols no longer match the current credentialed-access surface"
        current_refs = {item.id for item in self._current_generation_evidence(target, limit=500)}
        if task.evidence_refs and not set(task.evidence_refs).issubset(current_refs):
            return "task evidence references are not current for the active target generation"
        return ""

    def _invalidate_task(self, task: Task, reason: str, *, event_summary: str) -> EventRecord:
        task.status = TaskStatus.BLOCKED
        task.requires_approval = False
        task.updated_at = utc_now()
        task.metadata["invalidated_by_planner"] = True
        task.metadata["invalidation_reason"] = reason
        updated = self.store.update_task_status(
            task.id,
            from_statuses=[TaskStatus.PENDING, TaskStatus.RUNNING, TaskStatus.WAITING, TaskStatus.NEEDS_APPROVAL],
            to_status=TaskStatus.BLOCKED,
            metadata_patch=task.metadata,
            requires_approval=False,
        )
        if updated is not None:
            task = updated
        event = EventRecord(
            type=EventType.TASK_BLOCKED,
            summary=event_summary,
            target_id=task.target_id,
            task_id=task.id,
            metadata={"reason": reason, "invalidated_by_planner": True},
        )
        self.store.insert_event(event)
        return event

    def _planner_uncertainty_reasons(
        self,
        target: Target,
        state: TargetMethodologyState,
        invalidated_tasks: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        reasons: list[dict[str, object]] = []
        if invalidated_tasks:
            reasons.append(
                {
                    "code": "contradictory_existing_task",
                    "summary": "Current evidence contradicted an existing credentialed-access task or approval.",
                    "tasks": invalidated_tasks,
                }
            )
        ai_admission = state.metadata.get("ai_proposal_admission", {})
        accepted = ai_admission.get("accepted", []) if isinstance(ai_admission, dict) else []
        rejected = ai_admission.get("rejected", []) if isinstance(ai_admission, dict) else []
        if rejected and not accepted:
            reasons.append(
                {
                    "code": "all_ai_proposals_rejected",
                    "summary": "All AI-proposed actions lacked registered primitive mappings.",
                    "rejected": rejected,
                }
            )
        if (
            not state.candidate_actions
            and int(state.metadata.get("current_generation_evidence_count", 0) or 0) > 0
            and int(state.metadata.get("waiting_task_count", 0) or 0) == 0
            and state.no_progress_reason
        ):
            reasons.append(
                {
                    "code": "no_admissible_next_task",
                    "summary": "Live evidence exists, but no admissible next task is derivable.",
                    "no_progress_reason": state.no_progress_reason,
                }
            )
        return reasons

    def _latest_failed_planner_escalation(self, target: Target) -> dict[str, object] | None:
        active_generation = self._target_active_generation(target)
        for task in self.store.list_tasks(target_id=target.id, limit=100):
            if task.kind != TaskKind.REVIEW_PREMIUM_ESCALATION or task.status != TaskStatus.FAILED:
                continue
            task_generation = task.metadata.get("active_ip_generation")
            if (
                active_generation is not None
                and task_generation is not None
                and str(task_generation) != active_generation
            ):
                continue
            error = str(task.metadata.get("last_error") or task.metadata.get("error") or "").strip()
            if not error:
                latest_run = next(iter(self.store.list_task_runs(task_id=task.id, limit=1)), None)
                error = str(latest_run.error or "").strip() if latest_run is not None else ""
            if not error:
                error = task.summary
            return {
                "task_id": task.id,
                "title": task.title,
                "error": error,
                "active_ip_generation": task_generation,
            }
        return None

    def _planner_uncertainty_question(self, target: Target, state: TargetMethodologyState) -> str:
        return (
            f"What is the next valid, evidence-linked task for {target.handle} under "
            f"operator intent {self._active_intent_id()}? Classify invalid existing tasks and missing evidence, "
            "but do not approve credential use, expand scope, execute tools, or override Operator Intent."
        )
