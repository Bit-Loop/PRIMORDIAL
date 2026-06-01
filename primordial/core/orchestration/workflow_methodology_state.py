from __future__ import annotations

from primordial.core.orchestration.workflow_deps import (
    blueprint_for,
    MethodologyPhase,
    OrchestrationReport,
    Target,
    TargetMethodologyState,
    Task,
    TaskKind,
    TaskStatus,
)

from primordial.core.orchestration.workflow_types import (
    PlannedTargetAction,
)

class WorkflowMethodologyStateMixin:
    def _plan_target(self, target: Target, session_id: str | None, report: OrchestrationReport) -> None:
        if not target.handle.strip():
            self._record_invalid_target_block(target, report)
            return
        invalidated_tasks = self._invalidate_contradicted_credentialed_access_tasks(target, report)
        methodology_state = self._evaluate_target_methodology_state(target)
        self._persist_target_methodology_state(target, methodology_state, report)
        planned_any = False
        for action in methodology_state.candidate_actions:
            kind = TaskKind(str(action["kind"]))
            if kind == TaskKind.ANALYZE_EVIDENCE:
                task = self._build_analysis_task_if_stale(target, session_id)
                if task is None:
                    continue
                self._register_task(task, target, report)
                planned_any = True
                continue
            task = self._build_task(
                target.id,
                kind,
                str(action["title"]),
                str(action["summary"]),
                session_id=session_id,
            )
            active_generation = self._target_active_generation(target)
            if active_generation is not None:
                task.metadata["active_ip_generation"] = active_generation
                task.metadata["active_ip"] = target.metadata.get("active_ip")
            action_metadata = dict(action.get("metadata", {}))
            task.metadata.update(action_metadata)
            supporting_refs = action_metadata.get("evidence_refs") or action_metadata.get("supporting_evidence_refs")
            if isinstance(supporting_refs, list):
                task.evidence_refs = [str(item) for item in supporting_refs if str(item).strip()]
            self._register_task(task, target, report)
            planned_any = True
        if not planned_any and methodology_state.no_progress_reason:
            self._record_no_progress_state(target, methodology_state, report)
        uncertainty = self._planner_uncertainty_reasons(target, methodology_state, invalidated_tasks)
        if uncertainty:
            self.create_planner_uncertainty_escalation(
                target,
                reason_code="planner_uncertainty",
                question=self._planner_uncertainty_question(target, methodology_state),
                blockers=list(methodology_state.blockers),
                rejected_proposals=methodology_state.metadata.get("ai_proposal_admission", {}).get("rejected", []),
                invalid_existing_tasks=invalidated_tasks,
                session_id=session_id,
                report=report,
                uncertainty_reasons=uncertainty,
            )

    def _evaluate_target_methodology_state(self, target: Target) -> TargetMethodologyState:
        active_generation = self._target_active_generation(target)
        evidence = self._current_generation_evidence(target)
        tasks = self._current_generation_tasks(target)
        waiting_or_active = self._waiting_or_active_methodology_tasks(tasks)
        admissions = self._methodology_candidate_actions_with_admissions(target, tasks)
        candidate_actions, ai_admission, ai_materialized_actions, remote_review_admission, rag_hint_admission = admissions
        failed_planner_escalation = self._latest_failed_planner_escalation(target)
        blockers = self._methodology_state_blockers(
            target,
            evidence,
            ai_admission,
            remote_review_admission,
            rag_hint_admission,
            failed_planner_escalation,
        )
        verified_interests = self._verified_interest_count_current_generation(target)
        phase, subphase, completion, transition_reason = self._methodology_transition_state(
            target,
            evidence,
            candidate_actions,
            waiting_or_active,
            verified_interests,
        )

        next_unblock_action = blockers[0] if blockers else None
        no_progress_reason = self._methodology_no_progress_reason(
            candidate_actions,
            waiting_or_active,
            blockers,
            transition_reason,
        )

        return TargetMethodologyState(
            phase=phase,
            subphase=subphase,
            completion=completion,
            transition_reason=transition_reason,
            candidate_actions=self._methodology_candidate_action_payloads(candidate_actions),
            blockers=blockers,
            next_unblock_action=next_unblock_action,
            no_progress_reason=no_progress_reason,
            retry_budget=self._methodology_retry_budget(tasks),
            metadata=self._methodology_state_metadata(
                active_generation=active_generation,
                evidence=evidence,
                waiting_or_active=waiting_or_active,
                verified_interests=verified_interests,
                ai_admission=ai_admission,
                ai_materialized_actions=ai_materialized_actions,
                failed_planner_escalation=failed_planner_escalation,
                remote_review_admission=remote_review_admission,
                rag_hint_admission=rag_hint_admission,
            ),
        )

    def _waiting_or_active_methodology_tasks(self, tasks: list[Task]) -> list[Task]:
        waiting_statuses = {TaskStatus.PENDING, TaskStatus.RUNNING, TaskStatus.WAITING, TaskStatus.NEEDS_APPROVAL}
        return [task for task in tasks if task.status in waiting_statuses]

    def _methodology_candidate_actions_with_admissions(self, target: Target, tasks: list[Task]):
        candidate_actions = self._methodology_candidate_actions(target)
        ai_admission = self._evaluate_ai_proposal_admission(tasks)
        ai_materialized_actions = self._ai_admitted_candidate_actions(
            target,
            ai_admission,
            reserved_kinds={item.kind for item in candidate_actions},
        )
        candidate_actions.extend(ai_materialized_actions)
        remote_review_admission = self._evaluate_remote_review_admission(target)
        candidate_actions.extend(remote_review_admission["actions"])
        rag_hint_admission = self._evaluate_rag_hint_admission(target)
        candidate_actions.extend(rag_hint_admission["actions"])
        return candidate_actions, ai_admission, ai_materialized_actions, remote_review_admission, rag_hint_admission

    def _methodology_state_blockers(
        self,
        target: Target,
        evidence: list[object],
        ai_admission: dict[str, object],
        remote_review_admission: dict[str, object],
        rag_hint_admission: dict[str, object],
        failed_planner_escalation: dict[str, object] | None,
    ) -> list[str]:
        blockers = self._methodology_blockers(target, evidence)
        self._extend_admission_rejection_blockers(blockers, "AI proposal", ai_admission)
        self._extend_admission_rejection_blockers(blockers, "Remote premium recommendation", remote_review_admission)
        self._extend_admission_rejection_blockers(blockers, "RAG hint", rag_hint_admission)
        if failed_planner_escalation is not None:
            blockers.append(f"Planner uncertainty escalation failed: {failed_planner_escalation['error']}")
        return blockers

    def _extend_admission_rejection_blockers(
        self,
        blockers: list[str],
        label: str,
        admission: dict[str, object],
    ) -> None:
        rejected = admission.get("rejected", [])
        if isinstance(rejected, list):
            blockers.extend(f"{label} rejected: {item['title']} ({item['reason']})" for item in rejected[:3])

    def _methodology_transition_state(
        self,
        target: Target,
        evidence: list[object],
        candidate_actions: list[PlannedTargetAction],
        waiting_or_active: list[Task],
        verified_interests: int,
    ) -> tuple[MethodologyPhase, str, str, str]:
        if candidate_actions:
            lead = candidate_actions[0]
            return blueprint_for(lead.kind).phase, lead.subphase, "candidate_actions_ready", lead.transition_reason
        if waiting_or_active:
            lead_task = waiting_or_active[0]
            reason = f"Existing {lead_task.status.value} task is already covering the next methodology step."
            return lead_task.phase, lead_task.kind.value, "waiting_on_existing_tasks", reason
        if not evidence:
            return blueprint_for(TaskKind.RECON_SCAN).phase, "bootstrap", "blocked", "No current-generation target evidence is available yet."
        if self._memory_service().needs_compaction(target.id):
            reason = "Memory maintenance is due, but an equivalent task is already satisfied or waiting."
            return blueprint_for(TaskKind.COMPACT_MEMORY).phase, TaskKind.COMPACT_MEMORY.value, "memory_maintenance_due", reason
        if verified_interests >= 2:
            reason = "Verified exploit-chain inputs exist, but no new chain action is currently admissible."
            return blueprint_for(TaskKind.CHAIN_CANDIDATES).phase, "chain_backlog", "steady_state", reason
        if verified_interests >= 1:
            reason = "A verified hypothesis exists, but no new bounded verification action is currently admissible."
            return blueprint_for(TaskKind.VERIFY_HYPOTHESIS).phase, "verification_backlog", "steady_state", reason
        reason = "No new methodology transition is currently admissible from the current evidence."
        return blueprint_for(TaskKind.ANALYZE_EVIDENCE).phase, "analysis_backlog", "steady_state", reason

    def _methodology_no_progress_reason(
        self,
        candidate_actions: list[PlannedTargetAction],
        waiting_or_active: list[Task],
        blockers: list[str],
        transition_reason: str,
    ) -> str | None:
        if candidate_actions or waiting_or_active:
            return None
        return blockers[0] if blockers else transition_reason

    def _methodology_retry_budget(self, tasks: list[Task]) -> dict[str, int]:
        retry_statuses = {
            TaskStatus.PENDING,
            TaskStatus.RUNNING,
            TaskStatus.WAITING,
            TaskStatus.NEEDS_APPROVAL,
            TaskStatus.FAILED,
        }
        return {
            task.kind.value: max(0, task.max_attempts - task.attempts)
            for task in tasks
            if task.status in retry_statuses
        }

    def _methodology_candidate_action_payloads(self, candidate_actions: list[PlannedTargetAction]) -> list[dict[str, object]]:
        return [
            {
                "kind": item.kind.value,
                "title": item.title,
                "summary": item.summary,
                "confidence": item.confidence,
                "phase": item.phase_label,
                "subphase": item.subphase,
                "transition_reason": item.transition_reason,
                "prerequisite": item.prerequisite,
                "metadata": dict(item.metadata),
            }
            for item in candidate_actions
        ]

    def _methodology_state_metadata(
        self,
        *,
        active_generation: str | None,
        evidence: list[object],
        waiting_or_active: list[Task],
        verified_interests: int,
        ai_admission: dict[str, object],
        ai_materialized_actions: list[PlannedTargetAction],
        failed_planner_escalation: dict[str, object] | None,
        remote_review_admission: dict[str, object],
        rag_hint_admission: dict[str, object],
    ) -> dict[str, object]:
        return {
            "active_ip_generation": active_generation,
            "current_generation_evidence_count": len(evidence),
            "waiting_task_count": len(waiting_or_active),
            "verified_interest_count": verified_interests,
            "ai_proposal_admission": ai_admission,
            "ai_materialized_actions": self._ai_materialized_action_payloads(ai_materialized_actions),
            "planner_escalation_status": {"latest_failed": failed_planner_escalation},
            "remote_review_admission": {
                "accepted": remote_review_admission["accepted"],
                "rejected": remote_review_admission["rejected"],
            },
            "rag_hint_admission": {
                "accepted": rag_hint_admission["accepted"],
                "rejected": rag_hint_admission["rejected"],
            },
        }
