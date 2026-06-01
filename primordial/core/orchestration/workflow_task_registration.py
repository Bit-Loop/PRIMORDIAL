from __future__ import annotations

from primordial.core.orchestration.workflow_deps import (
    AgentRole,
    blueprint_for,
    EventRecord,
    EventType,
    MethodologyPhase,
    NotificationChannel,
    NotificationRecord,
    OrchestrationReport,
    ProviderRoute,
    RuntimeSignal,
    Target,
    Task,
    TaskKind,
    TaskStatus,
    utc_now,
    ValidationContext,
    ValidationStage,
)

class WorkflowTaskRegistrationMixin:
    def _build_task(
        self,
        target_id: str | None,
        kind: TaskKind,
        title: str,
        summary: str,
        session_id: str | None,
    ) -> Task:
        blueprint = blueprint_for(kind)
        task = Task(
            target_id=target_id,
            session_id=session_id,
            phase=blueprint.phase,
            kind=kind,
            title=title,
            summary=summary,
            role=blueprint.role,
            required_capabilities=list(blueprint.capabilities),
            priority=blueprint.default_priority,
            risk_tier=blueprint.risk_tier,
            max_attempts=min(blueprint.max_attempts, self.autonomy.max_auto_retries),
            metadata={"autonomy_mode": self.autonomy.mode.value},
        )
        task.metadata["operator_intent_id"] = self._active_intent_id()
        route = self.provider_router.select_route(task)
        task.provider_route = route.route
        task.provider_model = route.model_name
        task.metadata["provider_rationale"] = route.rationale
        task.metadata["cold_path"] = route.cold_path
        return task

    def _register_task(self, task: Task, target: Target | None, report: OrchestrationReport) -> None:
        validation_issues = self.validation_registry.validate(
            ValidationStage.TASK_REGISTRATION,
            ValidationContext(
                task=task,
                target=target,
                store=self.store,
                primitives=self._stored_primitives_for_task(task),
            ),
        )
        self._apply_validation_annotations(task, validation_issues)
        if any(issue.blocks_progress for issue in validation_issues):
            self._record_validation_failure(
                task,
                validation_issues,
                report,
                stage=ValidationStage.TASK_REGISTRATION,
                track_created=True,
            )
            return
        auto_approved = self._maybe_auto_approve_agent_chat_premium_review(task)
        decision = self.policy_engine.evaluate_task(task, target)
        self.policy_engine.apply_decision_to_task(task, decision)
        self.store.insert_task(task)
        self.store.insert_policy_decision(decision)
        report.created_tasks.append(task)
        report.decisions.append(decision)
        self.store.insert_event(
            EventRecord(
                type=(
                    EventType.TASK_NEEDS_APPROVAL
                    if task.status == TaskStatus.NEEDS_APPROVAL
                    else EventType.TASK_BLOCKED
                    if task.status == TaskStatus.BLOCKED
                    else EventType.TASK_PLANNED
                ),
                summary=f"{task.kind.value}: {task.title}",
                target_id=task.target_id,
                task_id=task.id,
                metadata={"status": task.status.value, "reason": decision.reason},
            )
        )
        if task.status != TaskStatus.BLOCKED:
            self.store.consume_handoffs_for_task(task)
        if auto_approved and task.status != TaskStatus.BLOCKED:
            approval_event = EventRecord(
                type=EventType.APPROVAL_GRANTED,
                summary=f"Auto-approved agent_chat_api planner premium review: {task.title}",
                target_id=task.target_id,
                task_id=task.id,
                metadata={
                    "auto_approved": True,
                    "auto_approval_source": "agent_chat_api_wrapper",
                    "task_kind": task.kind.value,
                },
            )
            self.store.insert_event(approval_event)
            report.events.append(approval_event)
        if self.event_bus is not None:
            self.event_bus.emit(
                RuntimeSignal.TASK_PLANNED,
                {"task_id": task.id, "target_id": task.target_id, "status": task.status.value},
            )
        if task.status == TaskStatus.NEEDS_APPROVAL:
            self.store.insert_notification(
                NotificationRecord(
                    channel=NotificationChannel.DISCORD,
                    event_type="approval_needed",
                    summary=f"Approval required: {task.title}",
                    target_id=task.target_id,
                    task_id=task.id,
                    urgency="high",
                    dedupe_key=f"approval:{task.id}",
                )
            )

    def _maybe_auto_approve_agent_chat_premium_review(self, task: Task) -> bool:
        if not self._is_agent_chat_planner_review_auto_approval_candidate(task):
            return False
        approved_at = utc_now().isoformat()
        task.metadata.update(
            {
                "remote_premium_operator_approved": True,
                "remote_premium_operator_approved_at": approved_at,
                "operator_approved": True,
                "operator_approved_at": approved_at,
                "auto_approved": True,
                "auto_approval_source": "agent_chat_api_wrapper",
            }
        )
        task.requires_approval = False
        return True

    def _mark_agent_chat_wrapper_review(self, task: Task) -> bool:
        if not self.worker_broker.has_runner_for(
            route=ProviderRoute.REMOTE_PREMIUM,
            kind=TaskKind.REVIEW_PREMIUM_ESCALATION,
            role=AgentRole.CLAUDE_REVIEWER,
            runner_id="agent-chat-premium-runner",
        ):
            return False
        if task.kind != TaskKind.REVIEW_PREMIUM_ESCALATION or task.role != AgentRole.CLAUDE_REVIEWER:
            return False
        task.metadata["local_chat_wrapper"] = "agent_chat_api"
        task.metadata["remote_premium_local_wrapper"] = True
        return True

    def _is_agent_chat_planner_review_auto_approval_candidate(self, task: Task) -> bool:
        if task.kind != TaskKind.REVIEW_PREMIUM_ESCALATION:
            return False
        if task.phase != MethodologyPhase.ANALYSIS:
            return False
        if task.role != AgentRole.CLAUDE_REVIEWER:
            return False
        if task.provider_route != ProviderRoute.REMOTE_PREMIUM:
            return False
        if not task.metadata.get("remote_premium_policy_approval_required"):
            return False
        if not self.worker_broker.has_runner_for(
            route=ProviderRoute.REMOTE_PREMIUM,
            kind=TaskKind.REVIEW_PREMIUM_ESCALATION,
            role=AgentRole.CLAUDE_REVIEWER,
            runner_id="agent-chat-premium-runner",
        ):
            return False
        package = task.metadata.get("escalation_package")
        if not isinstance(package, dict):
            return False
        if package.get("mode") != "planner_uncertainty_review":
            return False
        if package.get("expected_output_type") != "planner_remote_review_v1":
            return False
        package_metadata = package.get("metadata")
        if not isinstance(package_metadata, dict):
            return False
        packet = package_metadata.get("packet")
        if not isinstance(packet, dict):
            return False
        if packet.get("handoff_type") != "planner_uncertainty_review":
            return False
        required_output = packet.get("required_output")
        if not isinstance(required_output, dict):
            return False
        expected_keys = {
            "recommended_next_actions",
            "missing_evidence",
            "invalid_existing_tasks",
            "primitive_gaps",
            "confidence",
            "rationale_with_evidence_refs",
        }
        if not expected_keys.issubset(required_output):
            return False
        authority_limits = packet.get("authority_limits")
        if not isinstance(authority_limits, list):
            return False
        limit_text = "\n".join(str(item).lower() for item in authority_limits)
        for required_limit in (
            "cannot approve credential use",
            "cannot expand target scope",
            "cannot execute tools",
            "cannot override operator intent",
        ):
            if required_limit not in limit_text:
                return False
        return True
