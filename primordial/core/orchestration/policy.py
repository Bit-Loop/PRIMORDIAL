from __future__ import annotations

from typing import Callable

from primordial.core.config import AutonomySettings
from primordial.core.domain.enums import ApprovalAction, AutonomyMode, PolicyVerdict, RiskTier, SideEffectLevel
from primordial.core.domain.enums import TaskStatus
from primordial.core.domain.models import PolicyDecision, PrimitiveManifest, Target, Task
from primordial.core.orchestration.policy_rules import (
    SECRET_FIELD_ALIASES,
    credential_usage_class,
    estimated_remote_cost,
    evaluate_agent_safety_gate,
    evaluate_high_risk_task,
    evaluate_primitive_bounds,
    evaluate_remote_premium_approval_gate,
    evaluate_remote_premium_budget,
    evaluate_remote_premium_task,
    evaluate_task_bounds,
    primitive_action_policy,
    secret_service_key,
    secrets_available,
    task_action_policy,
    uses_local_chat_wrapper,
)


class PolicyEngine:
    SECRET_FIELD_ALIASES = SECRET_FIELD_ALIASES

    def __init__(
        self,
        settings: AutonomySettings,
        *,
        credentials_status_loader: Callable[[], dict[str, object]] | None = None,
        daily_remote_cost_loader: Callable[[], float] | None = None,
    ) -> None:
        self.settings = settings
        self.credentials_status_loader = credentials_status_loader
        self.daily_remote_cost_loader = daily_remote_cost_loader

    def evaluate_task(self, task: Task, target: Target | None) -> PolicyDecision:
        if target is not None and not target.in_scope:
            return PolicyDecision(
                action_kind=task.kind.value,
                verdict=PolicyVerdict.DENY,
                reason="target is out of scope",
                target_id=task.target_id,
                task_id=task.id,
            )
        remote_gate = self._evaluate_remote_premium_task(task, self._uses_local_chat_wrapper(task))
        if remote_gate is not None:
            return remote_gate
        action_policy = self._task_action_policy(task, target)
        bounded_gate = self._evaluate_task_bounds(task, action_policy)
        if bounded_gate is not None:
            bounded_gate.metadata.setdefault("action_policy", action_policy)
            return bounded_gate
        risk_gate = self._evaluate_high_risk_task(task, target, action_policy)
        if risk_gate is not None:
            return risk_gate
        return PolicyDecision(
            action_kind=task.kind.value,
            verdict=PolicyVerdict.ALLOW,
            reason="task falls within current scope, phase, and autonomy policy",
            target_id=task.target_id,
            task_id=task.id,
            metadata={"mode": self.settings.mode.value, "action_policy": action_policy},
        )

    def evaluate_primitive(
        self,
        task: Task,
        target: Target | None,
        primitive: PrimitiveManifest,
    ) -> PolicyDecision:
        if target is not None and not target.in_scope:
            return PolicyDecision(
                action_kind=primitive.name,
                verdict=PolicyVerdict.DENY,
                reason="primitive cannot run because target is out of scope",
                target_id=task.target_id,
                task_id=task.id,
            )
        if task.phase not in primitive.allowed_phases:
            return PolicyDecision(
                action_kind=primitive.name,
                verdict=PolicyVerdict.DENY,
                reason="primitive is not allowed in the current methodology phase",
                target_id=task.target_id,
                task_id=task.id,
                metadata={"phase": task.phase.value},
            )
        action_policy = self._primitive_action_policy(task, target, primitive)
        bounded_gate = self._evaluate_primitive_bounds(task, primitive, action_policy)
        if bounded_gate is not None:
            bounded_gate.metadata.setdefault("action_policy", action_policy)
            return bounded_gate
        if self._high_risk_primitive_needs_approval(task, primitive):
            return PolicyDecision(
                action_kind=primitive.name,
                verdict=PolicyVerdict.NEEDS_APPROVAL,
                reason="high-risk primitive requires approval in the current autonomy mode",
                target_id=task.target_id,
                task_id=task.id,
                metadata={"action_policy": action_policy},
            )
        return PolicyDecision(
            action_kind=primitive.name,
            verdict=PolicyVerdict.ALLOW,
            reason="primitive is allowed by phase and risk policy",
            target_id=task.target_id,
            task_id=task.id,
            metadata={"action_policy": action_policy},
        )

    def apply_decision_to_task(self, task: Task, decision: PolicyDecision) -> Task:
        if decision.verdict == PolicyVerdict.ALLOW:
            task.status = TaskStatus.PENDING
            task.requires_approval = False
        elif decision.verdict == PolicyVerdict.NEEDS_APPROVAL:
            task.status = TaskStatus.NEEDS_APPROVAL
            task.requires_approval = True
        else:
            task.status = TaskStatus.BLOCKED
        return task

    def apply_approval_action(self, task: Task, action: ApprovalAction) -> Task:
        if action == ApprovalAction.APPROVE:
            task.status = TaskStatus.PENDING
            task.requires_approval = False
        else:
            task.status = TaskStatus.CANCELLED
        return task

    def _evaluate_remote_premium_task(self, task: Task, local_wrapper: bool) -> PolicyDecision | None:
        return evaluate_remote_premium_task(self.settings, task, local_wrapper, self.daily_remote_cost_loader)

    def _evaluate_remote_premium_approval_gate(self, task: Task) -> PolicyDecision | None:
        return evaluate_remote_premium_approval_gate(task)

    def _evaluate_remote_premium_budget(self, task: Task, daily_spent: float) -> PolicyDecision | None:
        return evaluate_remote_premium_budget(self.settings, task, daily_spent)

    def _evaluate_high_risk_task(
        self,
        task: Task,
        target: Target | None,
        action_policy: dict[str, object],
    ) -> PolicyDecision | None:
        return evaluate_high_risk_task(self.settings, task, target, action_policy)

    def _evaluate_agent_safety_gate(self, task: Task, target: Target | None) -> PolicyDecision | None:
        return evaluate_agent_safety_gate(self.settings, task, target)

    def _estimated_remote_cost(self, task: Task) -> float:
        return estimated_remote_cost(task)

    def _uses_local_chat_wrapper(self, task: Task) -> bool:
        return uses_local_chat_wrapper(task)

    def _task_action_policy(self, task: Task, target: Target | None) -> dict[str, object]:
        return task_action_policy(self.settings, task, target)

    def _primitive_action_policy(
        self,
        task: Task,
        target: Target | None,
        primitive: PrimitiveManifest,
    ) -> dict[str, object]:
        return primitive_action_policy(self.settings, task, target, primitive)

    def _evaluate_task_bounds(self, task: Task, action_policy: dict[str, object]) -> PolicyDecision | None:
        return evaluate_task_bounds(self.settings, task, action_policy)

    def _evaluate_primitive_bounds(
        self,
        task: Task,
        primitive: PrimitiveManifest,
        action_policy: dict[str, object],
    ) -> PolicyDecision | None:
        return evaluate_primitive_bounds(
            self.settings,
            self.credentials_status_loader,
            task,
            primitive,
            action_policy,
        )

    def _secrets_available(self, required_secrets: list[str]) -> bool:
        return secrets_available(self.credentials_status_loader, required_secrets)

    def _secret_service_key(self, secret: str) -> tuple[str, str] | None:
        return secret_service_key(secret)

    def _credential_usage_class(self, required_secrets: list[str]) -> str:
        return credential_usage_class(required_secrets)

    def _high_risk_primitive_needs_approval(self, task: Task, primitive: PrimitiveManifest) -> bool:
        if primitive.risk_tier not in {RiskTier.HIGH, RiskTier.CRITICAL}:
            return False
        if self.settings.mode not in {AutonomyMode.MANUAL, AutonomyMode.ASSISTED}:
            return False
        return not (task.metadata.get("operator_approved") is True and primitive.side_effect_level == SideEffectLevel.READ_ONLY)
