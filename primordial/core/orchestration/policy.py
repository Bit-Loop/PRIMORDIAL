from __future__ import annotations

from typing import Callable

from primordial.core.config import AutonomySettings
from primordial.core.domain.enums import (
    ApprovalAction,
    AutonomyMode,
    MethodologyPhase,
    PolicyVerdict,
    ProviderRoute,
    RiskTier,
    ScopeProfile,
    SideEffectLevel,
    TaskStatus,
)
from primordial.core.domain.models import PolicyDecision, PrimitiveManifest, Target, Task


class PolicyEngine:
    SECRET_FIELD_ALIASES = {
        "DISCORD_WEBHOOK_URL": ("discord", "webhook_url"),
        "NOTION_API_KEY": ("notion", "api_key"),
        "NOTION_PARENT_PAGE_ID": ("notion", "parent_page_id"),
        "NOTION_VERSION": ("notion", "version"),
        "PRIMORDIAL_CAIDO_GRAPHQL_URL": ("caido", "graphql_url"),
        "PRIMORDIAL_CAIDO_API_TOKEN": ("caido", "api_token"),
    }

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

        if task.provider_route == ProviderRoute.REMOTE_PREMIUM and not self.settings.allow_remote_premium:
            return PolicyDecision(
                action_kind=task.kind.value,
                verdict=PolicyVerdict.DENY,
                reason="remote premium provider use is disabled by policy",
                target_id=task.target_id,
                task_id=task.id,
            )

        if task.provider_route == ProviderRoute.REMOTE_PREMIUM and self.daily_remote_cost_loader is not None:
            daily_spent = self.daily_remote_cost_loader()
            if daily_spent >= self.settings.daily_remote_budget:
                return PolicyDecision(
                    action_kind=task.kind.value,
                    verdict=PolicyVerdict.DENY,
                    reason=f"daily remote budget exhausted: ${daily_spent:.2f} >= ${self.settings.daily_remote_budget:.2f}",
                    target_id=task.target_id,
                    task_id=task.id,
                    metadata={"daily_spent_usd": daily_spent, "daily_budget_usd": self.settings.daily_remote_budget},
                )

        action_policy = self._task_action_policy(task, target)
        bounded_gate = self._evaluate_task_bounds(task, action_policy)
        if bounded_gate is not None:
            bounded_gate.metadata.setdefault("action_policy", action_policy)
            return bounded_gate

        risky_phase = task.phase in {MethodologyPhase.EXPLOITATION, MethodologyPhase.CHAINING}
        high_risk = task.risk_tier in {RiskTier.HIGH, RiskTier.CRITICAL}
        if risky_phase or high_risk:
            if not self.settings.allow_exploitative_actions:
                return PolicyDecision(
                    action_kind=task.kind.value,
                    verdict=PolicyVerdict.NEEDS_APPROVAL,
                    reason="exploitative or high-risk task requires approval because exploitative actions are disabled",
                    target_id=task.target_id,
                    task_id=task.id,
                    metadata={"mode": self.settings.mode.value, "action_policy": action_policy},
                )
            agent_gate = self._evaluate_agent_safety_gate(task, target)
            if agent_gate is not None:
                agent_gate.metadata.setdefault("action_policy", action_policy)
                return agent_gate
            return PolicyDecision(
                action_kind=task.kind.value,
                verdict=PolicyVerdict.NEEDS_APPROVAL,
                reason="task is gated by autonomy mode, risk policy, or missing agent safety approval",
                target_id=task.target_id,
                task_id=task.id,
                metadata={"mode": self.settings.mode.value, "action_policy": action_policy},
            )

        return PolicyDecision(
            action_kind=task.kind.value,
            verdict=PolicyVerdict.ALLOW,
            reason="task falls within current scope, phase, and autonomy policy",
            target_id=task.target_id,
            task_id=task.id,
            metadata={"mode": self.settings.mode.value, "action_policy": action_policy},
        )

    def _evaluate_agent_safety_gate(self, task: Task, target: Target | None) -> PolicyDecision | None:
        if not self.settings.allow_agent_safety_approval:
            return None
        if self.settings.mode not in {AutonomyMode.SUPERVISED_AUTO, AutonomyMode.HIGH_AUTONOMY}:
            return None
        if target is None:
            return None
        if target.profile == ScopeProfile.HACKERONE and not target.metadata.get("allow_agent_poc_execution"):
            return None
        approval = task.metadata.get("agent_safety_approval")
        if not isinstance(approval, dict):
            return None
        reviewer = str(approval.get("reviewer_agent", ""))
        if reviewer not in self.settings.approved_reviewer_agents:
            return None
        checks = {
            "approved": approval.get("approved") is True,
            "scope_verified": approval.get("scope_verified") is True,
            "bounded_execution": approval.get("bounded_execution") is True,
            "dos_risk_false": approval.get("dos_risk") is False,
            "ddos_risk_false": approval.get("ddos_risk") is False,
            "evidence_linked": bool(approval.get("evidence_refs") or task.evidence_refs),
        }
        try:
            timeout_seconds = int(approval.get("timeout_seconds", 0))
            max_requests = int(approval.get("max_requests", 0))
        except (TypeError, ValueError):
            return None
        checks["timeout_bounded"] = 0 < timeout_seconds <= self.settings.max_poc_timeout_seconds
        checks["request_bounded"] = 0 < max_requests <= self.settings.max_poc_requests
        if not all(checks.values()):
            return None
        return PolicyDecision(
            action_kind=task.kind.value,
            verdict=PolicyVerdict.ALLOW,
            reason="task allowed by explicit agent safety approval and bounded non-DoS execution policy",
            target_id=task.target_id,
            task_id=task.id,
            metadata={
                "mode": self.settings.mode.value,
                "approval_source": reviewer,
                "safety_checks": checks,
                "timeout_seconds": timeout_seconds,
                "max_requests": max_requests,
            },
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

        if primitive.risk_tier in {RiskTier.HIGH, RiskTier.CRITICAL} and self.settings.mode in {
            AutonomyMode.MANUAL,
            AutonomyMode.ASSISTED,
        }:
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

    def _task_action_policy(self, task: Task, target: Target | None) -> dict[str, object]:
        risky = task.phase in {MethodologyPhase.EXPLOITATION, MethodologyPhase.CHAINING} or task.risk_tier in {
            RiskTier.HIGH,
            RiskTier.CRITICAL,
        }
        target_metadata = target.metadata if target else {}
        explicit_time_cap = "timeout_seconds" in task.metadata or "policy_timeout_seconds" in target_metadata
        default_timeout = self.settings.max_poc_timeout_seconds if risky else max(180, self.settings.max_poc_timeout_seconds)
        default_requests = self.settings.max_poc_requests if risky else max(25, self.settings.max_poc_requests)
        default_concurrency = self.settings.high_risk_concurrency if risky else self.settings.hot_path_concurrency
        return {
            "target_profile": target.profile.value if target else None,
            "request_cap": int(task.metadata.get("max_requests", target_metadata.get("policy_max_requests", default_requests)) or default_requests),
            "time_cap_seconds": int(task.metadata.get("timeout_seconds", target_metadata.get("policy_timeout_seconds", default_timeout)) or default_timeout),
            "explicit_time_cap": explicit_time_cap,
            "rate_window_seconds": int(target_metadata.get("policy_rate_window_seconds", 60 if target and target.profile == ScopeProfile.HACK_THE_BOX else 300)),
            "concurrency_ceiling": int(target_metadata.get("policy_concurrency_ceiling", default_concurrency) or default_concurrency),
            "side_effect_class": str(task.metadata.get("side_effect_class", "exploitative" if risky else "read_only")),
            "credential_usage_class": str(task.metadata.get("credential_usage_class", "none")),
        }

    def _primitive_action_policy(
        self,
        task: Task,
        target: Target | None,
        primitive: PrimitiveManifest,
    ) -> dict[str, object]:
        task_policy = self._task_action_policy(task, target)
        max_requests = int(
            primitive.metadata.get(
                "max_requests",
                task.metadata.get("max_requests", target.metadata.get("policy_max_requests") if target else task_policy["request_cap"]),
            )
            or task_policy["request_cap"]
        )
        return {
            **task_policy,
            "primitive": primitive.name,
            "primitive_timeout_seconds": primitive.timeout_seconds,
            "request_cap": max_requests,
            "side_effect_class": primitive.side_effect_level.value,
            "credential_usage_class": self._credential_usage_class(primitive.required_secrets),
            "required_secrets": list(primitive.required_secrets),
        }

    def _evaluate_task_bounds(self, task: Task, action_policy: dict[str, object]) -> PolicyDecision | None:
        timeout_seconds = int(action_policy["time_cap_seconds"])
        request_cap = int(action_policy["request_cap"])
        if timeout_seconds <= 0 or request_cap <= 0:
            return PolicyDecision(
                action_kind=task.kind.value,
                verdict=PolicyVerdict.DENY,
                reason="task action-policy bounds are invalid",
                target_id=task.target_id,
                task_id=task.id,
            )
        if task.risk_tier in {RiskTier.HIGH, RiskTier.CRITICAL} and timeout_seconds > self.settings.max_poc_timeout_seconds:
            return PolicyDecision(
                action_kind=task.kind.value,
                verdict=PolicyVerdict.NEEDS_APPROVAL,
                reason="task exceeds the configured high-risk timeout ceiling",
                target_id=task.target_id,
                task_id=task.id,
            )
        if task.risk_tier in {RiskTier.HIGH, RiskTier.CRITICAL} and request_cap > self.settings.max_poc_requests:
            return PolicyDecision(
                action_kind=task.kind.value,
                verdict=PolicyVerdict.NEEDS_APPROVAL,
                reason="task exceeds the configured high-risk request ceiling",
                target_id=task.target_id,
                task_id=task.id,
            )
        return None

    def _evaluate_primitive_bounds(
        self,
        task: Task,
        primitive: PrimitiveManifest,
        action_policy: dict[str, object],
    ) -> PolicyDecision | None:
        required_secrets = list(primitive.required_secrets)
        if required_secrets and not self._secrets_available(required_secrets):
            return PolicyDecision(
                action_kind=primitive.name,
                verdict=PolicyVerdict.NEEDS_APPROVAL,
                reason="primitive requires credentials or integration secrets that are not configured",
                target_id=task.target_id,
                task_id=task.id,
            )
        if (
            primitive.timeout_seconds > int(action_policy["time_cap_seconds"])
            and (
                bool(action_policy.get("explicit_time_cap"))
                or task.risk_tier in {RiskTier.HIGH, RiskTier.CRITICAL}
                or primitive.side_effect_level in {SideEffectLevel.MUTATING, SideEffectLevel.EXPLOITATIVE}
            )
        ):
            return PolicyDecision(
                action_kind=primitive.name,
                verdict=PolicyVerdict.NEEDS_APPROVAL,
                reason="primitive timeout exceeds the target action-policy time cap",
                target_id=task.target_id,
                task_id=task.id,
            )
        if primitive.side_effect_level in {SideEffectLevel.MUTATING, SideEffectLevel.EXPLOITATIVE}:
            if self.settings.mode in {AutonomyMode.MANUAL, AutonomyMode.ASSISTED}:
                return PolicyDecision(
                    action_kind=primitive.name,
                    verdict=PolicyVerdict.NEEDS_APPROVAL,
                    reason="mutating or exploitative primitive requires approval in the current autonomy mode",
                    target_id=task.target_id,
                    task_id=task.id,
                )
        return None

    def _secrets_available(self, required_secrets: list[str]) -> bool:
        if not required_secrets:
            return True
        if self.credentials_status_loader is None:
            return False
        payload = self.credentials_status_loader()
        services = payload.get("services", {}) if isinstance(payload, dict) else {}
        if not isinstance(services, dict):
            return False
        for secret in required_secrets:
            service_key = self._secret_service_key(secret)
            if service_key is None:
                return False
            service, key = service_key
            entry = services.get(service, {})
            status = entry.get(key, {}) if isinstance(entry, dict) else {}
            if not isinstance(status, dict) or not status.get("configured"):
                return False
        return True

    def _secret_service_key(self, secret: str) -> tuple[str, str] | None:
        if "." in secret:
            service, key = secret.split(".", 1)
            return service, key
        return self.SECRET_FIELD_ALIASES.get(secret)

    def _credential_usage_class(self, required_secrets: list[str]) -> str:
        if not required_secrets:
            return "none"
        if any(secret.startswith("lab.") for secret in required_secrets):
            return "lab"
        if any(secret.startswith("caido.") for secret in required_secrets):
            return "integration"
        return "external_secret"
