from __future__ import annotations

from typing import Callable

from primordial.core.config import AutonomySettings
from primordial.core.domain.enums import (
    AgentRole,
    AutonomyMode,
    MethodologyPhase,
    PolicyVerdict,
    ProviderRoute,
    RiskTier,
    ScopeProfile,
    SideEffectLevel,
    TaskKind,
)
from primordial.core.domain.models import PolicyDecision, PrimitiveManifest, Target, Task


SECRET_FIELD_ALIASES = {
    "DISCORD_WEBHOOK_URL": ("discord", "webhook_url"),
    "NOTION_API_KEY": ("notion", "api_key"),
    "NOTION_PARENT_PAGE_ID": ("notion", "parent_page_id"),
    "NOTION_VERSION": ("notion", "version"),
    "PRIMORDIAL_CAIDO_GRAPHQL_URL": ("caido", "graphql_url"),
    "PRIMORDIAL_CAIDO_API_TOKEN": ("caido", "api_token"),
}


def evaluate_remote_premium_task(
    settings: AutonomySettings,
    task: Task,
    local_wrapper: bool,
    daily_remote_cost_loader: Callable[[], float] | None,
) -> PolicyDecision | None:
    if task.provider_route != ProviderRoute.REMOTE_PREMIUM or local_wrapper:
        return None
    if not settings.allow_remote_premium:
        approval_gate = evaluate_remote_premium_approval_gate(task)
        if approval_gate is not None:
            return approval_gate
    if daily_remote_cost_loader is None:
        return None
    try:
        daily_spent = float(daily_remote_cost_loader())
    except Exception as exc:  # noqa: BLE001 - remote spend uncertainty must fail closed
        return PolicyDecision(
            action_kind=task.kind.value,
            verdict=PolicyVerdict.DENY,
            reason="daily remote budget could not be read from the cost ledger",
            target_id=task.target_id,
            task_id=task.id,
            metadata={"error": str(exc), "daily_budget_usd": settings.daily_remote_budget},
        )
    return evaluate_remote_premium_budget(settings, task, daily_spent)


def evaluate_remote_premium_approval_gate(task: Task) -> PolicyDecision | None:
    approval_required = (
        task.kind == TaskKind.REVIEW_PREMIUM_ESCALATION
        and task.metadata.get("remote_premium_policy_approval_required")
    )
    if approval_required and not task.metadata.get("remote_premium_operator_approved"):
        return PolicyDecision(
            action_kind=task.kind.value,
            verdict=PolicyVerdict.NEEDS_APPROVAL,
            reason="remote premium provider use is disabled by policy and requires explicit operator approval",
            target_id=task.target_id,
            task_id=task.id,
            metadata={"remote_premium_policy_approval_required": True},
        )
    if approval_required and task.metadata.get("remote_premium_operator_approved"):
        return None
    return PolicyDecision(
        action_kind=task.kind.value,
        verdict=PolicyVerdict.DENY,
        reason="remote premium provider use is disabled by policy",
        target_id=task.target_id,
        task_id=task.id,
    )


def evaluate_remote_premium_budget(
    settings: AutonomySettings,
    task: Task,
    daily_spent: float,
) -> PolicyDecision | None:
    estimated_cost = estimated_remote_cost(task)
    if daily_spent < settings.daily_remote_budget and daily_spent + estimated_cost <= settings.daily_remote_budget:
        return None
    return PolicyDecision(
        action_kind=task.kind.value,
        verdict=PolicyVerdict.DENY,
        reason=(
            "daily remote budget exhausted: "
            f"${daily_spent:.2f} spent + ${estimated_cost:.2f} estimated > "
            f"${settings.daily_remote_budget:.2f}"
        ),
        target_id=task.target_id,
        task_id=task.id,
        metadata={
            "daily_spent_usd": daily_spent,
            "estimated_task_cost_usd": estimated_cost,
            "daily_budget_usd": settings.daily_remote_budget,
        },
    )


def evaluate_high_risk_task(
    settings: AutonomySettings,
    task: Task,
    target: Target | None,
    action_policy: dict[str, object],
) -> PolicyDecision | None:
    risky_phase = task.phase in {MethodologyPhase.EXPLOITATION, MethodologyPhase.CHAINING}
    high_risk = task.risk_tier in {RiskTier.HIGH, RiskTier.CRITICAL}
    if not (risky_phase or high_risk):
        return None
    if not settings.allow_exploitative_actions:
        return PolicyDecision(
            action_kind=task.kind.value,
            verdict=PolicyVerdict.NEEDS_APPROVAL,
            reason="exploitative or high-risk task requires approval because exploitative actions are disabled",
            target_id=task.target_id,
            task_id=task.id,
            metadata={"mode": settings.mode.value, "action_policy": action_policy},
        )
    agent_gate = evaluate_agent_safety_gate(settings, task, target)
    if agent_gate is not None:
        agent_gate.metadata.setdefault("action_policy", action_policy)
        return agent_gate
    return PolicyDecision(
        action_kind=task.kind.value,
        verdict=PolicyVerdict.NEEDS_APPROVAL,
        reason="task is gated by autonomy mode, risk policy, or missing agent safety approval",
        target_id=task.target_id,
        task_id=task.id,
        metadata={"mode": settings.mode.value, "action_policy": action_policy},
    )


def evaluate_agent_safety_gate(
    settings: AutonomySettings,
    task: Task,
    target: Target | None,
) -> PolicyDecision | None:
    if not _can_consider_agent_safety(settings, target):
        return None
    approval = task.metadata.get("agent_safety_approval")
    if not isinstance(approval, dict):
        return None
    reviewer = str(approval.get("reviewer_agent", ""))
    if reviewer not in settings.approved_reviewer_agents:
        return None
    checks = _agent_safety_checks(approval, task)
    bounds = _agent_safety_bounds(settings, approval)
    if bounds is None:
        return None
    timeout_seconds, max_requests = bounds
    checks["timeout_bounded"] = timeout_seconds <= settings.max_poc_timeout_seconds
    checks["request_bounded"] = max_requests <= settings.max_poc_requests
    if not all(checks.values()):
        return None
    if settings.mode == AutonomyMode.SUPERVISED_AUTO and task.metadata.get("operator_approved") is not True:
        return _supervised_auto_agent_safety_gate(settings, task, reviewer, checks, bounds)
    return PolicyDecision(
        action_kind=task.kind.value,
        verdict=PolicyVerdict.ALLOW,
        reason="task allowed by explicit agent safety approval and bounded non-DoS execution policy",
        target_id=task.target_id,
        task_id=task.id,
        metadata={
            "mode": settings.mode.value,
            "approval_source": reviewer,
            "safety_checks": checks,
            "timeout_seconds": timeout_seconds,
            "max_requests": max_requests,
        },
    )


def estimated_remote_cost(task: Task) -> float:
    raw = task.metadata.get("estimated_remote_cost_usd", 0.0)
    try:
        return max(0.0, float(raw))
    except (TypeError, ValueError):
        return 0.0


def uses_local_chat_wrapper(task: Task) -> bool:
    return (
        task.provider_route == ProviderRoute.REMOTE_PREMIUM
        and task.kind == TaskKind.REVIEW_PREMIUM_ESCALATION
        and task.role == AgentRole.CLAUDE_REVIEWER
        and task.metadata.get("local_chat_wrapper") == "agent_chat_api"
        and task.metadata.get("remote_premium_local_wrapper") is True
    )


def task_action_policy(
    settings: AutonomySettings,
    task: Task,
    target: Target | None,
) -> dict[str, object]:
    risky = task.phase in {MethodologyPhase.EXPLOITATION, MethodologyPhase.CHAINING} or task.risk_tier in {
        RiskTier.HIGH,
        RiskTier.CRITICAL,
    }
    target_metadata = target.metadata if target else {}
    default_timeout = settings.max_poc_timeout_seconds if risky else max(180, settings.max_poc_timeout_seconds)
    default_requests = settings.max_poc_requests if risky else max(25, settings.max_poc_requests)
    default_concurrency = settings.high_risk_concurrency if risky else settings.hot_path_concurrency
    return _action_policy_payload(
        task,
        target,
        target_metadata,
        default_timeout,
        default_requests,
        default_concurrency,
        risky,
    )


def primitive_action_policy(
    settings: AutonomySettings,
    task: Task,
    target: Target | None,
    primitive: PrimitiveManifest,
) -> dict[str, object]:
    task_policy = task_action_policy(settings, task, target)
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
        "credential_usage_class": credential_usage_class(primitive.required_secrets),
        "required_secrets": list(primitive.required_secrets),
    }


def evaluate_task_bounds(
    settings: AutonomySettings,
    task: Task,
    action_policy: dict[str, object],
) -> PolicyDecision | None:
    timeout_seconds = int(action_policy["time_cap_seconds"])
    request_cap = int(action_policy["request_cap"])
    if timeout_seconds <= 0 or request_cap <= 0:
        return _task_bounds_decision(task, PolicyVerdict.DENY, "task action-policy bounds are invalid")
    if task.risk_tier in {RiskTier.HIGH, RiskTier.CRITICAL} and timeout_seconds > settings.max_poc_timeout_seconds:
        return _task_bounds_decision(task, PolicyVerdict.NEEDS_APPROVAL, "task exceeds the configured high-risk timeout ceiling")
    if task.risk_tier in {RiskTier.HIGH, RiskTier.CRITICAL} and request_cap > settings.max_poc_requests:
        return _task_bounds_decision(task, PolicyVerdict.NEEDS_APPROVAL, "task exceeds the configured high-risk request ceiling")
    return None


def evaluate_primitive_bounds(
    settings: AutonomySettings,
    credentials_status_loader: Callable[[], dict[str, object]] | None,
    task: Task,
    primitive: PrimitiveManifest,
    action_policy: dict[str, object],
) -> PolicyDecision | None:
    if primitive.required_secrets and not secrets_available(credentials_status_loader, list(primitive.required_secrets)):
        return _primitive_bounds_decision(
            task,
            primitive,
            "primitive requires credentials or integration secrets that are not configured",
        )
    if primitive_timeout_exceeds_policy(task, primitive, action_policy):
        return _primitive_bounds_decision(task, primitive, "primitive timeout exceeds the target action-policy time cap")
    if primitive.side_effect_level in {SideEffectLevel.MUTATING, SideEffectLevel.EXPLOITATIVE}:
        if settings.mode in {AutonomyMode.MANUAL, AutonomyMode.ASSISTED}:
            return _primitive_bounds_decision(
                task,
                primitive,
                "mutating or exploitative primitive requires approval in the current autonomy mode",
            )
    return None


def primitive_timeout_exceeds_policy(
    task: Task,
    primitive: PrimitiveManifest,
    action_policy: dict[str, object],
) -> bool:
    if primitive.timeout_seconds <= int(action_policy["time_cap_seconds"]):
        return False
    return (
        bool(action_policy.get("explicit_time_cap"))
        or task.risk_tier in {RiskTier.HIGH, RiskTier.CRITICAL}
        or primitive.side_effect_level in {SideEffectLevel.MUTATING, SideEffectLevel.EXPLOITATIVE}
    )


def secrets_available(
    credentials_status_loader: Callable[[], dict[str, object]] | None,
    required_secrets: list[str],
) -> bool:
    if not required_secrets:
        return True
    if credentials_status_loader is None:
        return False
    payload = credentials_status_loader()
    services = payload.get("services", {}) if isinstance(payload, dict) else {}
    if not isinstance(services, dict):
        return False
    return all(secret_configured(services, secret) for secret in required_secrets)


def secret_configured(services: dict[object, object], secret: str) -> bool:
    service_key = secret_service_key(secret)
    if service_key is None:
        return False
    service, key = service_key
    entry = services.get(service, {})
    status = entry.get(key, {}) if isinstance(entry, dict) else {}
    return isinstance(status, dict) and bool(status.get("configured"))


def secret_service_key(secret: str) -> tuple[str, str] | None:
    if "." in secret:
        service, key = secret.split(".", 1)
        return service, key
    return SECRET_FIELD_ALIASES.get(secret)


def credential_usage_class(required_secrets: list[str]) -> str:
    if not required_secrets:
        return "none"
    if any(secret.startswith("lab.") for secret in required_secrets):
        return "lab"
    if any(secret.startswith("caido.") for secret in required_secrets):
        return "integration"
    return "external_secret"


def _can_consider_agent_safety(settings: AutonomySettings, target: Target | None) -> bool:
    if not settings.allow_agent_safety_approval:
        return False
    if settings.mode not in {AutonomyMode.SUPERVISED_AUTO, AutonomyMode.HIGH_AUTONOMY}:
        return False
    if target is None:
        return False
    return target.profile != ScopeProfile.HACKERONE or bool(target.metadata.get("allow_agent_poc_execution"))


def _agent_safety_checks(approval: dict[object, object], task: Task) -> dict[str, bool]:
    return {
        "approved": approval.get("approved") is True,
        "scope_verified": approval.get("scope_verified") is True,
        "bounded_execution": approval.get("bounded_execution") is True,
        "dos_risk_false": approval.get("dos_risk") is False,
        "ddos_risk_false": approval.get("ddos_risk") is False,
        "evidence_linked": bool(approval.get("evidence_refs") or task.evidence_refs),
    }


def _agent_safety_bounds(settings: AutonomySettings, approval: dict[object, object]) -> tuple[int, int] | None:
    try:
        timeout_seconds = int(approval.get("timeout_seconds", 0))
        max_requests = int(approval.get("max_requests", 0))
    except (TypeError, ValueError):
        return None
    if timeout_seconds <= 0 or max_requests <= 0:
        return None
    return timeout_seconds, max_requests


def _supervised_auto_agent_safety_gate(
    settings: AutonomySettings,
    task: Task,
    reviewer: str,
    checks: dict[str, bool],
    bounds: tuple[int, int],
) -> PolicyDecision:
    timeout_seconds, max_requests = bounds
    return PolicyDecision(
        action_kind=task.kind.value,
        verdict=PolicyVerdict.NEEDS_APPROVAL,
        reason="supervised-auto exploitative or high-risk task requires operator approval in addition to agent safety approval",
        target_id=task.target_id,
        task_id=task.id,
        metadata={
            "mode": settings.mode.value,
            "approval_source": reviewer,
            "safety_checks": checks,
            "timeout_seconds": timeout_seconds,
            "max_requests": max_requests,
            "operator_approval_required": True,
        },
    )


def _action_policy_payload(
    task: Task,
    target: Target | None,
    target_metadata: dict[str, object],
    default_timeout: int,
    default_requests: int,
    default_concurrency: int,
    risky: bool,
) -> dict[str, object]:
    explicit_time_cap = "timeout_seconds" in task.metadata or "policy_timeout_seconds" in target_metadata
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


def _task_bounds_decision(task: Task, verdict: PolicyVerdict, reason: str) -> PolicyDecision:
    return PolicyDecision(
        action_kind=task.kind.value,
        verdict=verdict,
        reason=reason,
        target_id=task.target_id,
        task_id=task.id,
    )


def _primitive_bounds_decision(task: Task, primitive: PrimitiveManifest, reason: str) -> PolicyDecision:
    return PolicyDecision(
        action_kind=primitive.name,
        verdict=PolicyVerdict.NEEDS_APPROVAL,
        reason=reason,
        target_id=task.target_id,
        task_id=task.id,
    )
