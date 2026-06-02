from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from primordial.core.domain.enums import TaskRunStatus, TaskStatus
from primordial.core.domain.models import Target, json_ready, utc_now
from primordial.core.evidence import classify_credentialed_access_surface


ACTIVE_RUN_STATUSES = {TaskRunStatus.CLAIMED, TaskRunStatus.RUNNING}
WAITING_TASK_STATUSES = {TaskStatus.WAITING, TaskStatus.NEEDS_APPROVAL}


def build_work_status_payload(
    *,
    tasks: list[Any],
    runs: list[Any],
    targets: dict[str, Target],
    mode: dict[str, object],
    blockers: list[dict[str, object]],
    live_methodology_state: Callable[[Target], dict[str, object] | None],
    limit: int,
) -> dict[str, object]:
    tasks_by_id = {task.id: task for task in tasks}
    active_runs = [run for run in runs if _is_active_run(run)][:limit]
    active_run_task_ids = {run.task_id for run in active_runs}
    running_tasks = [
        task for task in tasks if task.status == TaskStatus.RUNNING and task.id not in active_run_task_ids
    ][:limit]
    queued_tasks = [task for task in tasks if task.status == TaskStatus.PENDING][:limit]
    waiting_tasks = [task for task in tasks if task.status in WAITING_TASK_STATUSES][:limit]
    recent_runs = [run for run in runs if not _is_active_run(run)][:limit]
    active_items = [_run_payload(run, tasks_by_id, targets) for run in active_runs]
    active_items += [_task_payload(task, targets) for task in running_tasks]
    queued_items = [_task_payload(task, targets) for task in queued_tasks]
    waiting_items = [_task_payload(task, targets) for task in waiting_tasks]
    recent_items = [_run_payload(run, tasks_by_id, targets) for run in recent_runs]
    target_states = _target_states_payload(targets.values(), live_methodology_state)
    return {
        "summary": _summary(active_items, queued_items, waiting_items, target_states, blockers, mode),
        "is_busy": bool(active_items),
        "updated_at": utc_now().isoformat(),
        "execution_mode": mode,
        "counts": _counts(tasks, active_items),
        "active": active_items,
        "queued": queued_items,
        "waiting": waiting_items,
        "recent": recent_items,
        "blockers": blockers,
        "target_states": target_states,
    }


def work_status_capabilities(primitives: Iterable[Any]) -> set[str]:
    return {
        tag.lower()
        for primitive in primitives
        for tag in [primitive.name, *primitive.capability_tags]
    }


def current_generation_evidence(
    evidence: Iterable[Any],
    active_generation: str | None,
    matches_generation: Callable[[Any, str | None], bool],
) -> list[Any]:
    return [item for item in evidence if matches_generation(item, active_generation)]


def stale_recon_blocker(target: Target, evidence: Iterable[Any]) -> dict[str, object] | None:
    active_ip = target.metadata.get("active_ip")
    if not active_ip:
        return None
    active_generation = str(target.metadata.get("active_ip_generation", ""))
    has_current_recon = any(
        item.metadata.get("kind") == "tcp_service_discovery"
        and str(item.metadata.get("active_ip_generation", "")) == active_generation
        for item in evidence
    )
    if not active_generation or has_current_recon:
        return None
    return {
        "target": target.handle,
        "kind": "stale_recon",
        "summary": (
            f"`{target.handle}` active IP changed to `{active_ip}`; "
            "fresh service discovery has not completed yet."
        ),
    }


def poc_validation_blocker(
    target: Target,
    evidence: Iterable[Any],
    interests: Iterable[Any],
    capabilities: set[str],
    poc_adaptation_available: Callable[[set[str]], bool],
    intent_policy: Any | None = None,
) -> dict[str, object] | None:
    evidence_items = list(evidence)
    interest_items = list(interests)
    if not _has_poc_candidates(evidence_items, interest_items) or _has_poc_validation(evidence_items):
        return None
    if poc_adaptation_available(capabilities):
        if intent_policy is not None and not bool(getattr(intent_policy, "poc_applicability_validation", False)):
            return {
                "target": target.handle,
                "kind": "operator_intent_blocks_poc_validation",
                "summary": (
                    f"`{target.handle}` has public PoC candidates, but the active operator intent "
                    "does not allow PoC applicability validation."
                ),
            }
        return {
            "target": target.handle,
            "kind": "runnable_poc_validation",
            "summary": f"`{target.handle}` has public PoC candidates waiting for gated applicability validation.",
        }
    return {
        "target": target.handle,
        "kind": "missing_poc_validation_primitive",
        "summary": f"`{target.handle}` has PoC candidates but no PoC applicability primitive is registered.",
    }


def credentialed_access_blocker(
    target: Target,
    current_evidence: Iterable[Any],
    capabilities: set[str],
    lab_credentials_configured: bool,
    has_any_capability: Callable[..., bool],
    intent_policy: Any | None = None,
) -> dict[str, object] | None:
    has_credentialed_capability = has_any_capability(
        capabilities,
        "credentialed-access-check",
        "smb-session",
        "winrm",
    )
    credential_surface = classify_credentialed_access_surface(current_evidence)
    if not has_credentialed_capability or lab_credentials_configured or not credential_surface.eligible:
        return None
    credential_policy = getattr(intent_policy, "credential_policy", None)
    if credential_policy is not None and not bool(getattr(credential_policy, "credential_validation_allowed", False)):
        return {
            "target": target.handle,
            "kind": "operator_intent_blocks_credential_validation",
            "summary": (
                f"`{target.handle}` has evidence-supported Windows SMB/WinRM services, "
                "but the active operator intent does not allow credential validation."
            ),
        }
    return {
        "target": target.handle,
        "kind": "missing_known_credentials",
        "summary": (
            f"`{target.handle}` has evidence-supported Windows SMB/WinRM services, "
            "but known username/password are not configured."
        ),
    }


def missing_verified_path_blocker(
    target: Target,
    findings: Iterable[Any],
    evidence: Iterable[Any],
) -> dict[str, object] | None:
    if any(findings) or not any(evidence):
        return None
    return {
        "target": target.handle,
        "kind": "no_verified_path",
        "summary": f"`{target.handle}` has evidence, but no verified finding or runnable exploit path yet.",
    }


def _is_active_run(run: Any) -> bool:
    return run.status in ACTIVE_RUN_STATUSES and run.finished_at is None


def _target_label(targets: dict[str, Target], target_id: str | None) -> str | None:
    if not target_id:
        return None
    target = targets.get(target_id)
    return target.handle if target else target_id


def _task_payload(task: Any, targets: dict[str, Target]) -> dict[str, object]:
    return {
        "kind": "task",
        "task_id": task.id,
        "task_kind": task.kind.value,
        "title": task.title,
        "summary": task.summary,
        "status": task.status.value,
        "agent": task.role.value,
        "route": task.provider_route.value if task.provider_route else None,
        "model": task.provider_model,
        "worker_contract": task.metadata.get("worker_contract"),
        "target": _target_label(targets, task.target_id),
        "metadata": json_ready(task.metadata),
        "active_ip_generation": task.metadata.get("active_ip_generation"),
        "invalid_target": bool(task.metadata.get("invalid_target")),
        "updated_at": task.updated_at.isoformat(),
    }


def _run_payload(run: Any, tasks_by_id: dict[str, Any], targets: dict[str, Target]) -> dict[str, object]:
    task = tasks_by_id.get(run.task_id)
    metadata = task.metadata if task else {}
    return {
        "kind": "run",
        "run_id": run.id,
        "task_id": run.task_id,
        "task_kind": task.kind.value if task else None,
        "title": task.title if task else run.trace_summary,
        "summary": run.trace_summary,
        "status": run.status.value,
        "agent": run.role.value,
        "route": run.provider_route.value,
        "model": run.model_name,
        "worker_contract": run.metadata.get("worker_contract"),
        "suitability_score": run.metadata.get("suitability_score"),
        "target": _target_label(targets, task.target_id if task else None),
        "metadata": json_ready(metadata),
        "active_ip_generation": metadata.get("active_ip_generation"),
        "invalid_target": bool(metadata.get("invalid_target")),
        "started_at": run.started_at.isoformat(),
        "heartbeat_at": run.heartbeat_at.isoformat() if run.heartbeat_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "error": run.error,
    }


def _target_states_payload(
    targets: Iterable[Target],
    live_methodology_state: Callable[[Target], dict[str, object] | None],
) -> list[dict[str, object]]:
    target_states = []
    for target in targets:
        state = live_methodology_state(target)
        if not state:
            continue
        target_states.append(
            {
                "target": target.handle,
                "phase": state.get("phase"),
                "subphase": state.get("subphase"),
                "completion": state.get("completion"),
                "transition_reason": state.get("transition_reason"),
                "next_unblock_action": state.get("next_unblock_action"),
                "no_progress_reason": state.get("no_progress_reason"),
                "candidate_actions": state.get("candidate_actions", []),
            }
        )
    return target_states


def _summary(
    active_items: list[dict[str, object]],
    queued_items: list[dict[str, object]],
    waiting_items: list[dict[str, object]],
    target_states: list[dict[str, object]],
    blockers: list[dict[str, object]],
    mode: dict[str, object],
) -> str:
    if active_items:
        return f"Working on {len(active_items)} active item(s)."
    if queued_items:
        return f"Idle between executions; {len(queued_items)} task(s) are queued."
    if waiting_items:
        return f"Blocked or waiting; {len(waiting_items)} task(s) need approval or resume."
    if target_states and target_states[0].get("no_progress_reason"):
        return "Idle/stalled: " + str(target_states[0]["no_progress_reason"])
    if blockers:
        return "Idle/stalled: " + str(blockers[0]["summary"])
    if mode["mode"] == "continuous":
        return f"Continuous mode is enabled; waiting for the next {mode['interval_seconds']}s tick."
    return "Idle; no active, queued, or waiting work is currently visible."


def _counts(tasks: list[Any], active_items: list[dict[str, object]]) -> dict[str, int]:
    return {
        "active": len(active_items),
        "queued": len([task for task in tasks if task.status == TaskStatus.PENDING]),
        "waiting": len([task for task in tasks if task.status in WAITING_TASK_STATUSES]),
    }


def _has_poc_candidates(evidence: Iterable[Any], interests: Iterable[Any]) -> bool:
    return any(
        item.metadata.get("kind") == "exploit_research"
        and int(item.metadata.get("match_count", 0) or 0) > 0
        for item in evidence
    ) or any(item.metadata.get("class") == "exploit_research" for item in interests)


def _has_poc_validation(evidence: Iterable[Any]) -> bool:
    return any(item.metadata.get("kind") == "poc_applicability_validation" for item in evidence)
