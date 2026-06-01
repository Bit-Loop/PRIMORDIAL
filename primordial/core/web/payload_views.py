from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def control_plane_payload(app: Any, *, target: str | None = None, live_metrics: bool = False) -> dict[str, Any]:
    dashboard = app.runtime.dashboard_payload()
    if live_metrics:
        dashboard = dict(dashboard)
        dashboard["system_metrics"] = app.runtime.system_metrics_payload(force_refresh=True)
    work_status = app.work_status_payload()
    scope = app.runtime.scope_payload()
    scope_profiles = app.runtime.scope_profiles_payload()
    audit = app.runtime.audit_payload(limit=50)
    credentials = app.runtime.credentials_payload()
    caido_status = app.runtime.caido_status_payload(check_health=False)
    models = app.runtime.models_payload()
    intent = app.runtime.operator_intent_payload()
    execution_mode = app.runtime.execution_mode_payload()
    runtime_tuning = app.runtime.runtime_tuning_payload()
    storage_status = app.runtime.storage_status_payload()
    findings_context = app.runtime.findings_context_payload(include_guidance=False)
    skills = app.runtime.skills_payload(include_body=False)
    metrics = dashboard.get("system_metrics", {})
    counts = dashboard.get("counts", {}) if isinstance(dashboard.get("counts"), dict) else {}
    all_targets = [item for item in scope.get("targets", []) if app._target_handle(item)]
    selected_target = app._selected_target_filter(target, all_targets)
    targets = app._filter_scope_targets(all_targets, selected_target)
    selected_target_id = app._target_id_for_handle(selected_target, all_targets)
    records = app.runtime.records_payload(limit=100, target_id=selected_target_id)
    task_items = app._tasks_view(dashboard, work_status, targets)
    if selected_target:
        task_items = [item for item in task_items if item.get("target") == selected_target]
    approval_items = app._approvals_view(work_status, task_items)
    event_items = app._events_view(audit)
    notes = app._notes_view(targets, findings_context, credentials, audit)
    interests = app._interests_view(records, targets)
    graph = app._graph_view(targets, records)
    traces = app._traces_view(audit, task_items, selected_target=selected_target)
    geo = app._geo_view(targets, caido_status, models)
    model_rows = app._models_view(models)
    plan = app._plan_view(intent, dashboard, skills, work_status, records)
    runtime = _runtime_payload(app, metrics, counts, work_status, approval_items, execution_mode, runtime_tuning, intent, storage_status)
    return _control_plane_body(
        app,
        runtime=runtime,
        model_rows=model_rows,
        models=models,
        task_items=task_items,
        approval_items=approval_items,
        event_items=event_items,
        targets=targets,
        scope=scope,
        scope_profiles=scope_profiles,
        graph=graph,
        traces=traces,
        selected_target=selected_target,
        all_targets=all_targets,
        geo=geo,
        plan=plan,
        notes=notes,
        interests=interests,
        caido_status=caido_status,
        records=records,
        credentials=credentials,
        storage_status=storage_status,
        audit=audit,
    )


def traces_view(app: Any, audit: dict[str, Any], tasks: list[dict[str, Any]], *, selected_target: str | None = None) -> list[dict[str, Any]]:
    grouped = _group_recent_traces(app, audit, tasks, selected_target=selected_target)
    children = sorted(grouped.values(), key=lambda item: str(item.get("last_at") or ""), reverse=True)[:40]
    if not children:
        children = _task_trace_fallback(app, tasks, selected_target=selected_target)
    active = [item for item in children if item.get("status") == "run"]
    idle_reason = "No active run for selected target." if selected_target else "No active run exists."
    if not children:
        children = [_empty_trace(selected_target, idle_reason)]
    return [_trace_root(active, children, selected_target, idle_reason)]


def _runtime_payload(
    app: Any,
    metrics: dict[str, Any],
    counts: dict[str, Any],
    work_status: dict[str, Any],
    approval_items: list[dict[str, Any]],
    execution_mode: dict[str, Any],
    runtime_tuning: dict[str, Any],
    intent: dict[str, Any],
    storage_status: dict[str, Any],
) -> dict[str, Any]:
    network = metrics.get("network", {}) if isinstance(metrics.get("network"), dict) else {}
    gpu_metrics = metrics.get("gpu", {}) if isinstance(metrics.get("gpu"), dict) else {}
    return {
        "autonomy": str(app.runtime.config.autonomy.mode.value),
        "intent": str(intent.get("active", {}).get("id") or intent.get("default") or "recon_only"),
        "health": str(app.runtime.health_payload().get("status", "ok")).upper(),
        "uptime": "live",
        "cpu": app._metric_ratio(metrics, "cpu"),
        "gpu": app._metric_ratio(metrics, "gpu"),
        "mem": app._memory_ratio(metrics),
        "diskWrites": int(counts.get("events", 0) or 0),
        "netIn": str(network.get("rx_label") or "0 B/s"),
        "netOut": str(network.get("tx_label") or "0 B/s"),
        "gpuMemory": app._gpu_memory_payload(gpu_metrics),
        "activeTasks": int(work_status.get("counts", {}).get("active", 0) or 0),
        "queued": int(work_status.get("counts", {}).get("queued", 0) or 0),
        "approvals": len(approval_items),
        "counts": counts,
        "executionMode": execution_mode,
        "runtimeTuning": runtime_tuning,
        "operatorIntent": intent,
        "workStatus": work_status,
        "systemMetrics": metrics,
        "premiumWrapper": app._premium_wrapper_payload(),
        "storage": storage_status,
    }


def _control_plane_body(app: Any, **payload: Any) -> dict[str, Any]:
    all_targets = payload["all_targets"]
    selected_target = payload["selected_target"]
    return {
        "mode": "real",
        "runtime": payload["runtime"],
        "models": payload["model_rows"],
        "modelPayload": payload["models"],
        "tasks": payload["task_items"],
        "approvals": payload["approval_items"],
        "events": payload["event_items"],
        "scope": app._scope_view(payload["targets"]),
        "scopePayload": payload["scope"],
        "scopeProfiles": payload["scope_profiles"],
        "graph": payload["graph"],
        "traces": payload["traces"],
        "traceMeta": _trace_meta(app, selected_target, all_targets),
        "geo": payload["geo"],
        "plan": payload["plan"],
        "notes": payload["notes"],
        "interests": payload["interests"],
        "caido": app._caido_view(payload["caido_status"], payload["records"], payload["targets"]),
        "approvalChat": app._approval_chat_view(payload["approval_items"]),
        "inquiryChat": app._operator_chat_view(),
        "signals": app._signals_view(payload["audit"]),
        "credentials": payload["credentials"],
        "storage_status": payload["storage_status"],
        "selfTest": {"status": "not_run", "checks": [], "summary": {}},
        "api": _api_payload(),
    }


def _trace_meta(app: Any, selected_target: str | None, all_targets: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "selectedTarget": selected_target or "",
        "targetOptions": [{"id": "", "label": "All targets"}]
        + [{"id": app._target_handle(item), "label": app._target_handle(item)} for item in all_targets],
        "grouped": True,
        "defaultLimit": 40,
    }


def _api_payload() -> dict[str, Any]:
    return {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "endpoints": {
            "controlPlane": "/api/control-plane",
            "tick": "/api/actions/tick",
            "stopWork": "/api/actions/stop-work",
            "compact": "/api/actions/compact",
            "processQueues": "/api/actions/process-queues",
            "warmModels": "/api/actions/warm-models",
            "clearModels": "/api/actions/clear-models",
            "uiCommands": "/api/ui/commands",
            "approvalInquiry": "/api/approvals/inquiry",
            "ragStatus": "/api/rag/status",
            "ragConfig": "/api/rag/config",
            "ragImport": "/api/rag/import",
            "ragSearch": "/api/rag/search",
            "ragSynthesize": "/api/rag/synthesize",
            "ragVulnStatus": "/api/rag/vuln/status",
            "ragVulnSync": "/api/rag/vuln/sync",
            "ragVulnSearch": "/api/rag/vuln/search",
            "ragVulnHints": "/api/rag/vuln/hints",
        },
    }


def _group_recent_traces(
    app: Any,
    audit: dict[str, Any],
    tasks: list[dict[str, Any]],
    *,
    selected_target: str | None,
) -> dict[tuple[str, str, str, str, str], dict[str, Any]]:
    tasks_by_id = {str(item.get("id") or ""): item for item in tasks}
    grouped: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    recent = audit.get("recent_traces", []) if isinstance(audit.get("recent_traces", []), list) else []
    for index, trace in enumerate(recent):
        if isinstance(trace, dict):
            _add_trace_group(app, grouped, tasks_by_id, trace, index, selected_target=selected_target)
    return grouped


def _add_trace_group(
    app: Any,
    grouped: dict[tuple[str, str, str, str, str], dict[str, Any]],
    tasks_by_id: dict[str, dict[str, Any]],
    trace: dict[str, Any],
    index: int,
    *,
    selected_target: str | None,
) -> None:
    metadata = trace.get("metadata", {}) if isinstance(trace.get("metadata"), dict) else {}
    task_id = str(trace.get("task_id") or "")
    task = tasks_by_id.get(task_id, {})
    target = str(metadata.get("target") or task.get("target") or "*")
    if selected_target and target != selected_target:
        return
    item = _trace_item(app, trace, metadata, task, index, target=target, task_id=task_id)
    key = (target, task_id, str(item["kind"]), str(item["summary"]), str(item["status"]))
    if key not in grouped:
        grouped[key] = item
    else:
        _merge_trace_item(app, grouped[key], item, key)


def _trace_item(app: Any, trace: dict[str, Any], metadata: dict[str, Any], task: dict[str, Any], index: int, *, target: str, task_id: str) -> dict[str, Any]:
    status = app._trace_status_for_gui(str(trace.get("status") or "pass"))
    created_at = str(trace.get("created_at") or "")
    trace_id = str(trace.get("id") or f"trace_{index}")
    return {
        "id": trace_id,
        "kind": str(metadata.get("task_type") or metadata.get("summary_key") or metadata.get("stage") or trace.get("role") or "trace"),
        "status": status,
        "time": app._time_label(created_at),
        "summary": str(trace.get("summary") or metadata.get("summary") or "Runtime trace"),
        "task": task_id,
        "target": target,
        "route": str(metadata.get("route") or metadata.get("provider_route") or task.get("route") or ""),
        "model": str(metadata.get("model") or task.get("model") or ""),
        "count": 1,
        "first_at": created_at,
        "last_at": created_at,
        "latest_status": status,
        "repeated": False,
        "representative_id": trace_id,
        "member_ids": [trace_id],
        "inspect_kind": "trace",
        "inspect_id": trace_id,
    }


def _merge_trace_item(app: Any, existing: dict[str, Any], incoming: dict[str, Any], key: tuple[str, str, str, str, str]) -> None:
    existing["count"] = int(existing.get("count", 1) or 1) + 1
    existing["last_at"] = max(str(existing.get("last_at") or ""), str(incoming.get("last_at") or ""))
    existing["time"] = app._time_label(existing["last_at"])
    existing["latest_status"] = incoming["status"]
    existing["repeated"] = True
    members = existing.get("member_ids") if isinstance(existing.get("member_ids"), list) else []
    members.extend(incoming.get("member_ids", []))
    existing["member_ids"] = members
    group_id = app._stable_group_id("trace", key)
    existing["id"] = group_id
    existing["duplicate_group_id"] = group_id
    existing["inspect_kind"] = "group"
    existing["inspect_id"] = group_id


def _task_trace_fallback(app: Any, tasks: list[dict[str, Any]], *, selected_target: str | None) -> list[dict[str, Any]]:
    return [
        {
            "id": f"task_trace_{index}",
            "kind": item.get("kind", "task"),
            "status": app._trace_status_for_gui(item.get("status", "queued")),
            "time": "live",
            "summary": item.get("title", "Task"),
            "task": item.get("id", ""),
            "target": item.get("target", "*"),
            "route": item.get("route", ""),
            "model": item.get("model", ""),
            "count": 1,
            "member_ids": [str(item.get("id") or "")],
            "inspect_kind": "task",
            "inspect_id": str(item.get("id") or ""),
        }
        for index, item in enumerate(tasks[:16])
        if not selected_target or item.get("target") == selected_target
    ]


def _empty_trace(selected_target: str | None, idle_reason: str) -> dict[str, Any]:
    return {
        "id": "trace_empty",
        "kind": "workflow.idle",
        "status": "queued",
        "time": "idle",
        "summary": idle_reason,
        "task": "",
        "target": selected_target or "*",
        "route": "",
        "model": "",
        "count": 1,
    }


def _trace_root(active: list[dict[str, Any]], children: list[dict[str, Any]], selected_target: str | None, idle_reason: str) -> dict[str, Any]:
    return {
        "id": "tr_root",
        "kind": "workflow.runtime",
        "status": "run" if active else "queued",
        "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
        "summary": f"Active runtime trace: {len(active)} running" if active else f"Idle/stale: {idle_reason}",
        "route": "",
        "model": "",
        "target": selected_target or "*",
        "active": bool(active),
        "idle_reason": None if active else idle_reason,
        "inspect_kind": "group",
        "inspect_id": "tr_root",
        "children": children,
    }
