from __future__ import annotations

from typing import Any
from urllib.parse import unquote

from primordial.core.domain.enums import ScopeProfile


def dispatch_control_routes(
    app: Any,
    method: str,
    path: str,
    query: dict[str, list[str]],
    body: bytes,
) -> Any | None:
    for handler in (
        _context_routes,
        _caido_routes,
        _read_model_and_status_routes,
        _action_routes,
        _runtime_setting_routes,
        _approval_credential_chat_routes,
        _target_scope_routes,
    ):
        response = handler(app, method, path, query, body)
        if response is not None:
            return response
    return None


def _context_routes(app: Any, method: str, path: str, query: dict[str, list[str]], body: bytes) -> Any | None:
    if method == "GET" and path == "/api/skills":
        include_body = app._bool_param(query, "include_body", False)
        with app._lock:
            return app._json_response(app.runtime.skills_payload(include_body=include_body))
    if method == "GET" and path == "/api/findings-context":
        target = app._optional_query_string(query, "target")
        include_guidance = app._bool_param(query, "include_guidance", True)
        with app._lock:
            try:
                return app._json_response(app.runtime.findings_context_payload(target=target, include_guidance=include_guidance))
            except ValueError as exc:
                return app._json_response({"error": str(exc)}, status=404)
    if method == "POST" and path == "/api/findings-context/guidance":
        payload = app._parse_json_body(body)
        target = str(payload.get("target", "")).strip()
        guidance = str(payload.get("guidance", ""))
        if not target:
            return app._json_response({"error": "target is required"}, status=400)
        with app._lock:
            try:
                outcome = app.runtime.update_target_guidance(target, guidance)
                return app._action_response("update-target-guidance", {"findings_context": outcome})
            except ValueError as exc:
                return app._json_response({"error": str(exc)}, status=404)
    return None


def _caido_routes(app: Any, method: str, path: str, query: dict[str, list[str]], body: bytes) -> Any | None:
    if method == "GET" and path == "/api/integrations/caido":
        check_health = app._bool_param(query, "check_health", False)
        return app._json_response(app.runtime.caido_status_payload(check_health=check_health))
    if method == "POST" and path == "/api/integrations/caido/search":
        return _caido_search_route(app, body)
    if method == "GET" and path.startswith("/api/integrations/caido/requests/"):
        request_id = unquote(path.rsplit("/", 1)[-1])
        with app._lock:
            result = app.runtime.caido_request_detail(request_id)
            return app._json_response(result, status=200 if result.get("ok") else 502)
    if method == "POST" and path == "/api/integrations/caido/import":
        return _caido_import_route(app, body)
    if method == "POST" and path == "/api/integrations/caido/replay/draft":
        return _caido_replay_route(app, body, send=False)
    if method == "POST" and path == "/api/integrations/caido/replay/send":
        return _caido_replay_route(app, body, send=True)
    return None


def _caido_search_route(app: Any, body: bytes) -> Any:
    payload = app._parse_json_body(body)
    with app._lock:
        try:
            result = app.runtime.caido_search_requests(
                target=app._optional_string(payload, "target"),
                httpql=app._optional_string(payload, "httpql"),
                limit=app._optional_int(payload, "limit") or 50,
                offset=app._optional_int(payload, "offset") or 0,
            )
            return app._json_response(result, status=200 if result.get("ok") else 502)
        except ValueError as exc:
            return app._json_response({"ok": False, "error": str(exc)}, status=400)


def _caido_import_route(app: Any, body: bytes) -> Any:
    payload = app._parse_json_body(body)
    request_ids = payload.get("request_ids", [])
    if not isinstance(request_ids, list):
        return app._json_response({"ok": False, "error": "request_ids must be a list"}, status=400)
    target = str(payload.get("target", "")).strip()
    if not target:
        return app._json_response({"ok": False, "error": "target is required"}, status=400)
    with app._lock:
        try:
            return app._action_response(
                "caido-import",
                app.runtime.caido_import_requests(target=target, request_ids=[str(item) for item in request_ids], httpql=str(payload.get("httpql") or "")),
            )
        except ValueError as exc:
            return app._json_response({"ok": False, "error": str(exc)}, status=400)


def _caido_replay_route(app: Any, body: bytes, *, send: bool) -> Any:
    payload = app._parse_json_body(body)
    target = str(payload.get("target", "")).strip()
    raw_request = str(payload.get("raw_request") or "")
    if not target:
        return app._json_response({"ok": False, "error": "target is required"}, status=400)
    with app._lock:
        try:
            if not send:
                result = app.runtime.caido_replay_draft(target=target, raw_request=raw_request)
            else:
                result = app.runtime.caido_replay_send(
                    target=target,
                    raw_request=raw_request,
                    confirmation=app._optional_string(payload, "confirmation"),
                    session_id=app._optional_string(payload, "session_id"),
                )
            if result.get("ok") and send:
                return app._action_response("caido-replay-send", result)
            return app._json_response(result, status=200 if result.get("ok") else 502)
        except ValueError as exc:
            return app._json_response({"ok": False, "error": str(exc)}, status=400)


def _read_model_and_status_routes(app: Any, method: str, path: str, query: dict[str, list[str]], body: bytes) -> Any | None:
    if method == "GET" and path == "/api/models":
        return app._json_response(app.runtime.models_payload())
    if method == "GET" and path == "/api/chat":
        limit = app._int_param(query, "limit", 20)
        target = app._optional_query_string(query, "target")
        with app._lock:
            return app._json_response(app.runtime.operator_chat_payload(limit=limit, target=target))
    simple_getters = {
        "/api/dashboard": app._dashboard_payload,
        "/api/work-status": app.work_status_payload,
        "/api/execution-mode": app.runtime.execution_mode_payload,
        "/api/runtime-settings": app.runtime.runtime_tuning_payload,
        "/api/scope": app.runtime.scope_payload,
        "/api/scope-profiles": app.runtime.scope_profiles_payload,
        "/api/targets": app.runtime.scope_payload,
    }
    if method == "GET" and path in simple_getters:
        return app._json_response(simple_getters[path]())
    if method == "GET" and path == "/api/audit":
        return app._json_response(app.runtime.audit_payload(limit=app._int_param(query, "limit", 25)))
    if method == "GET" and path == "/api/records":
        target_id = app._optional_query_string(query, "target_id")
        return app._json_response(app.runtime.records_payload(limit=app._int_param(query, "limit", 25), target_id=target_id))
    if method == "GET" and path.startswith("/api/tasks/"):
        return _task_audit_route(app, path, query)
    return None


def _task_audit_route(app: Any, path: str, query: dict[str, list[str]]) -> Any:
    task_id = path.rsplit("/", 1)[-1]
    with app._lock:
        payload = app.runtime.task_audit_payload(task_id, limit=app._int_param(query, "limit", 25))
    if payload is None:
        return app._json_response({"error": "task not found"}, status=404)
    return app._json_response(payload)


def _action_routes(app: Any, method: str, path: str, query: dict[str, list[str]], body: bytes) -> Any | None:
    if method != "POST":
        return None
    if path == "/api/actions/tick":
        payload = app._parse_json_body(body)
        return app._run_tracked_action("Run orchestration tick", "tick", lambda: app._tick_action(int(payload.get("max_executions", 3))))
    tracked = {
        "/api/actions/compact": ("Compact memory", "compact", lambda: {"memory_entries_created": app.runtime.compact_memory()}),
        "/api/actions/process-queues": ("Process external queues", "process-queues", app.runtime.process_external_queues),
        "/api/actions/sync-findings-context": ("Sync findings context", "sync-findings-context", app.runtime.sync_findings_context_exports),
        "/api/actions/clear-models": ("Clear Ollama model lanes", "clear-models", app.runtime.clear_model_routes),
        "/api/actions/stop-work": ("Stop active work", "stop-work", app.runtime.stop_active_work),
    }
    if path in tracked:
        label, action, worker = tracked[path]
        return app._run_tracked_action(label, action, worker)
    if path == "/api/actions/warm-models":
        payload = app._parse_json_body(body)
        keep_alive = str(payload.get("keep_alive", "8h")).strip() or "8h"
        return app._run_tracked_action("Warm Ollama model lanes", "warm-models", lambda: app.runtime.warm_model_routes(keep_alive=keep_alive))
    if path == "/api/actions/clear-stale-web-actions":
        payload = app._parse_json_body(body)
        max_age_seconds = app._optional_int(payload, "max_age_seconds") or app.STALE_WEB_ACTION_SECONDS
        cleared = app._clear_stale_actions(max_age_seconds=max_age_seconds)
        return app._action_response("clear-stale-web-actions", {"cleared": cleared, "max_age_seconds": max_age_seconds})
    if path == "/api/ui/commands":
        return _ui_command_route(app, body)
    return None


def _ui_command_route(app: Any, body: bytes) -> Any:
    payload = app._parse_json_body(body)
    command = str(payload.get("command", "")).strip()
    if not command:
        return app._json_response({"error": "command is required"}, status=400)
    with app._lock:
        try:
            outcome = app.runtime.create_ui_command_proposal(command, payload)
        except ValueError as exc:
            return app._json_response({"error": str(exc)}, status=400)
        return app._action_response("ui-command-proposal", outcome)


def _runtime_setting_routes(app: Any, method: str, path: str, query: dict[str, list[str]], body: bytes) -> Any | None:
    if method == "POST" and path == "/api/execution-mode":
        payload = app._parse_json_body(body)
        try:
            interval = payload.get("interval_seconds")
            outcome = app.runtime.update_execution_mode(str(payload.get("mode", "")).strip(), interval_seconds=int(interval) if interval is not None else None)
            return app._action_response("execution-mode", {"execution_mode": outcome})
        except (TypeError, ValueError) as exc:
            return app._json_response({"error": str(exc)}, status=400)
    if method == "POST" and path == "/api/runtime-settings":
        return _runtime_settings_route(app, body)
    if method == "POST" and path == "/api/operator-intent":
        return _operator_intent_route(app, body)
    if method == "POST" and path == "/api/runtime-control":
        return _runtime_control_route(app, body)
    if method == "POST" and path == "/api/models":
        return _update_models_route(app, body)
    return None


def _runtime_settings_route(app: Any, body: bytes) -> Any:
    payload = app._parse_json_body(body)
    try:
        outcome = app.runtime.update_runtime_tuning(
            gpu_ai_timeout_seconds=app._optional_int(payload, "gpu_ai_timeout_seconds"),
            cpu_ai_timeout_seconds=app._optional_int(payload, "cpu_ai_timeout_seconds"),
            stale_run_timeout_seconds=app._optional_int(payload, "stale_run_timeout_seconds"),
            min_free_cpu_ram_mb=app._optional_int(payload, "min_free_cpu_ram_mb"),
            min_free_gpu_ram_mb=app._optional_int(payload, "min_free_gpu_ram_mb"),
        )
        return app._action_response("runtime-settings", {"runtime_tuning": outcome})
    except (TypeError, ValueError) as exc:
        return app._json_response({"error": str(exc)}, status=400)


def _operator_intent_route(app: Any, body: bytes) -> Any:
    payload = app._parse_json_body(body)
    intent_id = str(payload.get("intent_id", "")).strip()
    if not intent_id:
        return app._json_response({"error": "intent_id is required"}, status=400)
    try:
        outcome = app.runtime.set_operator_intent(intent_id)
    except (KeyError, ValueError) as exc:
        return app._json_response({"error": str(exc)}, status=400)
    return app._action_response("operator-intent", {"operator_intent": outcome})


def _runtime_control_route(app: Any, body: bytes) -> Any:
    payload = app._parse_json_body(body)
    mode = str(payload.get("mode", "")).strip()
    intent_id = str(payload.get("intent_id", "")).strip()
    if not mode:
        return app._json_response({"error": "mode is required"}, status=400)
    if not intent_id:
        return app._json_response({"error": "intent_id is required"}, status=400)
    try:
        interval = payload.get("interval_seconds")
        outcome = app.runtime.update_runtime_control(
            mode=mode,
            interval_seconds=int(interval) if interval is not None else None,
            intent_id=intent_id,
        )
    except (KeyError, TypeError, ValueError) as exc:
        return app._json_response({"error": str(exc)}, status=400)
    return app._runtime_control_response(outcome)


def _update_models_route(app: Any, body: bytes) -> Any:
    payload = app._parse_json_body(body)
    selections = payload.get("roles", {})
    processors = payload.get("processors", {})
    wrapper_mode = payload.get("wrapper_mode")
    if not isinstance(selections, dict):
        return app._json_response({"error": "roles must be an object"}, status=400)
    if not isinstance(processors, dict):
        return app._json_response({"error": "processors must be an object"}, status=400)
    if wrapper_mode is not None and not isinstance(wrapper_mode, dict):
        return app._json_response({"error": "wrapper_mode must be an object"}, status=400)
    with app._lock:
        try:
            models = app.runtime.update_model_roles(
                {str(key): str(value) for key, value in selections.items()},
                processors={str(key): str(value) for key, value in processors.items()},
                wrapper_mode={str(key): value for key, value in wrapper_mode.items()} if wrapper_mode else None,
            )
        except ValueError as exc:
            return app._json_response({"error": str(exc)}, status=400)
        return app._action_response("update-model-roles", {"models": models})


def _approval_credential_chat_routes(app: Any, method: str, path: str, query: dict[str, list[str]], body: bytes) -> Any | None:
    if method == "POST" and path in {"/api/actions/approve", "/api/actions/deny"}:
        approved = path.endswith("/approve")
        return _approval_route(app, body, approved=approved)
    if method == "POST" and path.startswith("/api/credentials/"):
        return _set_credentials_route(app, path, body)
    if method == "POST" and path == "/api/chat":
        return _operator_chat_route(app, body)
    if method == "POST" and path == "/api/approvals/inquiry":
        return _approval_inquiry_route(app, body)
    if method == "DELETE" and path.startswith("/api/credentials/"):
        service = unquote(path.rsplit("/", 1)[-1])
        try:
            credentials = app.runtime.clear_credentials(service)
        except ValueError as exc:
            return app._json_response({"error": str(exc)}, status=400)
        return app._action_response("clear-credentials", {"credentials": credentials})
    return None


def _approval_route(app: Any, body: bytes, *, approved: bool) -> Any:
    payload = app._parse_json_body(body)
    task_id = str(payload.get("task_id", "")).strip()
    if not task_id:
        return app._json_response({"error": "task_id is required"}, status=400)
    with app._lock:
        task = app.runtime.approve_task(task_id, approved=approved)
        if task is None:
            return app._json_response({"error": "task not found"}, status=404)
        return app._action_response("approve" if approved else "deny", {"task_id": task_id, "status": task.status.value})


def _set_credentials_route(app: Any, path: str, body: bytes) -> Any | None:
    payload = app._parse_json_body(body)
    routes = {
        "/api/credentials/notion": ("set-notion-credentials", app.runtime.set_notion_credentials, ("api_key", "parent_page_id", "version")),
        "/api/credentials/discord": ("set-discord-credentials", app.runtime.set_discord_credentials, ("webhook_url",)),
        "/api/credentials/known": ("set-known-credentials", app.runtime.set_known_credentials, ("username", "password", "domain")),
        "/api/credentials/lab": ("set-lab-credentials", app.runtime.set_lab_credentials, ("username", "password", "domain")),
        "/api/credentials/caido": ("set-caido-credentials", app.runtime.set_caido_credentials, ("graphql_url", "api_token")),
    }
    if path not in routes:
        return None
    action, setter, fields = routes[path]
    try:
        credentials = setter(**{field: app._optional_string(payload, field) for field in fields})
    except ValueError as exc:
        return app._json_response({"error": str(exc)}, status=400)
    return app._action_response(action, {"credentials": credentials})


def _operator_chat_route(app: Any, body: bytes) -> Any:
    payload = app._parse_json_body(body)
    message = str(payload.get("message", "")).strip()
    if not message:
        return app._json_response({"error": "message is required"}, status=400)
    target = app._optional_string(payload, "target")
    return app._run_tracked_action(
        "Ask operator AI",
        "operator-chat",
        lambda: {"chat": app.runtime.ask_operator_ai(message, target=target)},
        use_runtime_lock=False,
    )


def _approval_inquiry_route(app: Any, body: bytes) -> Any:
    payload = app._parse_json_body(body)
    task_id = str(payload.get("task_id") or payload.get("approval_id") or "").strip()
    message = str(payload.get("message") or "").strip()
    if not task_id:
        return app._json_response({"error": "task_id is required"}, status=400)
    if not message:
        return app._json_response({"error": "message is required"}, status=400)
    try:
        return app._run_tracked_action(
            "Ask approval inquiry",
            "approval-inquiry",
            lambda: {"chat": app.runtime.ask_approval_inquiry(task_id, message)},
            use_runtime_lock=False,
        )
    except ValueError as exc:
        return app._json_response({"error": str(exc)}, status=404)


def _target_scope_routes(app: Any, method: str, path: str, query: dict[str, list[str]], body: bytes) -> Any | None:
    if method == "POST" and path == "/api/targets":
        return _register_target_route(app, body)
    if method == "POST" and path == "/api/scope/import":
        return _scope_import_route(app, body)
    if method == "DELETE" and path.startswith("/api/targets/"):
        return _delete_target_route(app, path, query)
    return None


def _register_target_route(app: Any, body: bytes) -> Any:
    payload = app._parse_json_body(body)
    handle = str(payload.get("handle", "")).strip()
    profile = str(payload.get("profile", "")).strip()
    if not handle:
        return app._json_response({"error": "handle is required"}, status=400)
    if not profile:
        return app._json_response({"error": "profile is required"}, status=400)
    assets = payload.get("assets", [])
    if not isinstance(assets, list):
        return app._json_response({"error": "assets must be a list"}, status=400)
    try:
        parsed_profile = app.runtime.resolve_scope_profile(profile)
    except ValueError:
        return app._json_response({"error": "invalid profile"}, status=400)
    return _register_target_with_profile(app, payload, handle=handle, parsed_profile=parsed_profile, assets=assets)


def _register_target_with_profile(app: Any, payload: dict[str, Any], *, handle: str, parsed_profile: Any, assets: list[Any]) -> Any:
    active_ip = app._optional_string(payload, "active_ip")
    with app._lock:
        try:
            if bool(payload.get("replace_scope_assets", False)):
                target = app.runtime.replace_target_scope_assets(
                    handle=handle,
                    display_name=payload.get("display_name") and str(payload["display_name"]) or handle,
                    profile=parsed_profile,
                    in_scope=bool(payload.get("in_scope", True)),
                    active_ip=active_ip,
                    asset_rows=app._target_asset_rows(handle, active_ip, assets),
                )
            else:
                target = app.runtime.update_target_fields(
                    handle=handle,
                    display_name=payload.get("display_name") and str(payload["display_name"]),
                    profile=parsed_profile,
                    assets=assets or [handle],
                    active_ip=active_ip,
                    in_scope=bool(payload.get("in_scope", True)),
                    metadata=dict(payload.get("metadata", {})) if isinstance(payload.get("metadata", {}), dict) else {},
                )
        except ValueError as exc:
            return app._json_response({"error": str(exc)}, status=400)
        return app._action_response("register-target", app._scope_refresh_result(target=target))


def _scope_import_route(app: Any, body: bytes) -> Any:
    payload = app._parse_json_body(body)
    scope_payload = payload.get("scope", payload)
    profile = payload.get("profile")
    try:
        parsed_profile = app.runtime.resolve_scope_profile(str(profile)) if profile else None
        if not isinstance(scope_payload, dict):
            return app._json_response({"error": "scope must be an object"}, status=400)
        with app._lock:
            outcome = app.runtime.import_scope_payload(scope_payload, profile=parsed_profile, source_name=str(payload.get("source", "web import")))
            merged = dict(outcome)
            merged.update(app._scope_refresh_result())
            return app._action_response("import-scope", merged)
    except (KeyError, TypeError, ValueError) as exc:
        return app._json_response({"error": str(exc)}, status=400)


def _delete_target_route(app: Any, path: str, query: dict[str, list[str]]) -> Any:
    handle = unquote(path.rsplit("/", 1)[-1])
    raw_profile = query.get("profile", [])
    parsed_profile = None
    if raw_profile:
        try:
            parsed_profile = ScopeProfile(raw_profile[0])
        except ValueError:
            return app._json_response({"error": "invalid profile"}, status=400)
    with app._lock:
        outcome = app.runtime.remove_target(handle, parsed_profile)
        if outcome.get("blocked"):
            return app._json_response({"ok": False, "error": outcome["reason"], "result": outcome}, status=409)
        if not outcome["removed"]:
            return app._json_response({"error": "target not found"}, status=404)
        merged = dict(outcome)
        merged.update(app._scope_refresh_result())
        return app._action_response("remove-target", merged)
