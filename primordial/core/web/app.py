from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
from threading import RLock
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from primordial.app.runtime import PrimordialRuntime
from primordial.core.domain.enums import ScopeProfile


@dataclass(slots=True)
class WebResponse:
    status: int
    body: bytes
    content_type: str
    headers: dict[str, str] = field(default_factory=dict)


class PrimordialWebApp:
    def __init__(self, runtime: PrimordialRuntime) -> None:
        self.runtime = runtime
        self._lock = RLock()
        self._actions_lock = RLock()
        self._active_actions: dict[str, dict[str, Any]] = {}
        self._static_dir = Path(__file__).resolve().parent / "static"

    def dispatch(
        self,
        method: str,
        raw_path: str,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
    ) -> WebResponse:
        parsed = urlsplit(raw_path)
        path = parsed.path or "/"
        query = parse_qs(parsed.query)

        if method == "GET" and path == "/":
            return self._static_response("index.html", "text/html; charset=utf-8")
        if method == "GET" and path == "/app.js":
            return self._static_response("app.js", "text/javascript; charset=utf-8")
        if method == "GET" and path == "/styles.css":
            return self._static_response("styles.css", "text/css; charset=utf-8")
        if method == "GET" and path == "/api/health":
            return self._json_response(self.runtime.health_payload())
        if method == "GET" and path == "/api/credentials":
            with self._lock:
                return self._json_response(self.runtime.credentials_payload())
        if method == "GET" and path == "/api/skills":
            include_body = self._bool_param(query, "include_body", False)
            with self._lock:
                return self._json_response(self.runtime.skills_payload(include_body=include_body))
        if method == "GET" and path == "/api/findings-context":
            target = self._optional_query_string(query, "target")
            include_guidance = self._bool_param(query, "include_guidance", True)
            with self._lock:
                try:
                    return self._json_response(
                        self.runtime.findings_context_payload(target=target, include_guidance=include_guidance)
                    )
                except ValueError as exc:
                    return self._json_response({"error": str(exc)}, status=404)
        if method == "POST" and path == "/api/findings-context/guidance":
            payload = self._parse_json_body(body)
            target = str(payload.get("target", "")).strip()
            guidance = str(payload.get("guidance", ""))
            if not target:
                return self._json_response({"error": "target is required"}, status=400)
            with self._lock:
                try:
                    outcome = self.runtime.update_target_guidance(target, guidance)
                    return self._action_response("update-target-guidance", {"findings_context": outcome})
                except ValueError as exc:
                    return self._json_response({"error": str(exc)}, status=404)
        if method == "GET" and path == "/api/integrations/caido":
            check_health = self._bool_param(query, "check_health", False)
            with self._lock:
                return self._json_response(self.runtime.caido_status_payload(check_health=check_health))
        if method == "GET" and path == "/api/models":
            with self._lock:
                return self._json_response(self.runtime.models_payload())
        if method == "GET" and path == "/api/chat":
            limit = self._int_param(query, "limit", 20)
            target = self._optional_query_string(query, "target")
            with self._lock:
                return self._json_response(self.runtime.operator_chat_payload(limit=limit, target=target))
        if method == "GET" and path == "/api/dashboard":
            with self._lock:
                return self._json_response(self._dashboard_payload())
        if method == "GET" and path == "/api/work-status":
            return self._json_response(self.work_status_payload())
        if method == "GET" and path == "/api/execution-mode":
            with self._lock:
                return self._json_response(self.runtime.execution_mode_payload())
        if method == "GET" and path == "/api/runtime-settings":
            with self._lock:
                return self._json_response(self.runtime.runtime_tuning_payload())
        if method == "GET" and path == "/api/scope":
            with self._lock:
                return self._json_response(self.runtime.scope_payload())
        if method == "GET" and path == "/api/audit":
            limit = self._int_param(query, "limit", 25)
            with self._lock:
                return self._json_response(self.runtime.audit_payload(limit=limit))
        if method == "GET" and path == "/api/records":
            limit = self._int_param(query, "limit", 25)
            target_id = self._optional_query_string(query, "target_id")
            with self._lock:
                return self._json_response(self.runtime.records_payload(limit=limit, target_id=target_id))
        if method == "GET" and path.startswith("/api/tasks/"):
            task_id = path.rsplit("/", 1)[-1]
            with self._lock:
                payload = self.runtime.task_audit_payload(task_id, limit=self._int_param(query, "limit", 25))
            if payload is None:
                return self._json_response({"error": "task not found"}, status=404)
            return self._json_response(payload)
        if method == "POST" and path == "/api/actions/tick":
            payload = self._parse_json_body(body)
            max_executions = int(payload.get("max_executions", 3))
            return self._run_tracked_action(
                "Run orchestration tick",
                "tick",
                lambda: self._tick_action(max_executions),
            )
        if method == "POST" and path == "/api/actions/compact":
            return self._run_tracked_action(
                "Compact memory",
                "compact",
                lambda: {"memory_entries_created": self.runtime.compact_memory()},
            )
        if method == "POST" and path == "/api/actions/process-queues":
            return self._run_tracked_action(
                "Process external queues",
                "process-queues",
                self.runtime.process_external_queues,
            )
        if method == "POST" and path == "/api/actions/sync-findings-context":
            return self._run_tracked_action(
                "Sync findings context",
                "sync-findings-context",
                self.runtime.sync_findings_context_exports,
            )
        if method == "POST" and path == "/api/actions/warm-models":
            payload = self._parse_json_body(body)
            keep_alive = str(payload.get("keep_alive", "8h")).strip() or "8h"
            return self._run_tracked_action(
                "Warm Ollama model lanes",
                "warm-models",
                lambda: self.runtime.warm_model_routes(keep_alive=keep_alive),
            )
        if method == "POST" and path == "/api/actions/clear-models":
            return self._run_tracked_action(
                "Clear Ollama model lanes",
                "clear-models",
                self.runtime.clear_model_routes,
            )
        if method == "POST" and path == "/api/actions/stop-work":
            return self._run_tracked_action(
                "Stop active work",
                "stop-work",
                self.runtime.stop_active_work,
            )
        if method == "POST" and path == "/api/execution-mode":
            payload = self._parse_json_body(body)
            mode = str(payload.get("mode", "")).strip()
            interval = payload.get("interval_seconds")
            try:
                interval_seconds = int(interval) if interval is not None else None
                with self._lock:
                    outcome = self.runtime.update_execution_mode(mode, interval_seconds=interval_seconds)
                    return self._action_response("execution-mode", {"execution_mode": outcome})
            except (TypeError, ValueError) as exc:
                return self._json_response({"error": str(exc)}, status=400)
        if method == "POST" and path == "/api/runtime-settings":
            payload = self._parse_json_body(body)
            try:
                with self._lock:
                    outcome = self.runtime.update_runtime_tuning(
                        gpu_ai_timeout_seconds=self._optional_int(payload, "gpu_ai_timeout_seconds"),
                        cpu_ai_timeout_seconds=self._optional_int(payload, "cpu_ai_timeout_seconds"),
                        stale_run_timeout_seconds=self._optional_int(payload, "stale_run_timeout_seconds"),
                    )
                    return self._action_response("runtime-settings", {"runtime_tuning": outcome})
            except (TypeError, ValueError) as exc:
                return self._json_response({"error": str(exc)}, status=400)
        if method == "POST" and path == "/api/models":
            payload = self._parse_json_body(body)
            selections = payload.get("roles", {})
            processors = payload.get("processors", {})
            if not isinstance(selections, dict):
                return self._json_response({"error": "roles must be an object"}, status=400)
            if not isinstance(processors, dict):
                return self._json_response({"error": "processors must be an object"}, status=400)
            with self._lock:
                try:
                    models = self.runtime.update_model_roles(
                        {str(key): str(value) for key, value in selections.items()},
                        processors={str(key): str(value) for key, value in processors.items()},
                    )
                except ValueError as exc:
                    return self._json_response({"error": str(exc)}, status=400)
                return self._action_response("update-model-roles", {"models": models})
        if method == "POST" and path == "/api/actions/approve":
            payload = self._parse_json_body(body)
            task_id = str(payload.get("task_id", "")).strip()
            if not task_id:
                return self._json_response({"error": "task_id is required"}, status=400)
            with self._lock:
                task = self.runtime.approve_task(task_id, approved=True)
                if task is None:
                    return self._json_response({"error": "task not found"}, status=404)
                return self._action_response("approve", {"task_id": task_id, "status": task.status.value})
        if method == "POST" and path == "/api/actions/deny":
            payload = self._parse_json_body(body)
            task_id = str(payload.get("task_id", "")).strip()
            if not task_id:
                return self._json_response({"error": "task_id is required"}, status=400)
            with self._lock:
                task = self.runtime.approve_task(task_id, approved=False)
                if task is None:
                    return self._json_response({"error": "task not found"}, status=404)
                return self._action_response("deny", {"task_id": task_id, "status": task.status.value})
        if method == "POST" and path == "/api/credentials/notion":
            payload = self._parse_json_body(body)
            with self._lock:
                credentials = self.runtime.set_notion_credentials(
                    api_key=self._optional_string(payload, "api_key"),
                    parent_page_id=self._optional_string(payload, "parent_page_id"),
                    version=self._optional_string(payload, "version"),
                )
                return self._action_response("set-notion-credentials", {"credentials": credentials})
        if method == "POST" and path == "/api/credentials/discord":
            payload = self._parse_json_body(body)
            with self._lock:
                credentials = self.runtime.set_discord_credentials(
                    webhook_url=self._optional_string(payload, "webhook_url"),
                )
                return self._action_response("set-discord-credentials", {"credentials": credentials})
        if method == "POST" and path == "/api/credentials/lab":
            payload = self._parse_json_body(body)
            with self._lock:
                credentials = self.runtime.set_lab_credentials(
                    username=self._optional_string(payload, "username"),
                    password=self._optional_string(payload, "password"),
                    domain=self._optional_string(payload, "domain"),
                )
                return self._action_response("set-lab-credentials", {"credentials": credentials})
        if method == "POST" and path == "/api/credentials/caido":
            payload = self._parse_json_body(body)
            with self._lock:
                credentials = self.runtime.set_caido_credentials(
                    graphql_url=self._optional_string(payload, "graphql_url"),
                    api_token=self._optional_string(payload, "api_token"),
                )
                return self._action_response("set-caido-credentials", {"credentials": credentials})
        if method == "POST" and path == "/api/chat":
            payload = self._parse_json_body(body)
            message = str(payload.get("message", "")).strip()
            if not message:
                return self._json_response({"error": "message is required"}, status=400)
            target = self._optional_string(payload, "target")
            return self._run_tracked_action(
                "Ask operator AI",
                "operator-chat",
                lambda: {"chat": self.runtime.ask_operator_ai(message, target=target)},
            )
        if method == "DELETE" and path.startswith("/api/credentials/"):
            service = unquote(path.rsplit("/", 1)[-1])
            with self._lock:
                try:
                    credentials = self.runtime.clear_credentials(service)
                except ValueError as exc:
                    return self._json_response({"error": str(exc)}, status=400)
                return self._action_response("clear-credentials", {"credentials": credentials})
        if method == "POST" and path == "/api/targets":
            payload = self._parse_json_body(body)
            handle = str(payload.get("handle", "")).strip()
            profile = str(payload.get("profile", "")).strip()
            if not handle:
                return self._json_response({"error": "handle is required"}, status=400)
            if not profile:
                return self._json_response({"error": "profile is required"}, status=400)
            assets = payload.get("assets", [])
            if not isinstance(assets, list):
                return self._json_response({"error": "assets must be a list"}, status=400)
            active_ip = self._optional_string(payload, "active_ip")
            try:
                parsed_profile = ScopeProfile(profile)
            except ValueError:
                return self._json_response({"error": "invalid profile"}, status=400)
            with self._lock:
                try:
                    target = self.runtime.update_target_fields(
                        handle=handle,
                        display_name=payload.get("display_name") and str(payload["display_name"]),
                        profile=parsed_profile,
                        assets=assets or [handle],
                        active_ip=active_ip,
                        in_scope=bool(payload.get("in_scope", True)),
                        metadata=dict(payload.get("metadata", {})) if isinstance(payload.get("metadata", {}), dict) else {},
                    )
                except ValueError as exc:
                    return self._json_response({"error": str(exc)}, status=400)
                return self._action_response("register-target", {"target": target.as_payload()})
        if method == "POST" and path == "/api/scope/import":
            payload = self._parse_json_body(body)
            scope_payload = payload.get("scope", payload)
            profile = payload.get("profile")
            try:
                parsed_profile = ScopeProfile(str(profile)) if profile else None
                if not isinstance(scope_payload, dict):
                    return self._json_response({"error": "scope must be an object"}, status=400)
                with self._lock:
                    outcome = self.runtime.import_scope_payload(
                        scope_payload,
                        profile=parsed_profile,
                        source_name=str(payload.get("source", "web import")),
                    )
                    return self._action_response("import-scope", outcome)
            except (KeyError, TypeError, ValueError) as exc:
                return self._json_response({"error": str(exc)}, status=400)
        if method == "DELETE" and path.startswith("/api/targets/"):
            handle = unquote(path.rsplit("/", 1)[-1])
            raw_profile = query.get("profile", [])
            parsed_profile = None
            if raw_profile:
                try:
                    parsed_profile = ScopeProfile(raw_profile[0])
                except ValueError:
                    return self._json_response({"error": "invalid profile"}, status=400)
            with self._lock:
                outcome = self.runtime.remove_target(handle, parsed_profile)
                if not outcome["removed"]:
                    return self._json_response({"error": "target not found"}, status=404)
                return self._action_response("remove-target", outcome)
        return self._json_response({"error": "not found", "path": path}, status=404)

    def _tick_action(self, max_executions: int) -> dict[str, Any]:
        report = self.runtime.run_tick(max_executions=max_executions)
        return {"report": {"summary": report.summary, "completed_runs": len(report.completed_runs)}}

    def _run_tracked_action(self, label: str, action: str, worker) -> WebResponse:
        action_id = self._begin_action(label)
        try:
            with self._lock:
                result = worker()
            return self._action_response(action, result)
        finally:
            self._finish_action(action_id)

    def _begin_action(self, label: str) -> str:
        action_id = f"web_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')}"
        with self._actions_lock:
            self._active_actions[action_id] = {
                "id": action_id,
                "kind": "web_action",
                "label": label,
                "status": "running",
                "started_at": datetime.now(timezone.utc).isoformat(),
            }
        return action_id

    def _finish_action(self, action_id: str) -> None:
        with self._actions_lock:
            self._active_actions.pop(action_id, None)

    def _active_web_actions(self) -> list[dict[str, Any]]:
        with self._actions_lock:
            return list(self._active_actions.values())

    def _dashboard_payload(self) -> dict[str, Any]:
        payload = self.runtime.dashboard_payload()
        payload["work_status"] = self.work_status_payload()
        return payload

    def work_status_payload(self) -> dict[str, Any]:
        payload = self.runtime.work_status_payload()
        web_actions = self._active_web_actions()
        if web_actions:
            payload = dict(payload)
            payload["web_actions"] = web_actions
            payload["is_busy"] = True
            payload["summary"] = f"Web console is running {len(web_actions)} action(s)."
            counts = dict(payload.get("counts", {}))
            counts["web_actions"] = len(web_actions)
            payload["counts"] = counts
        else:
            payload["web_actions"] = []
        return payload

    def _action_response(self, action: str, result: dict[str, Any]) -> WebResponse:
        return self._json_response(
            {
                "ok": True,
                "action": action,
                "result": result,
                "dashboard": self._dashboard_payload(),
                "scope": self.runtime.scope_payload(),
                "audit": self.runtime.audit_payload(limit=12),
                "credentials": self.runtime.credentials_payload(),
                "skills": self.runtime.skills_payload(include_body=False),
                "caido": self.runtime.caido_status_payload(check_health=False),
                "findings_context": self.runtime.findings_context_payload(include_guidance=False),
                "models": self.runtime.models_payload(),
                "execution_mode": self.runtime.execution_mode_payload(),
                "work_status": self.work_status_payload(),
            }
        )

    def _static_response(self, filename: str, content_type: str) -> WebResponse:
        path = self._static_dir / filename
        if not path.exists():
            return self._json_response({"error": "asset missing", "asset": filename}, status=404)
        return WebResponse(
            status=200,
            body=path.read_bytes(),
            content_type=content_type,
            headers={"Cache-Control": "no-store"},
        )

    def _json_response(self, payload: dict[str, Any], status: int = 200) -> WebResponse:
        return WebResponse(
            status=status,
            body=json.dumps(payload, indent=2, sort_keys=True).encode("utf-8"),
            content_type="application/json; charset=utf-8",
            headers={"Cache-Control": "no-store"},
        )

    def _parse_json_body(self, body: bytes) -> dict[str, Any]:
        if not body:
            return {}
        try:
            payload = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError("invalid JSON payload") from exc
        if not isinstance(payload, dict):
            raise ValueError("JSON payload must be an object")
        return payload

    def _int_param(self, query: dict[str, list[str]], name: str, default: int) -> int:
        raw = query.get(name, [])
        if not raw:
            return default
        try:
            return max(1, int(raw[0]))
        except ValueError:
            return default

    def _bool_param(self, query: dict[str, list[str]], name: str, default: bool) -> bool:
        raw = query.get(name, [])
        if not raw:
            return default
        return raw[0].strip().lower() in {"1", "true", "yes", "on"}

    def _optional_string(self, payload: dict[str, Any], key: str) -> str | None:
        value = payload.get(key)
        if value is None:
            return None
        return str(value).strip() or None

    def _optional_int(self, payload: dict[str, Any], key: str) -> int | None:
        value = payload.get(key)
        if value is None or value == "":
            return None
        return int(value)

    def _optional_query_string(self, query: dict[str, list[str]], key: str) -> str | None:
        values = query.get(key, [])
        if not values:
            return None
        return values[0].strip() or None
