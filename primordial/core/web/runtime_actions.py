from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from primordial.core.web.responses import WebResponse


class WebRuntimeActionsMixin:
    def _tick_action(self, max_executions: int) -> dict[str, Any]:
        if not self._tick_lock.acquire(blocking=False):
            return {"report": {"summary": "tick already running", "completed_runs": 0}, "skipped": True}
        try:
            report = self.runtime.run_tick(max_executions=max_executions)
            return {"report": {"summary": report.summary, "completed_runs": len(report.completed_runs)}}
        finally:
            self._tick_lock.release()

    def _run_tracked_action(self, label: str, action: str, worker, *, use_runtime_lock: bool = True) -> WebResponse:
        action_id = self._begin_action(label)
        try:
            if use_runtime_lock:
                with self._lock:
                    result = worker()
            else:
                result = worker()
            return self._action_response(action, result)
        finally:
            self._finish_action(action_id)

    def _begin_action(self, label: str) -> str:
        started = datetime.now(timezone.utc)
        action_id = f"web_{started.strftime('%Y%m%dT%H%M%S%fZ')}"
        with self._actions_lock:
            self._active_actions[action_id] = {
                "id": action_id,
                "kind": "web_action",
                "label": label,
                "status": "running",
                "started_at": started.isoformat(),
                "started_at_epoch": started.timestamp(),
            }
        return action_id

    def _finish_action(self, action_id: str) -> None:
        with self._actions_lock:
            self._active_actions.pop(action_id, None)

    def _active_web_actions(self) -> list[dict[str, Any]]:
        now = datetime.now(timezone.utc).timestamp()
        with self._actions_lock:
            actions = []
            for action in self._active_actions.values():
                item = {key: value for key, value in action.items() if key != "started_at_epoch"}
                started_at_epoch = action.get("started_at_epoch")
                age_seconds = int(max(0, now - float(started_at_epoch))) if started_at_epoch is not None else 0
                item["age_seconds"] = age_seconds
                item["stale_after_seconds"] = self.STALE_WEB_ACTION_SECONDS
                item["stale"] = age_seconds >= self.STALE_WEB_ACTION_SECONDS
                if item["stale"]:
                    item["status"] = "stale"
                actions.append(item)
            return actions

    def _clear_stale_actions(self, *, max_age_seconds: int) -> int:
        now = datetime.now(timezone.utc).timestamp()
        cleared = 0
        with self._actions_lock:
            for action_id, action in list(self._active_actions.items()):
                started_at_epoch = action.get("started_at_epoch")
                if started_at_epoch is None:
                    continue
                if now - float(started_at_epoch) >= max(1, max_age_seconds):
                    self._active_actions.pop(action_id, None)
                    cleared += 1
        return cleared

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
            stale_count = sum(1 for action in web_actions if action.get("stale"))
            if stale_count:
                payload["summary"] = (
                    f"Web console has {stale_count} stale action(s); runtime work may have continued in the background."
                )
            else:
                payload["summary"] = f"Web console is running {len(web_actions)} action(s)."
            counts = dict(payload.get("counts", {}))
            counts["web_actions"] = len(web_actions)
            counts["stale_web_actions"] = stale_count
            payload["counts"] = counts
        else:
            payload["web_actions"] = []
        return payload

    def continuous_tick_once(self) -> dict[str, Any]:
        mode = self.runtime.execution_mode_payload()
        if mode.get("mode") != "continuous":
            return {"ran": False, "interval_seconds": mode.get("interval_seconds", 30)}
        if not self._tick_lock.acquire(blocking=False):
            return {
                "ran": False,
                "busy": True,
                "interval_seconds": mode.get("interval_seconds", 30),
                "summary": "previous continuous tick still running",
            }
        try:
            report = self.runtime.run_tick(max_executions=1)
            return {"ran": True, "interval_seconds": mode.get("interval_seconds", 30), "summary": report.summary}
        finally:
            self._tick_lock.release()

    def _action_response(self, action: str, result: dict[str, Any]) -> WebResponse:
        payload: dict[str, Any] = {
            "ok": True,
            "action": action,
            "result": result,
            "work_status": self.work_status_payload(),
        }
        if isinstance(result, dict):
            for key in (
                "execution_mode",
                "runtime_tuning",
                "operator_intent",
                "credentials",
                "target",
                "scope",
                "scopePayload",
                "scopeProfiles",
                "models",
                "caido",
                "findings_context",
                "storage_status",
            ):
                if key in result:
                    payload[key] = result[key]
        return self._json_response(payload)

    def _scope_refresh_result(self, *, target=None) -> dict[str, Any]:
        scope_payload = self.runtime.scope_payload()
        scope_profiles = self.runtime.scope_profiles_payload()
        scope_targets = [item for item in scope_payload.get("targets", []) if self._target_handle(item)]
        return {
            "target": target.as_payload() if target is not None else None,
            "scope": self._scope_view(scope_targets),
            "scopePayload": scope_payload,
            "scopeProfiles": scope_profiles,
        }

    def _runtime_control_response(self, result: dict[str, Any]) -> WebResponse:
        return self._json_response(
            {
                "ok": True,
                "action": "runtime-control",
                "execution_mode": result["execution_mode"],
                "operator_intent": result["operator_intent"],
                "work_status": self.work_status_payload(),
            }
        )
