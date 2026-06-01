from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


class WebWorkspaceViewsMixin:
    def _skills_view(self, skills: dict[str, Any]) -> list[dict[str, Any]]:
        rows = []
        for item in skills.get("skills", []) if isinstance(skills.get("skills", []), list) else []:
            if not isinstance(item, dict):
                continue
            rows.append(
                {
                    "id": str(item.get("id") or item.get("name") or ""),
                    "title": str(item.get("title") or item.get("name") or item.get("id") or "Skill"),
                    "summary": str(item.get("summary") or item.get("description") or ""),
                    "tags": item.get("tags", []) if isinstance(item.get("tags", []), list) else [],
                }
            )
        return rows

    def _playbooks_view(self, skills: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            {
                "id": "runtime",
                "label": "Runtime Planning",
                "desc": "Live workflow planner and policy-gated task execution.",
                "status": "active",
                "tasks": [item["id"] for item in self._skills_view(skills)[:6]],
            }
        ]

    def _pinned_assets_view(self, records: dict[str, Any]) -> list[dict[str, Any]]:
        pins = []
        for kind in ("evidence", "interests", "findings", "artifacts"):
            for item in records.get(kind, []) if isinstance(records.get(kind, []), list) else []:
                if not isinstance(item, dict):
                    continue
                pins.append(
                    {
                        "id": str(item.get("id") or f"pin_{len(pins)}"),
                        "kind": "interest" if kind == "interests" else kind.rstrip("s"),
                        "ref": str(item.get("id") or ""),
                        "label": str(item.get("title") or item.get("summary") or item.get("type") or kind),
                        "target": str(item.get("target_id") or "*"),
                        "pinned": self._time_label(item.get("created_at")),
                    }
                )
        return pins[:24]

    def _critical_thinking_view(self, work_status: dict[str, Any]) -> list[dict[str, str]]:
        blockers = work_status.get("blockers", []) if isinstance(work_status.get("blockers", []), list) else []
        rows = []
        for index, blocker in enumerate(blockers):
            if not isinstance(blocker, dict):
                continue
            rows.append(
                {
                    "id": str(blocker.get("kind") or f"ct_{index}"),
                    "prompt": str(blocker.get("summary") or "Review runtime blocker."),
                    "target": str(blocker.get("target") or "*"),
                    "phase": "analysis",
                    "status": "open",
                }
            )
        return rows or [
            {
                "id": "ct_scope",
                "prompt": "What evidence is missing before the next runtime action?",
                "target": "*",
                "phase": "recon",
                "status": "open",
            }
        ]

    def _workspace_body(self, target: dict[str, Any], workspace: dict[str, Any]) -> str:
        lines = [
            f"# {target.get('handle', 'Target')}",
            f"Profile: {target.get('profile', '')}",
            f"Findings path: {workspace.get('findings_path', 'not generated') if isinstance(workspace, dict) else 'not generated'}",
            f"Guidance path: {workspace.get('guidance_path', 'not generated') if isinstance(workspace, dict) else 'not generated'}",
        ]
        if isinstance(workspace, dict) and workspace.get("summary"):
            lines.extend(["", str(workspace["summary"])])
        return "\n".join(lines)

    def _target_lookup(self, targets: list[dict[str, Any]]) -> dict[str, str]:
        lookup = {}
        for item in targets:
            target = item.get("target", {}) if isinstance(item.get("target"), dict) else {}
            lookup[str(target.get("id") or "")] = str(target.get("handle") or "")
        return lookup

    def _target_handle(self, item: dict[str, Any]) -> str:
        target = item.get("target", {}) if isinstance(item.get("target"), dict) else {}
        return str(target.get("handle") or "").strip()

    def _first_asset(self, assets: list[Any], asset_type: str) -> str:
        for item in assets:
            if isinstance(item, dict) and item.get("asset_type") == asset_type:
                return str(item.get("asset") or "")
        return ""

    def _metric_ratio(self, metrics: dict[str, Any], key: str) -> float:
        payload = metrics.get(key, {}) if isinstance(metrics, dict) else {}
        if not isinstance(payload, dict):
            return 0.0
        for field_name in ("load_ratio", "utilization_ratio", "usage_ratio"):
            value = payload.get(field_name)
            if isinstance(value, int | float):
                return max(0.0, min(1.0, float(value)))
        percent = payload.get("percent")
        if isinstance(percent, int | float):
            return max(0.0, min(1.0, float(percent) / 100.0))
        return 0.0

    def _memory_ratio(self, metrics: dict[str, Any]) -> float:
        cpu = metrics.get("cpu", {}) if isinstance(metrics, dict) else {}
        if isinstance(cpu, dict):
            memory = cpu.get("memory", {})
            if isinstance(memory, dict):
                percent = memory.get("percent")
                if isinstance(percent, int | float):
                    return max(0.0, min(1.0, float(percent) / 100.0))
            percent = cpu.get("memory_percent")
            if isinstance(percent, int | float):
                return max(0.0, min(1.0, float(percent) / 100.0))
        return 0.0

    def _task_status_for_gui(self, status: str) -> str:
        normalized = status.lower()
        if normalized in {"running", "claimed"}:
            return "running"
        if normalized in {"pending", "queued"}:
            return "queued"
        if normalized in {"needs_approval", "waiting", "await_approval"}:
            return "await_approval"
        if normalized in {"completed", "done", "succeeded"}:
            return "done"
        if normalized in {"failed", "denied"}:
            return "failed"
        return normalized or "queued"

    def _trace_status_for_gui(self, status: str) -> str:
        normalized = self._task_status_for_gui(status)
        if normalized == "running":
            return "run"
        if normalized == "done":
            return "pass"
        if normalized == "failed":
            return "fail"
        if normalized == "await_approval":
            return "gated"
        return "queued"

    def _event_level(self, event_type: str) -> str:
        lowered = event_type.lower()
        if any(token in lowered for token in ("failed", "error", "denied")):
            return "err"
        if any(token in lowered for token in ("approval", "waiting", "stale")):
            return "warn"
        if any(token in lowered for token in ("completed", "success", "bootstrap", "scope")):
            return "ok"
        return "info"

    def _time_label(self, value: Any) -> str:
        if not value:
            return datetime.now(timezone.utc).strftime("%H:%M:%S")
        try:
            return datetime.fromisoformat(str(value)).strftime("%H:%M:%S")
        except ValueError:
            return str(value)
