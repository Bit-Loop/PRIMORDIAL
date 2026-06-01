from __future__ import annotations

import hashlib
import json
from typing import Any

from primordial.core.domain.enums import TaskKind


class WebTaskViewsMixin:
    def _tasks_view(
        self,
        dashboard: dict[str, Any],
        work_status: dict[str, Any],
        targets: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        by_id: dict[str, dict[str, Any]] = {}
        for group in ("active", "queued", "waiting", "recent"):
            for item in work_status.get(group, []) if isinstance(work_status.get(group, []), list) else []:
                if not isinstance(item, dict):
                    continue
                task_id = str(item.get("task_id") or item.get("run_id") or "")
                if not task_id:
                    continue
                by_id[task_id] = {
                    "id": task_id,
                    "kind": str(item.get("task_kind") or item.get("kind") or "task"),
                    "route": str(item.get("route") or ""),
                    "status": self._task_status_for_gui(str(item.get("status") or "")),
                    "target": str(item.get("target") or "*"),
                    "model": str(item.get("model") or ""),
                    "title": str(item.get("title") or item.get("summary") or task_id),
                    "ms": 0,
                    "raw": item,
                }
        target_lookup = self._target_lookup(targets)
        for task in dashboard.get("tasks", []) if isinstance(dashboard.get("tasks", []), list) else []:
            if not isinstance(task, dict):
                continue
            task_id = str(task.get("id") or "")
            if not task_id:
                continue
            target = target_lookup.get(str(task.get("target_id") or ""), "*")
            by_id.setdefault(
                task_id,
                {
                    "id": task_id,
                    "kind": str(task.get("kind") or "task"),
                    "route": str(task.get("provider_route") or ""),
                    "status": self._task_status_for_gui(str(task.get("status") or "")),
                    "target": target,
                    "model": str(task.get("provider_model") or ""),
                    "title": str(task.get("title") or task.get("summary") or task_id),
                    "ms": 0,
                    "raw": task,
                },
        )
        items = [item for item in by_id.values() if not self._hide_task_item(item)]
        for item in items:
            self._decorate_task_wrapper(item)
            hint = self._task_hint(item)
            if hint:
                item["hint"] = hint
        return self._group_task_items(items)[:100]

    def _decorate_task_wrapper(self, item: dict[str, Any]) -> None:
        raw = item.get("raw", {}) if isinstance(item.get("raw"), dict) else {}
        metadata = raw.get("metadata", {}) if isinstance(raw.get("metadata"), dict) else {}
        wrapper = str(metadata.get("local_chat_wrapper") or "")
        local_wrapper = bool(metadata.get("remote_premium_local_wrapper"))
        if not wrapper and local_wrapper:
            wrapper = "agent_chat_api"
        item["local_chat_wrapper"] = wrapper
        item["remote_premium_local_wrapper"] = local_wrapper
        if wrapper and local_wrapper:
            item["wrapper_label"] = f"{wrapper} wrapper"
            item["wrapper_detail"] = (
                "Claude/GPT review is routed through the local chat wrapper; "
                "remote premium flag and budget gates do not block this task."
            )

    def _hide_task_item(self, item: dict[str, Any]) -> bool:
        raw = item.get("raw", {}) if isinstance(item.get("raw"), dict) else {}
        metadata = raw.get("metadata", {}) if isinstance(raw.get("metadata"), dict) else {}
        if raw.get("invalid_target") or metadata.get("invalid_target"):
            return True
        if (
            item.get("target") in {"", "*"}
            and item.get("kind") == TaskKind.RECON_SCAN.value
            and item.get("status") in {"blocked", "failed"}
        ):
            return True
        return False

    def _task_hint(self, item: dict[str, Any]) -> str:
        if (
            item.get("status") == "queued"
            and item.get("route") == "local_compact"
            and item.get("model") == "phi4-reasoning"
        ):
            return "Missing local model hint: phi4-reasoning is selected for local_compact; warm/install it or change the role."
        return ""

    def _group_task_items(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        groupable_statuses = {"done", "failed", "blocked"}
        grouped: dict[tuple[str, ...], list[dict[str, Any]]] = {}
        for item in items:
            if item.get("status") not in groupable_statuses:
                continue
            key = self._task_group_key(item)
            grouped.setdefault(key, []).append(item)

        result: list[dict[str, Any]] = []
        emitted: set[tuple[str, ...]] = set()
        for item in items:
            if item.get("status") not in groupable_statuses:
                result.append(item)
                continue
            key = self._task_group_key(item)
            members = grouped.get(key, [])
            if len(members) <= 1:
                result.append(item)
                continue
            if key in emitted:
                continue
            emitted.add(key)
            first = members[0]
            status = str(first.get("status") or "done")
            verb = {"done": "completed", "failed": "failed", "blocked": "blocked"}.get(status, "repeated")
            member_ids = [str(member.get("id") or "") for member in members if member.get("id")]
            group_id = self._stable_group_id("task", key)
            result.append(
                {
                    **first,
                    "id": group_id,
                    "title": f"{first.get('kind', 'task')} {verb} {len(members)} times",
                    "grouped": True,
                    "grouped_count": len(members),
                    "duplicate_group_id": group_id,
                    "member_ids": member_ids,
                    "raw": {
                        "grouped_task_ids": member_ids,
                        "group_key": list(key),
                        "group_status": status,
                        "sample": first.get("raw", {}),
                    },
                }
            )
        return result

    def _task_group_key(self, item: dict[str, Any]) -> tuple[str, ...]:
        raw = item.get("raw", {}) if isinstance(item.get("raw"), dict) else {}
        metadata = raw.get("metadata", {}) if isinstance(raw.get("metadata"), dict) else {}
        generation = str(raw.get("active_ip_generation") or metadata.get("active_ip_generation") or "")
        return (
            str(item.get("target") or "*"),
            str(item.get("kind") or "task"),
            str(item.get("route") or ""),
            generation,
            str(item.get("status") or ""),
        )

    def _stable_group_id(self, prefix: str, key: tuple[str, ...]) -> str:
        digest = hashlib.sha256(json.dumps(list(key), sort_keys=True).encode("utf-8")).hexdigest()[:16]
        return f"group:{prefix}:{digest}"

    def _inspect_group_payload(self, group_id: str) -> dict[str, Any]:
        payload = self._control_plane_payload(live_metrics=False)
        for item in payload.get("tasks", []) if isinstance(payload.get("tasks", []), list) else []:
            if not isinstance(item, dict) or str(item.get("id") or "") != group_id:
                continue
            raw = item.get("raw") if isinstance(item.get("raw"), dict) else {}
            member_ids = raw.get("grouped_task_ids") if isinstance(raw.get("grouped_task_ids"), list) else item.get("member_ids")
            if not isinstance(member_ids, list) or not member_ids:
                break
            result = self.runtime.inspect_many("task", [str(member_id) for member_id in member_ids])
            result.update(
                {
                    "id": group_id,
                    "title": str(item.get("title") or "Task group"),
                    "summary": str(item.get("title") or ""),
                    "duplicate_group": {
                        "id": group_id,
                        "kind": "task",
                        "count": len(member_ids),
                        "members": [{"kind": "task", "id": str(member_id)} for member_id in member_ids],
                        "sample": raw.get("sample", {}),
                    },
                }
            )
            return result

        for node in self._iter_trace_nodes(payload.get("traces", [])):
            if str(node.get("id") or "") != group_id:
                continue
            member_ids = node.get("member_ids") if isinstance(node.get("member_ids"), list) else []
            if not member_ids:
                break
            result = self.runtime.inspect_many("trace", [str(member_id) for member_id in member_ids])
            result.update(
                {
                    "id": group_id,
                    "title": str(node.get("summary") or node.get("kind") or "Trace group"),
                    "summary": str(node.get("summary") or ""),
                    "duplicate_group": {
                        "id": group_id,
                        "kind": "trace",
                        "count": len(member_ids),
                        "members": [{"kind": "trace", "id": str(member_id)} for member_id in member_ids],
                        "representative_id": str(node.get("representative_id") or ""),
                    },
                }
            )
            return result
        raise ValueError(f"group not found: {group_id}")

    def _iter_trace_nodes(self, nodes: object) -> list[dict[str, Any]]:
        if not isinstance(nodes, list):
            return []
        result: list[dict[str, Any]] = []
        for node in nodes:
            if not isinstance(node, dict):
                continue
            result.append(node)
            result.extend(self._iter_trace_nodes(node.get("children", [])))
        return result

    def _approvals_view(self, work_status: dict[str, Any], tasks: list[dict[str, Any]]) -> list[dict[str, Any]]:
        pending = []
        waiting = work_status.get("waiting", []) if isinstance(work_status.get("waiting", []), list) else []
        for item in waiting:
            if not isinstance(item, dict):
                continue
            task_id = str(item.get("task_id") or "")
            if not task_id:
                continue
            pending.append(
                {
                    "id": task_id,
                    "risk": "med",
                    "task": task_id,
                    "title": str(item.get("title") or "Approval required"),
                    "detail": str(item.get("summary") or "Task is waiting for operator approval."),
                    "reason": str(item.get("worker_contract") or "Runtime policy requires explicit operator decision."),
                    "target": str(item.get("target") or "*"),
                    "primitive": str(item.get("task_kind") or "task"),
                    "limits": "bounded by active operator intent",
                    "inspect_kind": "task",
                    "inspect_id": task_id,
                }
            )
        if pending:
            return pending[:50]
        return [
            {
                "id": item["id"],
                "risk": "low",
                "task": item["id"],
                "title": item["title"],
                "detail": item.get("raw", {}).get("summary") or item["title"],
                "reason": "No pending approval; shown for inspection only.",
                "target": item.get("target", "*"),
                "primitive": item.get("kind", "task"),
                "limits": "not blocked",
                "inspect_kind": "task",
                "inspect_id": item["id"],
            }
            for item in tasks
            if item.get("status") == "await_approval"
        ][:50]
