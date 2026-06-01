from __future__ import annotations

from typing import Any

from primordial.core.web.payload_views import traces_view


class WebScopeViewsMixin:
    def _events_view(self, audit: dict[str, Any]) -> list[dict[str, str]]:
        events: list[dict[str, str]] = []
        for item in audit.get("recent_events", []) if isinstance(audit.get("recent_events", []), list) else []:
            if not isinstance(item, dict):
                continue
            events.append(
                {
                    "t": self._time_label(item.get("created_at")),
                    "lvl": self._event_level(str(item.get("type", ""))),
                    "msg": str(item.get("summary") or item.get("type") or "event"),
                }
            )
        for item in audit.get("recent_runtime_events", []) if isinstance(audit.get("recent_runtime_events", []), list) else []:
            if not isinstance(item, dict):
                continue
            events.append(
                {
                    "t": self._time_label(item.get("created_at")),
                    "lvl": "info",
                    "msg": str(item.get("signal") or "runtime event"),
                }
            )
        return events[:80]

    def _scope_view(self, targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
        rows = []
        for item in targets:
            target = item.get("target", {}) if isinstance(item.get("target"), dict) else {}
            counts = item.get("counts", {}) if isinstance(item.get("counts"), dict) else {}
            assets = item.get("assets", []) if isinstance(item.get("assets"), list) else []
            rows.append(
                {
                    "handle": str(target.get("handle") or ""),
                    "profile": str(target.get("profile") or ""),
                    "ip": str(target.get("metadata", {}).get("active_ip") or self._first_asset(assets, "ip") or ""),
                    "assets": int(counts.get("assets", len(assets)) or 0),
                    "evidence": int(counts.get("evidence", 0) or 0),
                    "findings": int(counts.get("findings", 0) or 0),
                    "status": "active" if target.get("in_scope", True) else "paused",
                }
            )
        return rows

    def _graph_view(self, targets: list[dict[str, Any]], records: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []
        x = 180
        y = 90
        for index, item in enumerate(targets):
            target = item.get("target", {}) if isinstance(item.get("target"), dict) else {}
            handle = str(target.get("handle") or "")
            if not handle:
                continue
            node_id = f"target_{index}"
            nodes.append({"id": node_id, "kind": "domain", "label": handle, "sub": str(target.get("profile") or ""), "x": x, "y": y})
            assets = item.get("assets", []) if isinstance(item.get("assets"), list) else []
            for asset_index, asset in enumerate(assets[:12]):
                if not isinstance(asset, dict):
                    continue
                kind = "host" if asset.get("asset_type") == "ip" else "svc" if asset.get("asset_type") in {"url", "webapp"} else "domain"
                asset_id = f"{node_id}_asset_{asset_index}"
                nodes.append(
                    {
                        "id": asset_id,
                        "kind": kind,
                        "label": str(asset.get("asset") or ""),
                        "sub": str(asset.get("asset_type") or "asset"),
                        "x": x + 220 + (asset_index % 4) * 150,
                        "y": y + (asset_index // 4) * 95,
                    }
                )
                edges.append({"a": node_id, "b": asset_id, "label": "scope"})
            x += 150
            y += 90
        for index, finding in enumerate(records.get("findings", []) if isinstance(records.get("findings", []), list) else []):
            if not isinstance(finding, dict):
                continue
            node_id = f"finding_{index}"
            nodes.append(
                {
                    "id": node_id,
                    "kind": "finding",
                    "label": str(finding.get("title") or finding.get("id") or "finding"),
                    "sub": str(finding.get("severity") or finding.get("status") or ""),
                    "x": 280 + (index % 5) * 180,
                    "y": 440 + (index // 5) * 90,
                }
            )
        return {"nodes": nodes, "edges": edges}

    def _traces_view(
        self,
        audit: dict[str, Any],
        tasks: list[dict[str, Any]],
        *,
        selected_target: str | None = None,
    ) -> list[dict[str, Any]]:
        return traces_view(self, audit, tasks, selected_target=selected_target)

    def _plan_view(
        self,
        intent: dict[str, Any],
        dashboard: dict[str, Any],
        skills: dict[str, Any],
        work_status: dict[str, Any],
        records: dict[str, Any],
    ) -> dict[str, Any]:
        active_intent = intent.get("active", {}) if isinstance(intent.get("active"), dict) else {}
        policy = active_intent.get("policy", {}) if isinstance(active_intent.get("policy"), dict) else {}
        task_counts = work_status.get("counts", {}) if isinstance(work_status.get("counts"), dict) else {}
        total_tasks = int(task_counts.get("active", 0) or 0) + int(task_counts.get("queued", 0) or 0) + int(task_counts.get("waiting", 0) or 0)
        return {
            "methodology": {
                "id": str(dashboard.get("sessions", [{}])[0].get("methodology", "runtime") if dashboard.get("sessions") else "runtime"),
                "label": "Runtime Methodology",
                "description": "Live methodology state derived from runtime tasks and target progress.",
                "phases": [
                    {"id": "active", "label": "Active", "status": "active" if total_tasks else "done", "tasks": total_tasks, "done": 0},
                    {"id": "waiting", "label": "Waiting", "status": "active" if task_counts.get("waiting") else "done", "tasks": int(task_counts.get("waiting", 0) or 0), "done": 0},
                    {"id": "queued", "label": "Queued", "status": "active" if task_counts.get("queued") else "done", "tasks": int(task_counts.get("queued", 0) or 0), "done": 0},
                    {"id": "complete", "label": "Complete", "status": "done", "tasks": len(records.get("evidence", []) or []), "done": len(records.get("evidence", []) or [])},
                ],
            },
            "intent": {
                "id": str(active_intent.get("id") or "recon_only"),
                "label": str(active_intent.get("label") or active_intent.get("id") or "Recon Only"),
                "flags": self._intent_policy_flags(policy),
                "policy": policy,
            },
            "autonomy": str(self.runtime.config.autonomy.mode.value),
            "autonomyModes": ["manual", "assisted", "supervised", "supervised_auto", "high_autonomy"],
            "pinnedAssets": self._pinned_assets_view(records),
            "playbooks": self._playbooks_view(skills),
            "skills": self._skills_view(skills),
            "criticalThinking": self._critical_thinking_view(work_status),
        }
