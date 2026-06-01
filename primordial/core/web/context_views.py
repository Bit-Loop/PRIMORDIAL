from __future__ import annotations

from typing import Any


class WebContextViewsMixin:
    def _notes_view(
        self,
        targets: list[dict[str, Any]],
        findings_context: dict[str, Any],
        credentials: dict[str, Any],
        audit: dict[str, Any],
    ) -> dict[str, Any]:
        credential_services = credentials.get("services", {}) if isinstance(credentials.get("services"), dict) else {}
        notion_fields = credential_services.get("notion", {}) if isinstance(credential_services.get("notion"), dict) else {}
        notion_configured = any(
            isinstance(field, dict) and field.get("configured")
            for field in notion_fields.values()
        )
        target_rows = []
        folders = []
        pages: dict[str, dict[str, str]] = {}
        context_targets = findings_context.get("targets", []) if isinstance(findings_context.get("targets", []), list) else []
        context_by_id = {
            str(item.get("target", {}).get("id") or item.get("target", {}).get("handle")): item.get("workspace", {})
            for item in context_targets
            if isinstance(item, dict) and isinstance(item.get("target"), dict)
        }
        for index, item in enumerate(targets):
            target = item.get("target", {}) if isinstance(item.get("target"), dict) else {}
            handle = str(target.get("handle") or "")
            if not handle:
                continue
            target_rows.append(
                {
                    "id": handle,
                    "label": str(target.get("display_name") or handle),
                    "profile": str(target.get("profile") or ""),
                    "active": index == 0,
                }
            )
            root_id = f"{handle}_root"
            page_id = f"{handle}_findings"
            folders.append(
                {
                    "id": root_id,
                    "label": f"{handle} Workspace",
                    "target": handle,
                    "kind": "target-root",
                    "synced": False,
                    "url": "#",
                    "children": [
                        {"id": page_id, "label": "Findings Context", "kind": "findings", "synced": False, "url": "#"},
                    ],
                }
            )
            workspace = context_by_id.get(str(target.get("id")), {})
            pages[page_id] = {
                "title": f"{handle} Findings Context",
                "body": self._workspace_body(target, workspace),
            }
        if not target_rows:
            pages["workspace_empty"] = {
                "title": "Findings Context",
                "body": "No targets are currently registered in the runtime.",
            }
        return {
            "targets": target_rows,
            "syncStatus": {
                "ok": notion_configured,
                "lastSync": self._time_label((audit.get("recent_sync_jobs") or [{}])[0].get("updated_at") if audit.get("recent_sync_jobs") else None),
                "pendingJobs": 0,
                "failedJobs": len(audit.get("recent_sync_jobs", []) or []),
                "configured": notion_configured,
            },
            "folders": folders,
            "pages": pages,
        }

    def _interests_view(self, records: dict[str, Any], targets: list[dict[str, Any]]) -> dict[str, Any]:
        surfaces = []
        for index, item in enumerate(targets):
            target = item.get("target", {}) if isinstance(item.get("target"), dict) else {}
            assets = item.get("assets", []) if isinstance(item.get("assets"), list) else []
            handle = str(target.get("handle") or "")
            for asset in assets[:20]:
                if not isinstance(asset, dict):
                    continue
                surfaces.append(
                    {
                        "id": str(asset.get("id") or f"srf_{index}_{len(surfaces)}"),
                        "target": handle,
                        "kind": str(asset.get("asset_type") or "asset"),
                        "ports": str(asset.get("metadata", {}).get("ports") or "*"),
                        "severity": "info",
                        "status": "active" if target.get("in_scope", True) else "paused",
                        "desc": str(asset.get("asset") or ""),
                    }
                )
        findings = [
            {
                "id": str(item.get("id") or ""),
                "severity": str(item.get("severity") or "info"),
                "title": str(item.get("title") or "Finding"),
                "status": str(item.get("verification_status") or item.get("status") or "unverified"),
                "evidence": item.get("evidence_ids", []) if isinstance(item.get("evidence_ids", []), list) else [],
                "desc": str(item.get("summary") or item.get("description") or ""),
            }
            for item in records.get("findings", []) if isinstance(item, dict)
        ]
        pocs = [
            {
                "id": str(item.get("id") or ""),
                "edb": str(item.get("metadata", {}).get("edb") or "N/A"),
                "title": str(item.get("title") or item.get("summary") or "Interest"),
                "platform": str(item.get("metadata", {}).get("platform") or ""),
                "status": str(item.get("status") or "open"),
                "gated": bool(item.get("metadata", {}).get("gated", False)),
                "applicability": str(item.get("summary") or item.get("description") or ""),
                "evidence": item.get("evidence_ids", []) if isinstance(item.get("evidence_ids", []), list) else [],
                "generated": False,
                "downloadable": False,
            }
            for item in records.get("interests", []) if isinstance(item, dict)
        ]
        artifacts = [
            {
                "id": str(item.get("id") or ""),
                "kind": str(item.get("kind") or "artifact"),
                "task": str(item.get("task_id") or ""),
                "title": str(item.get("title") or item.get("path") or "Artifact"),
                "target": str(item.get("target_id") or ""),
                "size": str(item.get("size") or item.get("size_bytes") or ""),
                "downloadable": False,
                "inspect_kind": "artifact",
                "inspect_id": str(item.get("id") or ""),
            }
            for item in records.get("artifacts", []) if isinstance(item, dict)
        ]
        return {"surfaces": surfaces, "findings": findings, "pocs": pocs, "artifacts": artifacts}
