from __future__ import annotations

from primordial.app.runtime_deps import (
    EventRecord,
    EventType,
    json,
    os,
    Path,
    re,
    ScopeProfile,
    Target,
    TaskRunStatus,
    TaskStatus,
    utc_now,
)

class RuntimeScopeAssetsMixin:
    def replace_target_scope_assets(
        self,
        *,
        handle: str,
        display_name: str,
        profile: ScopeProfile,
        in_scope: bool,
        active_ip: str | None,
        asset_rows: list[dict[str, object]],
    ) -> Target:
        """Replace all scope assets for a target atomically.

        Each row in asset_rows must contain: asset (str), asset_type (str),
        and optionally ports (str, default "*") and scope_rule (str, default "allow").
        Updating the active IP may create a new generation if the IP changes.
        No ticks are triggered — caller is responsible for orchestration.
        """
        handle = str(handle).strip()
        if not handle:
            raise ValueError("target handle is required")
        display_name = str(display_name or handle).strip() or handle
        parsed_active_ip = self._validated_optional_ip(active_ip) if active_ip else None
        environment_classification = self._classify_environment(
            profile=profile.value,
            asset_metadata=self._asset_metadata_from_entries(asset_rows),
        )
        self._ensure_profile_default_operator_intent(profile, classification=environment_classification)
        normalized_rows: list[dict[str, object]] = []
        for row in asset_rows:
            raw_asset = str(row["asset"]).strip()
            if not raw_asset:
                continue
            normalized_rows.append(
                {
                    "asset": raw_asset,
                    "asset_type": str(row.get("asset_type") or self._infer_asset_type(raw_asset)),
                    "metadata": {
                        "ports": str(row.get("ports") or "*"),
                        "scope_rule": str(row.get("scope_rule") or "allow"),
                        "operator_managed": True,
                    },
                }
            )

        outcome = self.store.replace_target_scope_assets(
            handle=handle,
            display_name=display_name,
            profile=profile,
            in_scope=in_scope,
            active_ip=parsed_active_ip,
            asset_rows=normalized_rows,
        )
        target = outcome["target"]
        if outcome.get("ip_changed"):
            self.memory.supersede_stale_generation_entries(target.id, str(outcome.get("active_ip_generation") or ""))

        self.findings_context.ensure_target(target)
        return target

    def diagnose_payload(self) -> dict[str, object]:
        """Return a human-readable diagnostic snapshot for operator troubleshooting."""
        from primordial.core.domain.enums import TaskStatus, TaskRunStatus

        tasks = self.store.list_tasks(limit=200)
        runs = self.store.list_task_runs(limit=50)
        targets = self.store.list_targets()
        mode = self.execution_mode_payload()
        models = self.models_payload()

        status_counts: dict[str, int] = {}
        for task in tasks:
            key = task.status.value
            status_counts[key] = status_counts.get(key, 0) + 1

        active_runs = [r for r in runs if r.status in {TaskRunStatus.CLAIMED, TaskRunStatus.RUNNING} and r.finished_at is None]
        failed_recent = [r for r in runs if r.status in {TaskRunStatus.FAILED, TaskRunStatus.TIMED_OUT}][:5]

        pending_approvals = [t for t in tasks if t.status == TaskStatus.NEEDS_APPROVAL]
        stuck_running = [t for t in tasks if t.status == TaskStatus.RUNNING]

        ollama_ok = False
        ollama_error = ""
        try:
            import urllib.request
            with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=3) as resp:
                ollama_ok = resp.status == 200
        except Exception as exc:  # noqa: BLE001
            ollama_error = str(exc)

        lines = [
            "=== Primordial System Diagnostics ===",
            f"Ollama reachable: {'yes' if ollama_ok else f'NO - {ollama_error}'}",
            f"Execution mode: {mode['mode']} (interval: {mode['interval_seconds']}s)",
            f"Targets: {len(targets)}  |  Tasks total: {len(tasks)}",
            f"Task status breakdown: {status_counts}",
        ]
        if active_runs:
            lines.append(f"Active runs ({len(active_runs)}):")
            for r in active_runs:
                age = (utc_now() - r.started_at).total_seconds()
                lines.append(f"  - {r.role.value} | {r.model_name} | {r.status.value} | running {age:.0f}s")
        else:
            lines.append("Active runs: none")
        if pending_approvals:
            lines.append(f"Awaiting approval ({len(pending_approvals)}):")
            for t in pending_approvals[:5]:
                lines.append(f"  - [{t.id}] {t.title}")
        if stuck_running:
            lines.append(f"Tasks stuck in RUNNING state (no active run): {len(stuck_running)}")
            lines.append("  -> Run 'repair_execution_state' or restart to recover")
        if failed_recent:
            lines.append("Recent failures:")
            for r in failed_recent:
                lines.append(f"  - {r.role.value} | {r.model_name} | {r.error or 'no error recorded'}")
        roles = models.get("roles", [])
        lines.append("Model routes:")
        for role in roles:
            if isinstance(role, dict):
                lines.append(f"  {role.get('role')}: {role.get('selected_model')} ({role.get('processor')})")
        if not targets:
            lines.append("WARNING: No targets configured — ticks will produce no tasks until scope is added")
        for target in targets:
            assets = self.store.list_scope_assets(target.id)
            lines.append(f"Target '{target.handle}': {len(assets)} scope asset(s) | active_ip={target.metadata.get('active_ip') or 'not set'}")
        return {"lines": lines, "summary": "\n".join(lines)}

    def remove_target(self, handle: str, profile: ScopeProfile | None = None) -> dict[str, object]:
        target = self.store.get_target_by_handle(handle, profile)
        if target is None:
            return {"removed": False, "handle": handle}
        allow_destructive_delete = (
            os.getenv("PRIMORDIAL_ALLOW_DESTRUCTIVE_TARGET_DELETE", "").strip()
            == "I_UNDERSTAND_TARGET_RUNTIME_RECORDS_WILL_BE_DELETED"
        )
        deletion = self.store.delete_target_cascade(
            target.id,
            allow_runtime_record_deletion=allow_destructive_delete,
            deletion_reason=f"operator requested target removal for {target.handle}",
        )
        if deletion.get("blocked"):
            self.store.insert_event(
                EventRecord(
                    type=EventType.SCOPE_UPDATED,
                    summary=f"Blocked destructive target removal: {target.handle}",
                    target_id=target.id,
                    metadata={
                        "profile": target.profile.value,
                        "reason": deletion.get("reason"),
                        "runtime_record_counts": deletion.get("runtime_record_counts", {}),
                    },
                )
            )
            return {
                "removed": False,
                "blocked": True,
                "handle": target.handle,
                "profile": target.profile.value,
                "reason": deletion.get("reason"),
                "runtime_record_counts": deletion.get("runtime_record_counts", {}),
            }
        self._cleanup_deleted_paths(deletion["artifact_paths"] + deletion["checkpoint_paths"])
        self.store.insert_event(
            EventRecord(
                type=EventType.SCOPE_UPDATED,
                summary=f"Removed target: {target.handle}",
                metadata={"profile": target.profile.value, "deleted_counts": deletion["deleted"]},
            )
        )
        return {
            "removed": True,
            "handle": target.handle,
            "profile": target.profile.value,
            "deleted": deletion["deleted"],
        }

    def _load_scope_payload(self, path: Path) -> dict[str, object]:
        if path.suffix.lower() == ".json":
            return json.loads(path.read_text())
        lines = [
            line.strip()
            for line in path.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        return {
            "profile": ScopeProfile.HACKERONE.value,
            "targets": [
                {
                    "handle": line,
                    "display_name": line,
                    "in_scope": True,
                    "assets": [{"asset": line, "asset_type": "hostname"}],
                }
                for line in lines
            ],
        }

    def _asset_metadata_from_entries(self, entries: list[str | dict[str, object]]) -> list[dict[str, object]]:
        metadata: list[dict[str, object]] = []
        for entry in entries:
            if isinstance(entry, dict) and isinstance(entry.get("metadata"), dict):
                metadata.append(dict(entry["metadata"]))
        return metadata

    def _normalize_scope_profile_id(self, value: str) -> str:
        normalized = re.sub(r"[^a-z0-9_]+", "_", str(value).strip().lower())
        normalized = normalized.strip("_")
        if not normalized:
            raise ValueError("scope profile id is required")
        return normalized[:64]
