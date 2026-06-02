from __future__ import annotations

from primordial.app.runtime_deps import (
    build_work_status_payload,
    classify_credentialed_access_surface,
    credentialed_access_blocker,
    current_generation_evidence,
    DashboardSnapshot,
    EvidenceRecord,
    json_ready,
    missing_verified_path_blocker,
    poc_validation_blocker,
    stale_recon_blocker,
    work_status_capabilities,
)

class RuntimePayloadsMixin:
    def dashboard(self) -> DashboardSnapshot:
        counts = self.store.count_all()
        return DashboardSnapshot(
            counts=counts,
            sessions=self.store.list_sessions(limit=4),
            targets=self.store.list_targets(),
            tasks=self.store.list_tasks(limit=12),
            task_runs=self.store.list_task_runs(limit=10),
            notes=self.store.list_notes(limit=6),
            interests=self.store.list_interests(limit=6),
            findings=self.store.list_findings(limit=6),
            notifications=self.store.list_notifications(limit=6),
            sync_jobs=self.store.list_external_sync_jobs(limit=6),
            events=self.store.list_events(limit=10),
        )

    def dashboard_payload(self) -> dict[str, object]:
        payload = json_ready(self.dashboard())
        payload["execution_mode"] = self.execution_mode_payload()
        payload["runtime_tuning"] = self.runtime_tuning_payload()
        payload["system_metrics"] = self.system_metrics_payload()
        payload["work_status"] = self.work_status_payload()
        payload["operator_intent"] = self.operator_intent_payload()
        return payload

    def work_status_payload(self, *, limit: int = 8) -> dict[str, object]:
        self.repair_execution_state()
        tasks = self.store.list_tasks(limit=500)
        runs = self.store.list_task_runs(limit=200)
        targets = {target.id: target for target in self.store.list_targets()}
        mode = self.execution_mode_payload()
        blockers = self._work_status_blockers()
        return build_work_status_payload(
            tasks=tasks,
            runs=runs,
            targets=targets,
            mode=mode,
            blockers=blockers,
            live_methodology_state=self._live_methodology_state_payload,
            limit=limit,
        )

    def _work_status_blockers(self) -> list[dict[str, object]]:
        blockers: list[dict[str, object]] = []
        capabilities = work_status_capabilities(self.store.list_primitives())
        lab_credentials_configured = self._lab_credentials_configured()
        intent_policy = self.intent_policy()
        for target in self.store.list_targets():
            evidence = self.store.list_evidence(target_id=target.id, limit=100)
            active_generation = self._target_active_generation(target)
            current_evidence = current_generation_evidence(
                evidence,
                active_generation,
                self._record_matches_active_generation,
            )
            interests = self.store.list_interests(target_id=target.id, limit=100)
            findings = self.store.list_findings(target_id=target.id, limit=20)

            blocker = stale_recon_blocker(target, evidence)
            if blocker:
                blockers.append(blocker)
                continue
            blocker = poc_validation_blocker(
                target,
                evidence,
                interests,
                capabilities,
                self._poc_adaptation_available,
                intent_policy,
            )
            if blocker:
                blockers.append(blocker)
                continue
            blocker = credentialed_access_blocker(
                target,
                current_evidence,
                capabilities,
                lab_credentials_configured,
                self._has_any_capability,
                intent_policy,
            )
            if blocker:
                blockers.append(blocker)
                continue
            blocker = missing_verified_path_blocker(target, findings, evidence)
            if blocker:
                blockers.append(blocker)
        return blockers[:8]

    def _target_has_remote_admin_surface(self, evidence: list[EvidenceRecord]) -> bool:
        return classify_credentialed_access_surface(evidence).eligible

    def audit_payload(self, limit: int = 25) -> dict[str, object]:
        return {
            "counts": self.store.count_all(),
            "recent_events": [item.as_payload() for item in self.store.list_events(limit=limit)],
            "recent_traces": [item.as_payload() for item in self.store.list_traces(limit=limit)],
            "recent_checkpoints": [item.as_payload() for item in self.store.list_checkpoints(limit=limit)],
            "recent_notifications": [item.as_payload() for item in self.store.list_notifications(limit=limit)],
            "recent_sync_jobs": [item.as_payload() for item in self.store.list_external_sync_jobs(limit=limit)],
            "recent_runtime_events": [
                {
                    "signal": event.signal.value,
                    "payload": json_ready(event.payload),
                    "created_at": event.created_at.isoformat(),
                }
                for event in self.event_bus.recent(limit=limit)
            ],
        }

    def records_payload(self, limit: int = 25, target_id: str | None = None) -> dict[str, object]:
        target = self.store.get_target(target_id) if target_id else None
        return {
            "evidence": [item.as_payload() for item in self.store.list_evidence(target_id=target_id, limit=limit)],
            "notes": [item.as_payload() for item in self.store.list_notes(target_id=target_id, limit=limit)],
            "interests": [item.as_payload() for item in self.store.list_interests(target_id=target_id, limit=limit)],
            "findings": [item.as_payload() for item in self.store.list_findings(target_id=target_id, limit=limit)],
            "memory_entries": [
                item.as_payload() for item in self.store.list_memory_entries(target_id=target_id, limit=limit)
            ],
            "artifacts": [
                item.as_payload()
                for item in self.store.list_artifacts(limit=limit)
                if target_id is None or item.target_id == target_id
            ],
            "notifications": [item.as_payload() for item in self.store.list_notifications(limit=limit)],
            "sync_jobs": [item.as_payload() for item in self.store.list_external_sync_jobs(limit=limit)],
            "primitives": [item.as_payload() for item in self.store.list_primitives()],
            "operator_messages": [
                item.as_payload() for item in self.store.list_operator_messages(target_id=target_id, limit=limit)
            ],
            "findings_context": (
                self.findings_context.payload_for_target(target, include_guidance=False)
                if target
                else None
            ),
        }

    def operator_chat_payload(self, limit: int = 20, target: str | None = None) -> dict[str, object]:
        target_record = self._resolve_target_reference(target)
        return {
            "target": target_record.as_payload() if target_record else None,
            "messages": [
                item.as_payload()
                for item in reversed(
                    self.store.list_operator_messages(
                        target_id=target_record.id if target_record else None,
                        limit=limit,
                    )
                )
            ],
        }

    def task_audit_payload(self, task_id: str, limit: int = 25) -> dict[str, object] | None:
        task = self.store.get_task(task_id)
        if task is None:
            return None
        target = self.store.get_target(task.target_id)
        runs = self.store.list_task_runs(task_id=task_id, limit=limit)
        run_ids = {run.id for run in runs}
        checkpoints = [
            item.as_payload()
            for item in self.store.list_checkpoints(limit=limit * 5)
            if item.task_id == task_id or item.run_id in run_ids
        ][:limit]
        events = [
            item.as_payload()
            for item in self.store.list_events(limit=limit * 5)
            if item.task_id == task_id
        ][:limit]
        return {
            "task": task.as_payload(),
            "target": target.as_payload() if target else None,
            "runs": [item.as_payload() for item in runs],
            "traces": [item.as_payload() for item in self.store.list_traces(task_id=task_id, limit=limit)],
            "handoffs": [item.as_payload() for item in self.store.list_handoffs(task_id=task_id, limit=limit)],
            "checkpoints": checkpoints,
            "events": events,
        }
