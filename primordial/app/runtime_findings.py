from __future__ import annotations

from primordial.app.runtime_deps import (
    EventRecord,
    EventType,
)

class RuntimeFindingsMixin:
    def findings_context_payload(self, *, target: str | None = None, include_guidance: bool = True) -> dict[str, object]:
        target_record = self._resolve_target_reference(target) if target else None
        if target_record is None and target:
            raise ValueError("target not found")
        if target_record is not None:
            return {
                "target": target_record.as_payload(),
                "workspace": self.findings_context.payload_for_target(
                    target_record,
                    include_guidance=include_guidance,
                ),
            }
        return {
            "findings_dir": str(self.config.findings_dir),
            "notion_exports_dir": str(self.config.notion_exports_dir),
            "targets": [
                {
                    "target": item.as_payload(),
                    "workspace": self.findings_context.payload_for_target(item, include_guidance=False),
                }
                for item in self.store.list_targets()
            ],
        }

    def update_target_guidance(self, target: str, body: str) -> dict[str, object]:
        target_record = self._resolve_target_reference(target)
        if target_record is None:
            raise ValueError("target not found")
        workspace = self.findings_context.write_guidance(target_record, body)
        self.store.insert_event(
            EventRecord(
                type=EventType.SCOPE_UPDATED,
                summary=f"Updated agent guidance for {target_record.handle}",
                target_id=target_record.id,
                metadata={"guidance_path": str(workspace.guidance_path)},
            )
        )
        self.sync_findings_context_exports()
        return self.findings_context_payload(target=target_record.id, include_guidance=True)

    def sync_findings_context_exports(self) -> dict[str, object]:
        synced = []
        for target in self.store.list_targets():
            workspace = self.findings_context.sync_target_export(
                target,
                evidence=self.store.list_evidence(target_id=target.id, limit=100),
                notes=self.store.list_notes(target_id=target.id, limit=100),
                interests=self.store.list_interests(target_id=target.id, limit=100),
                findings=self.store.list_findings(target_id=target.id, limit=100),
            )
            synced.append({"target": target.handle, "workspace": workspace.as_payload()})
        return {"synced": synced}

    def audit_findings_context_exports(self) -> dict[str, object]:
        return self.findings_context.audit_generated_exports()
