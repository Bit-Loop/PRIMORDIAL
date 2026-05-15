from __future__ import annotations

import json
import os
from urllib import error, request

from primordial.core.credentials import CredentialStore
from primordial.core.findings_context import FindingsContextService
from primordial.core.events.bus import EventBus, RuntimeSignal
from primordial.core.domain.enums import EventType, ExternalSyncKind, ExternalSyncStatus
from primordial.core.domain.models import EventRecord, NotionPage
from primordial.core.storage.runtime import RuntimeStore


class NotionSyncService:
    def __init__(
        self,
        store: RuntimeStore,
        credentials: CredentialStore,
        event_bus: EventBus | None = None,
        findings_context: FindingsContextService | None = None,
    ) -> None:
        self.store = store
        self.credentials = credentials
        self.event_bus = event_bus
        self.findings_context = findings_context
        self.base_url = os.getenv("NOTION_API_BASE_URL", "https://api.notion.com/v1").rstrip("/")

    def process_pending(self, limit: int = 10) -> int:
        completed = 0
        for _ in range(limit):
            job = self.store.claim_next_external_sync_job(kind=ExternalSyncKind.NOTION)
            if job is None:
                break
            target = self.store.get_target(job.target_id)
            if not target:
                job.status = ExternalSyncStatus.FAILED
                job.last_error = "target not found"
                self.store.insert_external_sync_job(job)
                continue
            workspace = None
            if self.findings_context is not None:
                workspace = self.findings_context.sync_target_export(
                    target,
                    evidence=self.store.list_evidence(target_id=target.id, limit=100),
                    notes=self.store.list_notes(target_id=target.id, limit=100),
                    interests=self.store.list_interests(target_id=target.id, limit=100),
                    findings=self.store.list_findings(target_id=target.id, limit=100),
                )

            api_key = self.credentials.get("notion", "api_key")
            parent_page_id = self.credentials.get("notion", "parent_page_id")
            api_version = self.credentials.get("notion", "version") or "2022-06-28"
            if not api_key or not parent_page_id:
                job.status = ExternalSyncStatus.FAILED
                job.last_error = "Notion API key and parent page ID are required for Notion sync"
                if workspace is not None:
                    job.metadata["local_export_path"] = str(workspace.notion_export_path)
                self.store.insert_external_sync_job(job)
                self.store.insert_event(
                    EventRecord(
                        type=EventType.SYNC_FAILED,
                        summary=job.last_error,
                        target_id=target.id,
                    )
                )
                continue

            try:
                root = self._create_page(
                    api_key=api_key,
                    api_version=api_version,
                    parent_id=parent_page_id,
                    title=f"{target.display_name} Workspace",
                    children=[
                        self._paragraph(f"Target: {target.handle}"),
                        self._paragraph(f"Profile: {target.profile.value}"),
                        self._paragraph(
                            f"Local Notion export mirror: {workspace.notion_export_path}"
                            if workspace is not None
                            else "Local Notion export mirror unavailable."
                        ),
                    ],
                )
                self.store.insert_notion_page(
                    NotionPage(
                        target_id=target.id,
                        page_type="target-root",
                        title=f"{target.display_name} Workspace",
                        external_id=str(root["id"]),
                        status="synced",
                        url=str(root.get("url", "")),
                        metadata={"job_id": job.id},
                    )
                )
                for child in (
                    "overview",
                    "notes",
                    "evidence-links",
                    "findings",
                    "open-hypotheses",
                    "next-actions",
                    "agent-guidance",
                ):
                    child_body = (
                        self.findings_context.read_guidance(target, max_chars=1800)
                        if child == "agent-guidance" and self.findings_context is not None
                        else f"Primordial {child.replace('-', ' ')} view for {target.handle}."
                    )
                    child_page = self._create_page(
                        api_key=api_key,
                        api_version=api_version,
                        parent_id=str(root["id"]),
                        title=f"{target.display_name} {child.replace('-', ' ').title()}",
                        children=[self._paragraph(child_body)],
                    )
                    self.store.insert_notion_page(
                        NotionPage(
                            target_id=target.id,
                            page_type=child,
                            title=f"{target.display_name} {child.replace('-', ' ').title()}",
                            external_id=str(child_page["id"]),
                            status="synced",
                            url=str(child_page.get("url", "")),
                            metadata={"job_id": job.id, "parent": root["id"]},
                        )
                    )
            except (OSError, error.URLError, error.HTTPError, ValueError) as exc:
                job.status = ExternalSyncStatus.FAILED
                job.last_error = str(exc)
                self.store.insert_external_sync_job(job)
                self.store.insert_event(
                    EventRecord(
                        type=EventType.SYNC_FAILED,
                        summary=f"Notion sync failed for {target.display_name}: {exc}",
                        target_id=target.id,
                    )
                )
                continue

            job.status = ExternalSyncStatus.SUCCEEDED
            job.last_error = None
            self.store.insert_external_sync_job(job)
            self.store.insert_event(
                EventRecord(
                    type=EventType.SYNC_COMPLETED,
                    summary=f"Notion sync completed for {target.display_name}",
                    target_id=target.id,
                )
            )
            if self.event_bus is not None:
                self.event_bus.emit(
                    RuntimeSignal.SYNC_COMPLETED,
                    {"target_id": target.id, "kind": "notion", "job_id": job.id},
                )
            completed += 1
        return completed

    def _create_page(
        self,
        *,
        api_key: str,
        api_version: str,
        parent_id: str,
        title: str,
        children: list[dict[str, object]],
    ) -> dict[str, object]:
        payload = {
            "parent": {"page_id": parent_id},
            "properties": {"title": {"title": [{"text": {"content": title}}]}},
            "children": children,
        }
        return self._request_json("POST", "/pages", payload, api_key=api_key, api_version=api_version)

    def _request_json(
        self,
        method: str,
        path: str,
        payload: dict[str, object],
        *,
        api_key: str,
        api_version: str,
    ) -> dict[str, object]:
        body = json.dumps(payload).encode("utf-8")
        req = request.Request(
            f"{self.base_url}{path}",
            data=body,
            method=method,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "Notion-Version": api_version,
            },
        )
        try:
            with request.urlopen(req, timeout=20) as response:
                return json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise ValueError(f"Notion API returned {exc.code}: {detail}") from exc

    def _paragraph(self, text: str) -> dict[str, object]:
        return {
            "object": "block",
            "type": "paragraph",
            "paragraph": {"rich_text": [{"type": "text", "text": {"content": text[:1900]}}]},
        }
