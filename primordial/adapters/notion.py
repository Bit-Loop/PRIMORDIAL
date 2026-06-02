from __future__ import annotations

import json
import os
from urllib import error, request

from primordial.core.credentials import CredentialStore
from primordial.core.findings_context import FindingsContextService, TargetFindingsWorkspace
from primordial.core.events.bus import EventBus, RuntimeSignal
from primordial.core.domain.enums import EventType, ExternalSyncKind, ExternalSyncStatus
from primordial.core.domain.models import EventRecord, ExternalSyncJob, NotionPage, Target, utc_now
from primordial.core.sensitive_text import redact_sensitive_text
from primordial.core.storage.runtime import RuntimeStore


class NotionSyncError(RuntimeError):
    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


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
        if self._auth_blocked():
            self._suppress_pending_auth_blocked()
            return completed
        for _ in range(limit):
            job = self.store.claim_next_external_sync_job(kind=ExternalSyncKind.NOTION)
            if job is None:
                break
            if self._process_job(job):
                completed += 1
        return completed

    def _process_job(self, job: ExternalSyncJob) -> bool:
        target = self.store.get_target(job.target_id)
        if not target:
            self._fail_missing_target(job)
            return False
        workspace = self._sync_local_workspace(target)
        credentials = self._notion_credentials()
        if credentials is None:
            self._fail_missing_credentials(job, target, workspace)
            return False
        try:
            self._sync_target_pages(job, target, workspace, credentials)
        except (OSError, error.URLError, error.HTTPError, ValueError, NotionSyncError) as exc:
            self._fail_sync_exception(job, target, exc)
            return False
        self._mark_sync_succeeded(job, target)
        return True

    def _sync_local_workspace(self, target: Target) -> TargetFindingsWorkspace | None:
        if self.findings_context is None:
            return None
        return self.findings_context.sync_target_export(
            target,
            evidence=self.store.list_evidence(target_id=target.id, limit=100),
            notes=self.store.list_notes(target_id=target.id, limit=100),
            interests=self.store.list_interests(target_id=target.id, limit=100),
            findings=self.store.list_findings(target_id=target.id, limit=100),
        )

    def _notion_credentials(self) -> tuple[str, str, str] | None:
        api_key = self.credentials.get("notion", "api_key")
        parent_page_id = self.credentials.get("notion", "parent_page_id")
        api_version = self.credentials.get("notion", "version") or "2022-06-28"
        if not api_key or not parent_page_id:
            return None
        return api_key, parent_page_id, api_version

    def _fail_missing_target(self, job: ExternalSyncJob) -> None:
        job.status = ExternalSyncStatus.FAILED
        job.last_error = "target not found"
        self.store.insert_external_sync_job(job)

    def _fail_missing_credentials(
        self,
        job: ExternalSyncJob,
        target: Target,
        workspace: TargetFindingsWorkspace | None,
    ) -> None:
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

    def _sync_target_pages(
        self,
        job: ExternalSyncJob,
        target: Target,
        workspace: TargetFindingsWorkspace | None,
        credentials: tuple[str, str, str],
    ) -> None:
        api_key, parent_page_id, api_version = credentials
        root = self._create_root_page(api_key, api_version, parent_page_id, target, workspace)
        self._insert_root_page(job, target, root)
        self._create_child_pages(job, target, root, api_key, api_version)

    def _create_root_page(
        self,
        api_key: str,
        api_version: str,
        parent_page_id: str,
        target: Target,
        workspace: TargetFindingsWorkspace | None,
    ) -> dict[str, object]:
        target_title = self._safe_target_title(target)
        mirror_line = (
            f"Local Notion export mirror: {workspace.notion_export_path}"
            if workspace is not None
            else "Local Notion export mirror unavailable."
        )
        return self._create_page(
            api_key=api_key,
            api_version=api_version,
            parent_id=parent_page_id,
            title=f"{target_title} Workspace",
            children=[
                _paragraph(f"Target: {redact_sensitive_text(target.handle)}"),
                _paragraph(f"Profile: {target.profile.value}"),
                _paragraph(mirror_line),
            ],
        )

    def _insert_root_page(self, job: ExternalSyncJob, target: Target, root: dict[str, object]) -> None:
        target_title = self._safe_target_title(target)
        self.store.insert_notion_page(
            NotionPage(
                target_id=target.id,
                page_type="target-root",
                title=f"{target_title} Workspace",
                external_id=str(root["id"]),
                status="synced",
                url=str(root.get("url", "")),
                metadata={"job_id": job.id},
            )
        )

    def _create_child_pages(
        self,
        job: ExternalSyncJob,
        target: Target,
        root: dict[str, object],
        api_key: str,
        api_version: str,
    ) -> None:
        target_title = self._safe_target_title(target)
        for child in (
            "overview",
            "notes",
            "evidence-links",
            "findings",
            "open-hypotheses",
            "next-actions",
            "agent-guidance",
        ):
            child_page = self._create_page(
                api_key=api_key,
                api_version=api_version,
                parent_id=str(root["id"]),
                title=f"{target_title} {child.replace('-', ' ').title()}",
                children=[_paragraph(self._child_body(target, child))],
            )
            self._insert_child_page(job, target, root, child, child_page)

    def _child_body(self, target: Target, child: str) -> str:
        if child == "agent-guidance" and self.findings_context is not None:
            return redact_sensitive_text(self.findings_context.read_guidance(target, max_chars=1800))
        return f"Primordial {child.replace('-', ' ')} view for {redact_sensitive_text(target.handle)}."

    def _insert_child_page(
        self,
        job: ExternalSyncJob,
        target: Target,
        root: dict[str, object],
        child: str,
        child_page: dict[str, object],
    ) -> None:
        target_title = self._safe_target_title(target)
        self.store.insert_notion_page(
            NotionPage(
                target_id=target.id,
                page_type=child,
                title=f"{target_title} {child.replace('-', ' ').title()}",
                external_id=str(child_page["id"]),
                status="synced",
                url=str(child_page.get("url", "")),
                metadata={"job_id": job.id, "parent": root["id"]},
            )
        )

    def _safe_target_title(self, target: Target) -> str:
        return redact_sensitive_text(target.display_name)

    def _fail_sync_exception(self, job: ExternalSyncJob, target: Target, exc: BaseException) -> None:
        safe_error = redact_sensitive_text(str(exc))
        job.status = ExternalSyncStatus.FAILED
        job.last_error = safe_error
        if self._is_auth_failure(exc):
            job.metadata["auth_blocked"] = True
            job.metadata["auth_blocked_at"] = utc_now().isoformat()
            self._mark_auth_blocked(safe_error)
        self.store.insert_external_sync_job(job)
        self.store.insert_event(
            EventRecord(
                type=EventType.SYNC_FAILED,
                summary=f"Notion sync failed for {self._safe_target_title(target)}: {safe_error}",
                target_id=target.id,
            )
        )
        if self._is_auth_failure(exc):
            self._suppress_pending_auth_blocked()

    def _mark_sync_succeeded(self, job: ExternalSyncJob, target: Target) -> None:
        job.status = ExternalSyncStatus.SUCCEEDED
        job.last_error = None
        self.store.insert_external_sync_job(job)
        self.store.insert_event(
            EventRecord(
                type=EventType.SYNC_COMPLETED,
                summary=f"Notion sync completed for {self._safe_target_title(target)}",
                target_id=target.id,
            )
        )
        if self.event_bus is not None:
            self.event_bus.emit(
                RuntimeSignal.SYNC_COMPLETED,
                {"target_id": target.id, "kind": "notion", "job_id": job.id},
            )

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
            raise NotionSyncError(f"Notion API returned {exc.code}: {detail}", status_code=exc.code) from exc

    def _auth_blocked(self) -> bool:
        return bool(self.credentials.service_status("notion").get("auth_blocked"))

    def _is_auth_failure(self, exc: BaseException) -> bool:
        status_code = getattr(exc, "status_code", None)
        if status_code in {401, 403}:
            return True
        if isinstance(exc, error.HTTPError) and exc.code in {401, 403}:
            return True
        return False

    def _mark_auth_blocked(self, reason: str) -> None:
        self.credentials.set_service_status(
            "notion",
            {
                "auth_blocked": True,
                "auth_blocked_at": utc_now().isoformat(),
                "last_error": redact_sensitive_text(reason),
            },
        )

    def _suppress_pending_auth_blocked(self) -> int:
        return self.store.fail_pending_external_sync_jobs(
            kind=ExternalSyncKind.NOTION,
            reason="Notion sync suppressed after authentication failure; save or clear Notion credentials to retry",
            metadata_patch={"auth_blocked": True},
        )


def _paragraph(text: str) -> dict[str, object]:
    return {
        "object": "block",
        "type": "paragraph",
        "paragraph": {"rich_text": [{"type": "text", "text": {"content": text[:1900]}}]},
    }
