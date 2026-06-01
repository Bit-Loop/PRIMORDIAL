from __future__ import annotations

from primordial.core.storage.runtime_common import *


class RuntimeNotificationsSyncMixin:
    def insert_notification(self, notification: NotificationRecord) -> None:
        self._execute(
            """
            INSERT INTO notifications
            (id, channel, event_type, summary, target_id, task_id, finding_id, status, urgency, dedupe_key, metadata, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET channel = EXCLUDED.channel, event_type = EXCLUDED.event_type, summary = EXCLUDED.summary, target_id = EXCLUDED.target_id, task_id = EXCLUDED.task_id, finding_id = EXCLUDED.finding_id, status = EXCLUDED.status, urgency = EXCLUDED.urgency, dedupe_key = EXCLUDED.dedupe_key, metadata = EXCLUDED.metadata, created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at
            """,
            (
                notification.id,
                notification.channel.value,
                notification.event_type,
                notification.summary,
                notification.target_id,
                notification.task_id,
                notification.finding_id,
                notification.status.value,
                notification.urgency,
                notification.dedupe_key,
                _dump(notification.metadata),
                notification.created_at.isoformat(),
                notification.updated_at.isoformat(),
            ),
        )

    def list_notifications(
        self,
        *,
        status: NotificationStatus | None = None,
        limit: int = 100,
    ) -> list[NotificationRecord]:
        if status:
            rows = self._query(
                "SELECT * FROM notifications WHERE status = %s ORDER BY created_at DESC LIMIT %s",
                (status.value, limit),
            )
        else:
            rows = self._query("SELECT * FROM notifications ORDER BY created_at DESC LIMIT %s", (limit,))
        return [self._notification_from_row(row) for row in rows]

    def get_notification(self, notification_id: str) -> NotificationRecord | None:
        row = self._query_one("SELECT * FROM notifications WHERE id = %s", (notification_id,))
        return self._notification_from_row(row) if row else None

    def insert_external_sync_job(self, job: ExternalSyncJob) -> None:
        self._execute(
            """
            INSERT INTO external_sync_jobs
            (id, kind, target_id, summary, payload, status, metadata, last_error, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET kind = EXCLUDED.kind, target_id = EXCLUDED.target_id, summary = EXCLUDED.summary, payload = EXCLUDED.payload, status = EXCLUDED.status, metadata = EXCLUDED.metadata, last_error = EXCLUDED.last_error, created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at
            """,
            (
                job.id,
                job.kind.value,
                job.target_id,
                job.summary,
                _dump(job.payload),
                job.status.value,
                _dump(job.metadata),
                job.last_error,
                job.created_at.isoformat(),
                job.updated_at.isoformat(),
            ),
        )

    def list_external_sync_jobs(
        self,
        *,
        status: ExternalSyncStatus | None = None,
        limit: int = 100,
    ) -> list[ExternalSyncJob]:
        if status:
            rows = self._query(
                "SELECT * FROM external_sync_jobs WHERE status = %s ORDER BY created_at DESC LIMIT %s",
                (status.value, limit),
            )
        else:
            rows = self._query(
                "SELECT * FROM external_sync_jobs ORDER BY created_at DESC LIMIT %s",
                (limit,),
            )
        return [self._sync_job_from_row(row) for row in rows]

    def get_external_sync_job(self, job_id: str) -> ExternalSyncJob | None:
        row = self._query_one("SELECT * FROM external_sync_jobs WHERE id = %s", (job_id,))
        return self._sync_job_from_row(row) if row else None

    def claim_next_external_sync_job(
        self,
        *,
        kind: ExternalSyncKind | None = None,
    ) -> ExternalSyncJob | None:
        params: list[Any] = [ExternalSyncStatus.PENDING.value]
        kind_clause = ""
        if kind is not None:
            kind_clause = "AND kind = %s"
            params.append(kind.value)
        with closing(self.connect()) as connection:
            connection.execute("BEGIN")
            row = connection.execute(
                f"""
                SELECT *
                FROM external_sync_jobs
                WHERE status = %s
                  {kind_clause}
                ORDER BY created_at ASC
                LIMIT 1
                FOR UPDATE SKIP LOCKED
                """,
                tuple(params),
            ).fetchone()
            if row is None:
                connection.commit()
                return None
            claimed = connection.execute(
                """
                UPDATE external_sync_jobs
                SET status = %s, updated_at = %s, metadata = metadata || %s
                WHERE id = %s AND status = %s
                RETURNING *
                """,
                (
                    ExternalSyncStatus.RUNNING.value,
                    utc_now().isoformat(),
                    _dump({"claimed_for_sync": True}),
                    row["id"],
                    ExternalSyncStatus.PENDING.value,
                ),
            ).fetchone()
            connection.commit()
        return self._sync_job_from_row(claimed) if claimed else None

    def fail_pending_external_sync_jobs(
        self,
        *,
        kind: ExternalSyncKind,
        reason: str,
        metadata_patch: dict[str, object] | None = None,
    ) -> int:
        now = utc_now().isoformat()
        metadata = {
            "suppressed_pending_sync": True,
            "suppression_reason": reason,
            **(metadata_patch or {}),
        }
        with closing(self.connect()) as connection:
            connection.execute("BEGIN")
            cursor = connection.execute(
                """
                UPDATE external_sync_jobs
                SET status = %s,
                    last_error = %s,
                    updated_at = %s,
                    metadata = metadata || %s
                WHERE kind = %s AND status = %s
                """,
                (
                    ExternalSyncStatus.FAILED.value,
                    reason,
                    now,
                    _dump(metadata),
                    kind.value,
                    ExternalSyncStatus.PENDING.value,
                ),
            )
            connection.commit()
        return cursor.rowcount

    def insert_notion_page(self, page: NotionPage) -> None:
        self._execute(
            """
            INSERT INTO notion_pages
            (id, target_id, page_type, title, external_id, status, url, metadata, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET target_id = EXCLUDED.target_id, page_type = EXCLUDED.page_type, title = EXCLUDED.title, external_id = EXCLUDED.external_id, status = EXCLUDED.status, url = EXCLUDED.url, metadata = EXCLUDED.metadata, created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at
            """,
            (
                page.id,
                page.target_id,
                page.page_type,
                page.title,
                page.external_id,
                page.status,
                page.url,
                _dump(page.metadata),
                page.created_at.isoformat(),
                page.updated_at.isoformat(),
            ),
        )

    def list_notion_pages(self, target_id: str | None = None, limit: int = 100) -> list[NotionPage]:
        if target_id:
            rows = self._query(
                "SELECT * FROM notion_pages WHERE target_id = %s ORDER BY created_at DESC LIMIT %s",
                (target_id, limit),
            )
        else:
            rows = self._query("SELECT * FROM notion_pages ORDER BY created_at DESC LIMIT %s", (limit,))
        return [self._notion_page_from_row(row) for row in rows]

    def insert_discord_delivery(self, delivery: DiscordDelivery) -> None:
        self._execute(
            """
            INSERT INTO discord_deliveries
            (id, notification_id, status, external_ref, attempts, last_error, metadata, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET notification_id = EXCLUDED.notification_id, status = EXCLUDED.status, external_ref = EXCLUDED.external_ref, attempts = EXCLUDED.attempts, last_error = EXCLUDED.last_error, metadata = EXCLUDED.metadata, created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at
            """,
            (
                delivery.id,
                delivery.notification_id,
                delivery.status.value,
                delivery.external_ref,
                delivery.attempts,
                delivery.last_error,
                _dump(delivery.metadata),
                delivery.created_at.isoformat(),
                delivery.updated_at.isoformat(),
            ),
        )

    def list_discord_deliveries(self, limit: int = 100) -> list[DiscordDelivery]:
        rows = self._query("SELECT * FROM discord_deliveries ORDER BY created_at DESC LIMIT %s", (limit,))
        return [self._discord_delivery_from_row(row) for row in rows]
