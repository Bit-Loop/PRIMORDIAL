from __future__ import annotations

from primordial.core.storage.runtime_common import *


class RuntimeSettingsMixin:
    def get_setting(self, key: str, default: Any = None) -> Any:
        row = self._query_one("SELECT value FROM app_settings WHERE key = %s", (key,))
        if row is None:
            return default
        return _load(row["value"], default)

    def set_setting(self, key: str, value: Any) -> None:
        self._execute(
            """
            INSERT INTO app_settings
            (key, value, updated_at)
            VALUES (%s, %s, %s)
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at
            """,
            (key, _dump(value), utc_now().isoformat()),
        )

    def purge_synthetic_external_records(self) -> dict[str, int]:
        with closing(self.connect()) as connection:
            synthetic_notion_rows = list(
                connection.execute(
                    """
                    SELECT id, metadata FROM notion_pages
                    WHERE url LIKE %s
                       OR external_id LIKE %s
                    """,
                    ("https://notion.local/%", "notion-%"),
                )
            )
            synthetic_job_ids: set[str] = set()
            for row in synthetic_notion_rows:
                metadata = _load(row["metadata"], {})
                if isinstance(metadata, dict) and metadata.get("job_id"):
                    synthetic_job_ids.add(str(metadata["job_id"]))

            synthetic_notion_pages = connection.execute(
                """
                DELETE FROM notion_pages
                WHERE url LIKE %s
                   OR external_id LIKE %s
                """,
                ("https://notion.local/%", "notion-%"),
            ).rowcount

            synthetic_discord_rows = list(
                connection.execute(
                    "SELECT notification_id FROM discord_deliveries WHERE external_ref LIKE %s",
                    ("discord://%",),
                )
            )
            synthetic_notification_ids = [str(row["notification_id"]) for row in synthetic_discord_rows]
            synthetic_discord_deliveries = connection.execute(
                "DELETE FROM discord_deliveries WHERE external_ref LIKE %s",
                ("discord://%",),
            ).rowcount

            synthetic_jobs_updated = 0
            if synthetic_job_ids:
                placeholders = ", ".join("%s" for _ in synthetic_job_ids)
                synthetic_jobs_updated = connection.execute(
                    f"""
                    UPDATE external_sync_jobs
                    SET status = %s, last_error = %s, updated_at = %s
                    WHERE id IN ({placeholders})
                    """,
                    (
                        ExternalSyncStatus.FAILED.value,
                        "legacy synthetic Notion records were removed; real Notion credentials are required",
                        utc_now().isoformat(),
                        *tuple(synthetic_job_ids),
                    ),
                ).rowcount

            synthetic_notifications_updated = 0
            if synthetic_notification_ids:
                placeholders = ", ".join("%s" for _ in synthetic_notification_ids)
                synthetic_notifications_updated = connection.execute(
                    f"""
                    UPDATE notifications
                    SET status = %s, updated_at = %s
                    WHERE id IN ({placeholders})
                    """,
                    (
                        NotificationStatus.FAILED.value,
                        utc_now().isoformat(),
                        *tuple(synthetic_notification_ids),
                    ),
                ).rowcount

            connection.commit()
        return {
            "notion_pages": synthetic_notion_pages,
            "discord_deliveries": synthetic_discord_deliveries,
            "sync_jobs_updated": synthetic_jobs_updated,
            "notifications_updated": synthetic_notifications_updated,
        }
