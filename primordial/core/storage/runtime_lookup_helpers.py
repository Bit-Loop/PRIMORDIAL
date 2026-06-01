from __future__ import annotations

from primordial.core.storage.runtime_common import *


class RuntimeLookupHelpersMixin:
    def target_has_evidence(self, target_id: str) -> bool:
        row = self._query_one("SELECT 1 FROM evidence WHERE target_id = %s LIMIT 1", (target_id,))
        return row is not None

    def verified_interest_count(self, target_id: str) -> int:
        row = self._query_one(
            "SELECT COUNT(*) AS count FROM interests WHERE target_id = %s AND status = %s",
            (target_id, InterestStatus.VERIFIED.value),
        )
        return int(row["count"]) if row else 0

    def memory_entry_exists(self, *, target_id: str, layer: MemoryLayer, title: str) -> bool:
        row = self._query_one(
            """
            SELECT 1 FROM memory_entries
            WHERE target_id = %s AND layer = %s AND title = %s AND status != %s
            LIMIT 1
            """,
            (target_id, layer.value, title, MemoryStatus.SUPERSEDED.value),
        )
        return row is not None

    def find_latest_notification_by_dedupe(self, dedupe_key: str) -> NotificationRecord | None:
        row = self._query_one(
            """
            SELECT * FROM notifications
            WHERE dedupe_key = %s
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (dedupe_key,),
        )
        return self._notification_from_row(row) if row else None
