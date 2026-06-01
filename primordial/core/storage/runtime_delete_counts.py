from __future__ import annotations

from primordial.core.storage.runtime_common import *


class RuntimeDeleteCountsMixin:
    def _target_runtime_record_counts(
        self,
        connection: Any,
        *,
        target_id: str,
        task_ids: list[str],
        run_ids: list[str],
        notification_ids: list[str],
    ) -> dict[str, int]:
        return {
            "tasks": self._count_target_rows(connection, "tasks", target_id),
            "task_runs": self._count_ids(connection, "task_runs", "task_id", task_ids),
            "evidence": self._count_target_rows(connection, "evidence", target_id),
            "notes": self._count_target_rows(connection, "notes", target_id),
            "interests": self._count_target_rows(connection, "interests", target_id),
            "findings": self._count_target_rows(connection, "findings", target_id),
            "memory_entries": self._count_target_rows(connection, "memory_entries", target_id),
            "artifacts": self._count_target_or_task_rows(connection, "artifacts", target_id, task_ids),
            "checkpoints": self._count_checkpoints(connection, task_ids, run_ids),
            "agent_traces": self._count_ids(connection, "agent_traces", "task_id", task_ids),
            "document_chunks": self._count_target_rows(connection, "document_chunks", target_id),
            "record_embeddings": self._count_target_rows(connection, "record_embeddings", target_id),
            "policy_decisions": self._count_target_or_task_rows(connection, "policy_decisions", target_id, task_ids),
            "notifications": self._count_target_or_task_rows(connection, "notifications", target_id, task_ids),
            "discord_deliveries": self._count_ids(connection, "discord_deliveries", "notification_id", notification_ids),
            "external_sync_jobs": self._count_target_rows(connection, "external_sync_jobs", target_id),
            "notion_pages": self._count_target_rows(connection, "notion_pages", target_id),
            "operator_messages": self._count_target_rows(connection, "operator_messages", target_id),
            "task_handoffs": self._count_ids(connection, "task_handoffs", "task_id", task_ids),
        }

    def _target_blocking_runtime_record_counts(
        self,
        connection: Any,
        *,
        target_id: str,
        notification_ids: list[str],
    ) -> dict[str, int]:
        return {
            "evidence": self._count_query(
                connection,
                """
                SELECT COUNT(*) AS count FROM evidence
                WHERE target_id = %s
                  AND task_id IS NULL
                  AND COALESCE(metadata->>'auto_generated', 'false') <> 'true'
                  AND NOT (metadata ? 'origin_task')
                """,
                (target_id,),
            ),
            "notes": self._count_query(
                connection,
                """
                SELECT COUNT(*) AS count FROM notes
                WHERE target_id = %s
                  AND task_id IS NULL
                  AND COALESCE(metadata->>'auto_generated', 'false') <> 'true'
                  AND NOT (metadata ? 'origin_task')
                """,
                (target_id,),
            ),
            "interests": self._count_query(
                connection,
                """
                SELECT COUNT(*) AS count FROM interests
                WHERE target_id = %s
                  AND COALESCE(metadata->>'auto_generated', 'false') <> 'true'
                  AND NOT (metadata ? 'origin_task')
                """,
                (target_id,),
            ),
            "findings": self._count_query(
                connection,
                """
                SELECT COUNT(*) AS count FROM findings
                WHERE target_id = %s
                  AND COALESCE(metadata->>'auto_generated', 'false') <> 'true'
                """,
                (target_id,),
            ),
            "memory_entries": self._count_target_rows(connection, "memory_entries", target_id),
            "artifacts": self._count_query(
                connection,
                "SELECT COUNT(*) AS count FROM artifacts WHERE target_id = %s AND task_id IS NULL",
                (target_id,),
            ),
            "document_chunks": self._count_target_rows(connection, "document_chunks", target_id),
            "record_embeddings": self._count_target_rows(connection, "record_embeddings", target_id),
            "notifications": self._count_query(
                connection,
                "SELECT COUNT(*) AS count FROM notifications WHERE target_id = %s AND task_id IS NULL",
                (target_id,),
            ),
            "discord_deliveries": self._target_blocking_discord_delivery_count(
                connection,
                target_id=target_id,
                notification_ids=notification_ids,
            ),
            "external_sync_jobs": self._count_query(
                connection,
                """
                SELECT COUNT(*) AS count FROM external_sync_jobs
                WHERE target_id = %s
                  AND NOT (payload ? 'task_id')
                """,
                (target_id,),
            ),
            "notion_pages": self._count_target_rows(connection, "notion_pages", target_id),
            "operator_messages": self._count_target_rows(connection, "operator_messages", target_id),
        }

    def _target_blocking_discord_delivery_count(
        self,
        connection: Any,
        *,
        target_id: str,
        notification_ids: list[str],
    ) -> int:
        if not notification_ids:
            return 0
        target_notification_count = self._count_query(
            connection,
            "SELECT COUNT(*) AS count FROM notifications WHERE target_id = %s AND task_id IS NULL",
            (target_id,),
        )
        if not target_notification_count:
            return 0
        return self._count_ids(connection, "discord_deliveries", "notification_id", notification_ids)
