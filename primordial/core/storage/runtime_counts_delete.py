from __future__ import annotations

from primordial.core.storage.runtime_common import *


class RuntimeCountsDeleteMixin:
    def count_all(self) -> dict[str, int]:
        tables = (
            "sessions",
            "targets",
            "scope_assets",
            "tasks",
            "task_runs",
            "task_handoffs",
            "evidence",
            "notes",
            "interests",
            "findings",
            "memory_entries",
            "policy_decisions",
            "primitives",
            "artifacts",
            "notifications",
            "external_sync_jobs",
            "notion_pages",
            "discord_deliveries",
            "checkpoints",
            "agent_traces",
            "events",
            "operator_messages",
            "model_eval_runs",
            "model_eval_role_metrics",
            "record_embeddings",
            "document_chunks",
        )
        counts: dict[str, int] = {}
        for table in tables:
            row = self._query_one(f"SELECT COUNT(*) AS count FROM {table}")
            counts[table] = int(row["count"]) if row else 0
        return counts

    def delete_target_cascade(
        self,
        target_id: str,
        *,
        allow_runtime_record_deletion: bool = False,
        deletion_reason: str | None = None,
    ) -> dict[str, Any]:
        with closing(self.connect()) as connection:
            task_ids = self._select_ids(connection, "SELECT id FROM tasks WHERE target_id = %s", (target_id,))
            run_ids = self._select_ids_for_parent(connection, "task_runs", "task_id", task_ids)
            notification_ids = self._select_notifications_for_target(connection, target_id, task_ids)
            artifact_paths = self._select_paths_for_target(connection, "artifacts", target_id, task_ids)
            checkpoint_paths = self._select_checkpoint_paths(connection, task_ids, run_ids)
            runtime_record_counts = self._target_runtime_record_counts(
                connection,
                target_id=target_id,
                task_ids=task_ids,
                run_ids=run_ids,
                notification_ids=notification_ids,
            )
            blocking_record_counts = self._target_blocking_runtime_record_counts(
                connection,
                target_id=target_id,
                notification_ids=notification_ids,
            )
            if any(blocking_record_counts.values()) and not allow_runtime_record_deletion:
                connection.rollback()
                return {
                    "blocked": True,
                    "reason": "target has operator-owned runtime records; destructive target deletion is disabled",
                    "runtime_record_counts": runtime_record_counts,
                    "blocking_runtime_record_counts": blocking_record_counts,
                    "artifact_paths": artifact_paths,
                    "checkpoint_paths": checkpoint_paths,
                    "task_ids": task_ids,
                    "notification_ids": notification_ids,
                }

            connection.execute("SET LOCAL primordial.allow_runtime_delete = 'on'")

            deleted = {
                "discord_deliveries": self._delete_ids(connection, "discord_deliveries", "notification_id", notification_ids),
                "task_handoffs": self._delete_ids(connection, "task_handoffs", "task_id", task_ids),
                "task_runs": self._delete_ids(connection, "task_runs", "task_id", task_ids),
                "checkpoints": self._delete_checkpoints(connection, task_ids, run_ids),
                "agent_traces": self._delete_ids(connection, "agent_traces", "task_id", task_ids),
                "document_chunks": self._delete_target_rows(connection, "document_chunks", target_id),
                "record_embeddings": self._delete_target_rows(connection, "record_embeddings", target_id),
                "policy_decisions": self._delete_target_or_task_rows(connection, "policy_decisions", target_id, task_ids),
                "artifacts": self._delete_target_or_task_rows(connection, "artifacts", target_id, task_ids),
                "notifications": self._delete_target_or_task_rows(connection, "notifications", target_id, task_ids),
                "external_sync_jobs": self._delete_target_rows(connection, "external_sync_jobs", target_id),
                "notion_pages": self._delete_target_rows(connection, "notion_pages", target_id),
                "evidence": self._delete_target_rows(connection, "evidence", target_id),
                "notes": self._delete_target_rows(connection, "notes", target_id),
                "interests": self._delete_target_rows(connection, "interests", target_id),
                "findings": self._delete_target_rows(connection, "findings", target_id),
                "memory_entries": self._delete_target_rows(connection, "memory_entries", target_id),
                "events": self._delete_target_or_task_rows(connection, "events", target_id, task_ids),
                "operator_messages": self._delete_target_rows(connection, "operator_messages", target_id),
                "scope_assets": self._delete_target_rows(connection, "scope_assets", target_id),
                "tasks": self._delete_target_rows(connection, "tasks", target_id),
                "targets": self._delete_target_rows(connection, "targets", target_id, key="id"),
            }
            connection.commit()
        return {
            "deleted": deleted,
            "artifact_paths": artifact_paths,
            "checkpoint_paths": checkpoint_paths,
            "task_ids": task_ids,
            "notification_ids": notification_ids,
            "deletion_reason": deletion_reason,
            "runtime_record_counts": runtime_record_counts,
            "blocking_runtime_record_counts": blocking_record_counts,
        }
