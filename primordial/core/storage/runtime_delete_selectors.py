from __future__ import annotations

from primordial.core.storage.runtime_common import *


class RuntimeDeleteSelectorsMixin:
    def _select_ids(
        self,
        connection: Any,
        sql: str,
        params: tuple[Any, ...],
    ) -> list[str]:
        return [str(row["id"]) for row in connection.execute(sql, params)]

    def _select_ids_for_parent(
        self,
        connection: Any,
        table: str,
        foreign_key: str,
        parent_ids: list[str],
    ) -> list[str]:
        if not parent_ids:
            return []
        placeholders = ", ".join("%s" for _ in parent_ids)
        sql = f"SELECT id FROM {table} WHERE {foreign_key} IN ({placeholders})"
        return [str(row["id"]) for row in connection.execute(sql, tuple(parent_ids))]

    def _select_notifications_for_target(
        self,
        connection: Any,
        target_id: str,
        task_ids: list[str],
    ) -> list[str]:
        where = ["target_id = %s"]
        params: list[Any] = [target_id]
        if task_ids:
            placeholders = ", ".join("%s" for _ in task_ids)
            where.append(f"task_id IN ({placeholders})")
            params.extend(task_ids)
        sql = f"SELECT id FROM notifications WHERE {' OR '.join(where)}"
        return [str(row["id"]) for row in connection.execute(sql, tuple(params))]

    def _select_paths_for_target(
        self,
        connection: Any,
        table: str,
        target_id: str,
        task_ids: list[str],
    ) -> list[str]:
        where = ["target_id = %s"]
        params: list[Any] = [target_id]
        if task_ids:
            placeholders = ", ".join("%s" for _ in task_ids)
            where.append(f"task_id IN ({placeholders})")
            params.extend(task_ids)
        sql = f"SELECT path FROM {table} WHERE {' OR '.join(where)}"
        return [str(row["path"]) for row in connection.execute(sql, tuple(params)) if row["path"]]

    def _select_checkpoint_paths(
        self,
        connection: Any,
        task_ids: list[str],
        run_ids: list[str],
    ) -> list[str]:
        where: list[str] = []
        params: list[Any] = []
        if task_ids:
            placeholders = ", ".join("%s" for _ in task_ids)
            where.append(f"task_id IN ({placeholders})")
            params.extend(task_ids)
        if run_ids:
            placeholders = ", ".join("%s" for _ in run_ids)
            where.append(f"run_id IN ({placeholders})")
            params.extend(run_ids)
        if not where:
            return []
        sql = f"SELECT path FROM checkpoints WHERE {' OR '.join(where)}"
        return [str(row["path"]) for row in connection.execute(sql, tuple(params)) if row["path"]]

    def _delete_target_rows(
        self,
        connection: Any,
        table: str,
        target_id: str,
        *,
        key: str = "target_id",
    ) -> int:
        return connection.execute(f"DELETE FROM {table} WHERE {key} = %s", (target_id,)).rowcount

    def _count_target_rows(
        self,
        connection: Any,
        table: str,
        target_id: str,
        *,
        key: str = "target_id",
    ) -> int:
        row = connection.execute(f"SELECT COUNT(*) AS count FROM {table} WHERE {key} = %s", (target_id,)).fetchone()
        return int(row["count"]) if row else 0

    def _delete_target_or_task_rows(
        self,
        connection: Any,
        table: str,
        target_id: str,
        task_ids: list[str],
    ) -> int:
        where = ["target_id = %s"]
        params: list[Any] = [target_id]
        if task_ids:
            placeholders = ", ".join("%s" for _ in task_ids)
            where.append(f"task_id IN ({placeholders})")
            params.extend(task_ids)
        sql = f"DELETE FROM {table} WHERE {' OR '.join(where)}"
        return connection.execute(sql, tuple(params)).rowcount

    def _count_target_or_task_rows(
        self,
        connection: Any,
        table: str,
        target_id: str,
        task_ids: list[str],
    ) -> int:
        where = ["target_id = %s"]
        params: list[Any] = [target_id]
        if task_ids:
            placeholders = ", ".join("%s" for _ in task_ids)
            where.append(f"task_id IN ({placeholders})")
            params.extend(task_ids)
        sql = f"SELECT COUNT(*) AS count FROM {table} WHERE {' OR '.join(where)}"
        row = connection.execute(sql, tuple(params)).fetchone()
        return int(row["count"]) if row else 0

    def _count_query(self, connection: Any, sql: str, params: tuple[Any, ...]) -> int:
        row = connection.execute(sql, params).fetchone()
        return int(row["count"]) if row else 0

    def _delete_ids(
        self,
        connection: Any,
        table: str,
        key: str,
        values: list[str],
    ) -> int:
        if not values:
            return 0
        placeholders = ", ".join("%s" for _ in values)
        sql = f"DELETE FROM {table} WHERE {key} IN ({placeholders})"
        return connection.execute(sql, tuple(values)).rowcount

    def _count_ids(
        self,
        connection: Any,
        table: str,
        key: str,
        values: list[str],
    ) -> int:
        if not values:
            return 0
        placeholders = ", ".join("%s" for _ in values)
        sql = f"SELECT COUNT(*) AS count FROM {table} WHERE {key} IN ({placeholders})"
        row = connection.execute(sql, tuple(values)).fetchone()
        return int(row["count"]) if row else 0

    def _delete_checkpoints(
        self,
        connection: Any,
        task_ids: list[str],
        run_ids: list[str],
    ) -> int:
        where: list[str] = []
        params: list[Any] = []
        if task_ids:
            placeholders = ", ".join("%s" for _ in task_ids)
            where.append(f"task_id IN ({placeholders})")
            params.extend(task_ids)
        if run_ids:
            placeholders = ", ".join("%s" for _ in run_ids)
            where.append(f"run_id IN ({placeholders})")
            params.extend(run_ids)
        if not where:
            return 0
        sql = f"DELETE FROM checkpoints WHERE {' OR '.join(where)}"
        return connection.execute(sql, tuple(params)).rowcount

    def _count_checkpoints(
        self,
        connection: Any,
        task_ids: list[str],
        run_ids: list[str],
    ) -> int:
        where: list[str] = []
        params: list[Any] = []
        if task_ids:
            placeholders = ", ".join("%s" for _ in task_ids)
            where.append(f"task_id IN ({placeholders})")
            params.extend(task_ids)
        if run_ids:
            placeholders = ", ".join("%s" for _ in run_ids)
            where.append(f"run_id IN ({placeholders})")
            params.extend(run_ids)
        if not where:
            return 0
        sql = f"SELECT COUNT(*) AS count FROM checkpoints WHERE {' OR '.join(where)}"
        row = connection.execute(sql, tuple(params)).fetchone()
        return int(row["count"]) if row else 0
