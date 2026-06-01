from __future__ import annotations

from primordial.core.storage.runtime_common import *


class RuntimeTasksMixin:
    def insert_task(self, task: Task) -> None:
        self._execute(
            """
            INSERT INTO tasks
            (id, target_id, session_id, phase, kind, title, summary, role, methodology,
                required_capabilities, evidence_refs, metadata, status, priority,
                risk_tier, attempts, max_attempts, requires_approval, provider_route, provider_model,
                parent_task_id, latest_run_id, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET target_id = EXCLUDED.target_id, session_id = EXCLUDED.session_id, phase = EXCLUDED.phase, kind = EXCLUDED.kind, title = EXCLUDED.title, summary = EXCLUDED.summary, role = EXCLUDED.role, methodology = EXCLUDED.methodology, required_capabilities = EXCLUDED.required_capabilities, evidence_refs = EXCLUDED.evidence_refs, metadata = EXCLUDED.metadata, status = EXCLUDED.status, priority = EXCLUDED.priority, risk_tier = EXCLUDED.risk_tier, attempts = EXCLUDED.attempts, max_attempts = EXCLUDED.max_attempts, requires_approval = EXCLUDED.requires_approval, provider_route = EXCLUDED.provider_route, provider_model = EXCLUDED.provider_model, parent_task_id = EXCLUDED.parent_task_id, latest_run_id = EXCLUDED.latest_run_id, created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at
            """,
            (
                task.id,
                task.target_id,
                task.session_id,
                task.phase.value,
                task.kind.value,
                task.title,
                task.summary,
                task.role.value,
                task.methodology.value,
                _dump(task.required_capabilities),
                _dump(task.evidence_refs),
                _dump(task.metadata),
                task.status.value,
                task.priority,
                task.risk_tier.value,
                task.attempts,
                task.max_attempts,
                bool(task.requires_approval),
                task.provider_route.value if task.provider_route else None,
                task.provider_model,
                task.parent_task_id,
                task.latest_run_id,
                task.created_at.isoformat(),
                task.updated_at.isoformat(),
            ),
        )

    def update_task(self, task: Task) -> None:
        task.updated_at = parse_datetime(task.updated_at.isoformat()) if isinstance(task.updated_at, str) else task.updated_at
        self.insert_task(task)

    def update_task_status(
        self,
        task_id: str,
        *,
        from_statuses: Iterable[TaskStatus],
        to_status: TaskStatus,
        metadata_patch: dict[str, Any] | None = None,
        requires_approval: bool | None = None,
    ) -> Task | None:
        statuses = list(from_statuses)
        if not statuses:
            raise ValueError("from_statuses is required")
        now = utc_now()
        set_clauses = ["status = %s", "updated_at = %s", "metadata = metadata || %s"]
        params: list[Any] = [to_status.value, now.isoformat(), _dump(metadata_patch or {})]
        if requires_approval is not None:
            set_clauses.append("requires_approval = %s")
            params.append(bool(requires_approval))
        params.append(task_id)
        params.extend(status.value for status in statuses)
        placeholders = ", ".join("%s" for _ in statuses)
        with closing(self.connect()) as connection:
            row = connection.execute(
                f"""
                UPDATE tasks
                SET {", ".join(set_clauses)}
                WHERE id = %s AND status IN ({placeholders})
                RETURNING *
                """,
                tuple(params),
            ).fetchone()
            connection.commit()
        return self._task_from_row(row) if row else None

    def guarded_update_task(self, task: Task, *, from_statuses: Iterable[TaskStatus]) -> Task | None:
        statuses = list(from_statuses)
        if not statuses:
            raise ValueError("from_statuses is required")
        task.updated_at = parse_datetime(task.updated_at.isoformat()) if isinstance(task.updated_at, str) else task.updated_at
        params: list[Any] = [
            task.target_id,
            task.session_id,
            task.phase.value,
            task.kind.value,
            task.title,
            task.summary,
            task.role.value,
            task.methodology.value,
            _dump(task.required_capabilities),
            _dump(task.evidence_refs),
            _dump(task.metadata),
            task.status.value,
            task.priority,
            task.risk_tier.value,
            task.attempts,
            task.max_attempts,
            bool(task.requires_approval),
            task.provider_route.value if task.provider_route else None,
            task.provider_model,
            task.parent_task_id,
            task.latest_run_id,
            task.created_at.isoformat(),
            task.updated_at.isoformat(),
            task.id,
        ]
        params.extend(status.value for status in statuses)
        placeholders = ", ".join("%s" for _ in statuses)
        with closing(self.connect()) as connection:
            row = connection.execute(
                f"""
                UPDATE tasks
                SET target_id = %s, session_id = %s, phase = %s, kind = %s,
                    title = %s, summary = %s, role = %s, methodology = %s,
                    required_capabilities = %s, evidence_refs = %s, metadata = %s,
                    status = %s, priority = %s, risk_tier = %s, attempts = %s,
                    max_attempts = %s, requires_approval = %s, provider_route = %s,
                    provider_model = %s, parent_task_id = %s, latest_run_id = %s,
                    created_at = %s, updated_at = %s
                WHERE id = %s AND status IN ({placeholders})
                RETURNING *
                """,
                tuple(params),
            ).fetchone()
            connection.commit()
        return self._task_from_row(row) if row else None

    def get_task(self, task_id: str) -> Task | None:
        row = self._query_one("SELECT * FROM tasks WHERE id = %s", (task_id,))
        return self._task_from_row(row) if row else None

    def list_tasks(
        self,
        *,
        statuses: Iterable[TaskStatus] | None = None,
        target_id: str | None = None,
        limit: int = 100,
    ) -> list[Task]:
        where: list[str] = []
        params: list[Any] = []
        if statuses:
            where.append("status IN (%s)" % ", ".join("%s" for _ in statuses))
            params.extend(status.value for status in statuses)
        if target_id:
            where.append("target_id = %s")
            params.append(target_id)
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        rows = self._query(
            f"SELECT * FROM tasks {clause} ORDER BY priority DESC, created_at ASC LIMIT %s",
            (*params, limit),
        )
        return [self._task_from_row(row) for row in rows]

    def claim_next_pending_task(self) -> Task | None:
        with closing(self.connect()) as connection:
            connection.execute("BEGIN")
            row = connection.execute(
                """
                SELECT * FROM tasks
                WHERE status = %s
                ORDER BY priority DESC, created_at ASC
                LIMIT 1
                FOR UPDATE SKIP LOCKED
                """,
                (TaskStatus.PENDING.value,),
            ).fetchone()
            if row is None:
                connection.commit()
                return None
            rows = list(connection.execute(
                """
                UPDATE tasks SET status = %s, updated_at = %s
                WHERE id = %s AND status = %s
                RETURNING *
                """,
                (TaskStatus.RUNNING.value, utc_now().isoformat(), row["id"], TaskStatus.PENDING.value),
            ))
            connection.commit()
        if not rows:
            return None
        return self._task_from_row(rows[0])

    def has_active_task(self, target_id: str | None, kind: TaskKind) -> bool:
        row = self._query_one(
            """
            SELECT 1
            FROM tasks
            WHERE target_id IS NOT DISTINCT FROM %s
              AND kind = %s
              AND status IN (%s, %s, %s, %s)
            LIMIT 1
            """,
            (
                target_id,
                kind.value,
                TaskStatus.PENDING.value,
                TaskStatus.RUNNING.value,
                TaskStatus.WAITING.value,
                TaskStatus.NEEDS_APPROVAL.value,
            ),
        )
        return row is not None

    def task_exists(
        self,
        target_id: str | None,
        kind: TaskKind,
        statuses: Iterable[TaskStatus] | None = None,
    ) -> bool:
        params: list[Any] = [target_id, kind.value]
        where = ["target_id IS NOT DISTINCT FROM %s", "kind = %s"]
        if statuses:
            where.append("status IN (%s)" % ", ".join("%s" for _ in statuses))
            params.extend(status.value for status in statuses)
        row = self._query_one(
            f"SELECT 1 FROM tasks WHERE {' AND '.join(where)} LIMIT 1",
            tuple(params),
        )
        return row is not None
