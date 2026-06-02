from __future__ import annotations

from primordial.core.storage.runtime_common import *


class RuntimeTaskRunsMixin:
    def insert_task_run(self, run: TaskRun) -> None:
        self._execute(
            """
            INSERT INTO task_runs
            (id, task_id, status, attempt_number, role, provider_route, model_name, cold_path,
                heartbeat_at, lease_expires_at, started_at, finished_at, trace_summary, error, metadata)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET task_id = EXCLUDED.task_id, status = EXCLUDED.status, attempt_number = EXCLUDED.attempt_number, role = EXCLUDED.role, provider_route = EXCLUDED.provider_route, model_name = EXCLUDED.model_name, cold_path = EXCLUDED.cold_path, heartbeat_at = EXCLUDED.heartbeat_at, lease_expires_at = EXCLUDED.lease_expires_at, started_at = EXCLUDED.started_at, finished_at = EXCLUDED.finished_at, trace_summary = EXCLUDED.trace_summary, error = EXCLUDED.error, metadata = EXCLUDED.metadata
            """,
            (
                run.id,
                run.task_id,
                run.status.value,
                run.attempt_number,
                run.role.value,
                run.provider_route.value,
                run.model_name,
                bool(run.cold_path),
                run.heartbeat_at.isoformat() if run.heartbeat_at else None,
                run.lease_expires_at.isoformat() if run.lease_expires_at else None,
                run.started_at.isoformat(),
                run.finished_at.isoformat() if run.finished_at else None,
                _storage_text(run.trace_summary),
                _storage_text(run.error) if run.error is not None else None,
                _dump(run.metadata),
            ),
        )

    def update_task_run_status(
        self,
        run_id: str,
        *,
        from_statuses: Iterable[TaskRunStatus],
        to_status: TaskRunStatus,
        metadata_patch: dict[str, Any] | None = None,
        error: str | None = None,
        trace_summary: str | None = None,
        finished: bool = False,
    ) -> TaskRun | None:
        statuses = list(from_statuses)
        if not statuses:
            raise ValueError("from_statuses is required")
        now = utc_now()
        set_clauses = ["status = %s", "heartbeat_at = %s", "metadata = metadata || %s"]
        params: list[Any] = [to_status.value, now.isoformat(), _dump(metadata_patch or {})]
        if error is not None:
            set_clauses.append("error = %s")
            params.append(_storage_text(error))
        if trace_summary is not None:
            set_clauses.append("trace_summary = %s")
            params.append(_storage_text(trace_summary))
        if finished:
            set_clauses.append("finished_at = %s")
            params.append(now.isoformat())
        params.append(run_id)
        params.extend(status.value for status in statuses)
        placeholders = ", ".join("%s" for _ in statuses)
        with closing(self.connect()) as connection:
            row = connection.execute(
                f"""
                UPDATE task_runs
                SET {", ".join(set_clauses)}
                WHERE id = %s AND status IN ({placeholders})
                RETURNING *
                """,
                tuple(params),
            ).fetchone()
            connection.commit()
        return self._task_run_from_row(row) if row else None

    def guarded_update_task_run(self, run: TaskRun, *, from_statuses: Iterable[TaskRunStatus]) -> TaskRun | None:
        statuses = list(from_statuses)
        if not statuses:
            raise ValueError("from_statuses is required")
        params: list[Any] = [
            run.task_id,
            run.status.value,
            run.attempt_number,
            run.role.value,
            run.provider_route.value,
            run.model_name,
            bool(run.cold_path),
            run.heartbeat_at.isoformat() if run.heartbeat_at else None,
            run.lease_expires_at.isoformat() if run.lease_expires_at else None,
            run.started_at.isoformat(),
            run.finished_at.isoformat() if run.finished_at else None,
            _storage_text(run.trace_summary),
            _storage_text(run.error) if run.error is not None else None,
            _dump(run.metadata),
            run.id,
        ]
        params.extend(status.value for status in statuses)
        placeholders = ", ".join("%s" for _ in statuses)
        with closing(self.connect()) as connection:
            row = connection.execute(
                f"""
                UPDATE task_runs
                SET task_id = %s, status = %s, attempt_number = %s, role = %s,
                    provider_route = %s, model_name = %s, cold_path = %s,
                    heartbeat_at = %s, lease_expires_at = %s, started_at = %s,
                    finished_at = %s, trace_summary = %s, error = %s, metadata = %s
                WHERE id = %s AND status IN ({placeholders})
                RETURNING *
                """,
                tuple(params),
            ).fetchone()
            connection.commit()
        return self._task_run_from_row(row) if row else None

    def list_running_task_runs(self) -> list[TaskRun]:
        rows = self._query(
            "SELECT * FROM task_runs WHERE status = %s ORDER BY started_at DESC",
            (TaskRunStatus.RUNNING.value,),
        )
        return [self._task_run_from_row(row) for row in rows]

    def list_task_runs(self, task_id: str | None = None, limit: int = 100) -> list[TaskRun]:
        if task_id:
            rows = self._query(
                "SELECT * FROM task_runs WHERE task_id = %s ORDER BY started_at DESC LIMIT %s",
                (task_id, limit),
            )
        else:
            rows = self._query("SELECT * FROM task_runs ORDER BY started_at DESC LIMIT %s", (limit,))
        return [self._task_run_from_row(row) for row in rows]

    def get_task_run(self, run_id: str) -> TaskRun | None:
        row = self._query_one("SELECT * FROM task_runs WHERE id = %s", (run_id,))
        return self._task_run_from_row(row) if row else None

    def recover_stale_task_run(
        self,
        *,
        run: TaskRun,
        task: Task | None,
        task_status: TaskStatus | None,
        reason: str,
        trace: AgentTrace,
        event: EventRecord,
    ) -> bool:
        now = utc_now()
        now_iso = now.isoformat()
        recovery_metadata = {"recovered_stale_execution": True, "recovery_reason": reason}
        with closing(self.connect()) as connection:
            connection.execute("BEGIN")
            run_row = connection.execute(
                """
                UPDATE task_runs
                SET status = %s, error = %s, finished_at = %s, heartbeat_at = %s,
                    metadata = metadata || %s
                WHERE id = %s AND status IN (%s, %s) AND finished_at IS NULL
                RETURNING *
                """,
                (
                    TaskRunStatus.CANCELLED.value,
                    _storage_text(f"recovered stale execution state: {reason}"),
                    now_iso,
                    now_iso,
                    _dump(recovery_metadata),
                    run.id,
                    TaskRunStatus.CLAIMED.value,
                    TaskRunStatus.RUNNING.value,
                ),
            ).fetchone()
            if run_row is None:
                connection.rollback()
                return False
            self._mark_recovered_stale_task(
                connection,
                task=task,
                task_status=task_status,
                recovery_metadata=recovery_metadata,
                now_iso=now_iso,
            )
            connection.execute(
                """
                INSERT INTO agent_traces
                (id, task_id, role, status, summary, metadata, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    trace.id,
                    trace.task_id,
                    trace.role.value,
                    trace.status,
                    _storage_text(trace.summary),
                    _dump(self._normalize_trace_metadata(trace)),
                    trace.created_at.isoformat(),
                ),
            )
            connection.execute(
                """
                INSERT INTO events
                (id, event_type, target_id, task_id, summary, metadata, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    event.id,
                    event.type.value,
                    event.target_id,
                    event.task_id,
                    _storage_text(event.summary),
                    _dump(event.metadata),
                    event.created_at.isoformat(),
                ),
            )
            connection.commit()
        return True

    def _mark_recovered_stale_task(
        self,
        connection: Any,
        *,
        task: Task | None,
        task_status: TaskStatus | None,
        recovery_metadata: dict[str, Any],
        now_iso: str,
    ) -> None:
        if task is None or task_status is None:
            return
        connection.execute(
            """
            UPDATE tasks
            SET status = %s, updated_at = %s, metadata = metadata || %s
            WHERE id = %s AND status = %s
            """,
            (
                task_status.value,
                now_iso,
                _dump(recovery_metadata),
                task.id,
                TaskStatus.RUNNING.value,
            ),
        )
