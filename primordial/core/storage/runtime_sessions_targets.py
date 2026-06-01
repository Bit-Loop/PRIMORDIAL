from __future__ import annotations

from primordial.core.storage.runtime_common import *


class RuntimeSessionsTargetsMixin:
    def insert_session(self, session: Session) -> None:
        self._execute(
            """
            INSERT INTO sessions
            (id, methodology, profile, autonomy_mode, status, title, metadata, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET methodology = EXCLUDED.methodology, profile = EXCLUDED.profile, autonomy_mode = EXCLUDED.autonomy_mode, status = EXCLUDED.status, title = EXCLUDED.title, metadata = EXCLUDED.metadata, created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at
            """,
            (
                session.id,
                session.methodology.value,
                session.profile.value,
                session.autonomy_mode,
                session.status.value,
                session.title,
                _dump(session.metadata),
                session.created_at.isoformat(),
                session.updated_at.isoformat(),
            ),
        )

    def list_sessions(self, limit: int = 20) -> list[Session]:
        rows = self._query("SELECT * FROM sessions ORDER BY created_at DESC LIMIT %s", (limit,))
        return [self._session_from_row(row) for row in rows]

    def get_active_session(self) -> Session | None:
        row = self._query_one(
            "SELECT * FROM sessions WHERE status = %s ORDER BY created_at DESC LIMIT 1",
            (SessionStatus.ACTIVE.value,),
        )
        return self._session_from_row(row) if row else None

    def pause_active_sessions(self) -> int:
        with closing(self.connect()) as connection:
            updated = connection.execute(
                "UPDATE sessions SET status = %s, updated_at = %s WHERE status = %s",
                (SessionStatus.PAUSED.value, utc_now().isoformat(), SessionStatus.ACTIVE.value),
            ).rowcount
            connection.commit()
        return updated

    def insert_target(self, target: Target) -> None:
        with closing(self.connect()) as connection:
            row = connection.execute(
                """
                INSERT INTO targets
                (id, handle, display_name, profile, in_scope, metadata, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (profile, handle) DO UPDATE SET
                    display_name = EXCLUDED.display_name,
                    in_scope = EXCLUDED.in_scope,
                    metadata = EXCLUDED.metadata,
                    updated_at = EXCLUDED.updated_at
                RETURNING id, created_at
                """,
                (
                    target.id,
                    target.handle,
                    target.display_name,
                    target.profile.value,
                    target.in_scope,
                    _dump(target.metadata),
                    target.created_at.isoformat(),
                    target.updated_at.isoformat(),
                ),
            ).fetchone()
            if not target.in_scope and row is not None:
                self._block_active_tasks_for_target_in_connection(
                    connection,
                    target_id=str(row["id"]),
                    reason="target was marked out of scope",
                    source="target_scope_update",
                    now=target.updated_at,
                )
            connection.commit()
        if row is not None:
            target.id = str(row["id"])
            target.created_at = parse_datetime(row["created_at"])

    def list_targets(self, *, include_system: bool = False) -> list[Target]:
        where = "" if include_system else "WHERE COALESCE(metadata->>'system_target', 'false') <> 'true'"
        rows = self._query(f"SELECT * FROM targets {where} ORDER BY created_at ASC")
        return [self._target_from_row(row) for row in rows]

    def get_target(self, target_id: str | None) -> Target | None:
        if not target_id:
            return None
        row = self._query_one("SELECT * FROM targets WHERE id = %s", (target_id,))
        return self._target_from_row(row) if row else None

    def get_target_by_handle(self, handle: str, profile: ScopeProfile | None = None) -> Target | None:
        if profile is None:
            row = self._query_one(
                "SELECT * FROM targets WHERE handle = %s ORDER BY created_at DESC LIMIT 1",
                (handle,),
            )
        else:
            row = self._query_one(
                "SELECT * FROM targets WHERE handle = %s AND profile = %s ORDER BY created_at DESC LIMIT 1",
                (handle, profile.value),
            )
        return self._target_from_row(row) if row else None

    def insert_scope_asset(self, asset: ScopeAsset) -> None:
        self._execute(
            """
            INSERT INTO scope_assets
            (id, target_id, asset, asset_type, metadata, created_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET target_id = EXCLUDED.target_id, asset = EXCLUDED.asset, asset_type = EXCLUDED.asset_type, metadata = EXCLUDED.metadata, created_at = EXCLUDED.created_at
            """,
            (
                asset.id,
                asset.target_id,
                asset.asset,
                asset.asset_type,
                _dump(asset.metadata),
                asset.created_at.isoformat(),
            ),
        )

    def delete_scope_assets_for_target(self, target_id: str) -> int:
        with closing(self.connect()) as connection:
            cursor = connection.execute("DELETE FROM scope_assets WHERE target_id = %s", (target_id,))
            total = cursor.rowcount
            connection.commit()
            return total

    def replace_target_scope_assets(
        self,
        *,
        handle: str,
        display_name: str,
        profile: ScopeProfile,
        in_scope: bool,
        active_ip: str | None,
        asset_rows: list[dict[str, Any]],
    ) -> dict[str, Any]:
        now = utc_now()
        with closing(self.connect()) as connection:
            outcome = replace_target_scope_assets_in_connection(
                connection,
                handle=handle,
                display_name=display_name,
                profile=profile,
                in_scope=in_scope,
                active_ip=active_ip,
                asset_rows=asset_rows,
                now=now,
                dump=_dump,
                target_from_row=self._target_from_row,
                block_active_tasks=self._block_active_tasks_for_target_in_connection,
            )
            connection.commit()
        return outcome

    def _block_active_tasks_for_target_in_connection(
        self,
        connection: _PostgresConnection,
        *,
        target_id: str,
        reason: str,
        source: str,
        now,
    ) -> int:
        metadata_patch = {
            "scope_invalidated": True,
            "scope_invalidation_reason": reason,
            "scope_invalidated_at": now.isoformat(),
            "scope_invalidation_source": source,
        }
        rows = list(
            connection.execute(
                """
                UPDATE tasks
                SET status = %s,
                    requires_approval = false,
                    updated_at = %s,
                    metadata = metadata || %s
                WHERE target_id = %s
                  AND status IN (%s, %s, %s, %s)
                RETURNING id
                """,
                (
                    TaskStatus.BLOCKED.value,
                    now.isoformat(),
                    _dump(metadata_patch),
                    target_id,
                    TaskStatus.PENDING.value,
                    TaskStatus.RUNNING.value,
                    TaskStatus.WAITING.value,
                    TaskStatus.NEEDS_APPROVAL.value,
                ),
            )
        )
        if rows:
            task_ids = [str(row["id"]) for row in rows]
            task_placeholders = ", ".join("%s" for _ in task_ids)
            connection.execute(
                f"""
                UPDATE task_runs
                SET status = %s,
                    error = %s,
                    finished_at = %s,
                    heartbeat_at = %s,
                    metadata = metadata || %s
                WHERE task_id IN ({task_placeholders})
                  AND status IN (%s, %s)
                """,
                (
                    TaskRunStatus.CANCELLED.value,
                    reason,
                    now.isoformat(),
                    now.isoformat(),
                    _dump(metadata_patch),
                    *task_ids,
                    TaskRunStatus.CLAIMED.value,
                    TaskRunStatus.RUNNING.value,
                ),
            )
            self._insert_scope_blocked_tasks_event(
                connection,
                target_id=target_id,
                reason=reason,
                metadata_patch=metadata_patch,
                task_ids=task_ids,
            )
        return len(rows)

    def _insert_scope_blocked_tasks_event(
        self,
        connection: _PostgresConnection,
        *,
        target_id: str,
        reason: str,
        metadata_patch: dict[str, Any],
        task_ids: list[str],
    ) -> None:
        event = EventRecord(
            type=EventType.TASK_BLOCKED,
            summary=f"Blocked {len(task_ids)} active task(s): {reason}",
            target_id=target_id,
            metadata={**metadata_patch, "task_ids": task_ids, "blocked_count": len(task_ids)},
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
                event.summary,
                _dump(event.metadata),
                event.created_at.isoformat(),
            ),
        )

    def list_scope_assets(self, target_id: str | None = None) -> list[ScopeAsset]:
        if target_id:
            rows = self._query(
                "SELECT * FROM scope_assets WHERE target_id = %s ORDER BY created_at ASC",
                (target_id,),
            )
        else:
            rows = self._query("SELECT * FROM scope_assets ORDER BY created_at ASC")
        return [self._scope_asset_from_row(row) for row in rows]

    def get_scope_asset(self, target_id: str, asset: str) -> ScopeAsset | None:
        row = self._query_one(
            "SELECT * FROM scope_assets WHERE target_id = %s AND asset = %s ORDER BY created_at DESC LIMIT 1",
            (target_id, asset),
        )
        return self._scope_asset_from_row(row) if row else None
