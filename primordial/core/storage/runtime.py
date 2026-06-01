from __future__ import annotations

import json
from json import JSONDecodeError
from contextlib import closing
import re
from typing import Any, Iterable

from primordial.core.context.normalization import canonical_rag_domain, normalized_context_key

try:
    import psycopg
    from psycopg.rows import dict_row
    from psycopg.types.json import Jsonb
except ModuleNotFoundError as exc:  # pragma: no cover - exercised before runtime startup
    psycopg = None
    dict_row = None
    Jsonb = None
    _PSYCOPG_IMPORT_ERROR = exc
else:
    _PSYCOPG_IMPORT_ERROR = None

from primordial.core.domain.enums import (
    AgentRole,
    ArtifactKind,
    CheckpointKind,
    EventType,
    EvidenceType,
    ExternalSyncKind,
    ExternalSyncStatus,
    FindingSeverity,
    HandoffStatus,
    InterestStatus,
    MemoryLayer,
    MemoryStatus,
    MethodologyName,
    MethodologyPhase,
    NotificationChannel,
    NotificationStatus,
    PrimitiveRuntime,
    ProviderRoute,
    RiskTier,
    ScopeProfile,
    SessionStatus,
    SideEffectLevel,
    TaskKind,
    TaskRunStatus,
    TaskStatus,
    VerificationStatus,
)
from primordial.core.domain.models import (
    AgentTrace,
    ArtifactRecord,
    new_id as _new_id,
    CheckpointRecord,
    DiscordDelivery,
    DocumentChunk,
    EventRecord,
    EvidenceRecord,
    ExternalSyncJob,
    Finding,
    Interest,
    MemoryEntry,
    Note,
    NotionPage,
    NotificationRecord,
    OperatorMessage,
    PolicyDecision,
    PrimitiveManifest,
    RecordEmbedding,
    ScopeAsset,
    Session,
    Target,
    Task,
    TaskHandoff,
    TaskRun,
    json_ready,
    parse_datetime,
    utc_now,
)
from primordial.core.storage.schema import SCHEMA_SQL
from primordial.core.storage.target_scope import replace_target_scope_assets_in_connection


_DOCUMENT_CHUNK_METADATA_FILTER_KEYS = {
    "domain": ["domain", "corpus_type"],
    "source_file": ["source_file", "source_name"],
    "doc_id": ["doc_id"],
    "citation_id": ["citation_id"],
    "chunk_type": ["chunk_type"],
    "card_type": ["card_type"],
    "risk_family": ["risk_family"],
    "output_mode": ["output_mode"],
    "source_priority": ["source_priority"],
    "requires_authorized_scope": ["requires_authorized_scope"],
    "vuln_id": ["vuln_id"],
    "cve_id": ["cve_id"],
    "ghsa_id": ["ghsa_ids", "aliases", "alias"],
    "osv_id": ["osv_ids", "aliases", "alias"],
    "alias": ["aliases", "alias", "cve_id", "ghsa_ids", "osv_ids"],
    "ecosystem": ["ecosystem"],
    "package": ["package"],
    "vendor": ["affected_vendors"],
    "product": ["affected_products"],
    "cpe": ["cpe", "affected_cpes"],
    "purl": ["purl", "affected_purls"],
    "cwe": ["cwe", "cwe_ids"],
    "cvss_severity": ["cvss_severity"],
    "kev": ["kev"],
    "fixed_version_known": ["fixed_version_known"],
    "asset_match": ["asset_match"],
    "watchlist_match": ["watchlist_match"],
    "source_kind": ["source_kind"],
    "safety_level": ["safety_level"],
}

_DOCUMENT_CHUNK_NUMERIC_FILTER_KEYS = {
    "epss_probability": "epss_probability",
    "epss_percentile": "epss_percentile",
}


def _dump(value: Any) -> Any:
    ready = json_ready(value)
    if Jsonb is not None:
        return Jsonb(ready)
    return json.dumps(ready, sort_keys=True)


def _load(value: Any | None, default: Any) -> Any:
    if not value:
        return default
    if isinstance(value, str):
        try:
            return json.loads(value)
        except JSONDecodeError:
            return value
    if isinstance(value, dict | list):
        return value
    try:
        return json.loads(value)
    except (JSONDecodeError, TypeError):
        return value


def _vector_literal(values: list[float]) -> str:
    if not values:
        raise ValueError("embedding vector cannot be empty")
    return "[" + ",".join(f"{float(value):.8f}" for value in values) + "]"


def _token_terms(value: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[A-Za-z0-9_.:/-]+", value.lower())
        if len(token) > 2
    }


_SCHEMA_VERSION = 1


class _PostgresCursor:
    def __init__(self, cursor: Any) -> None:
        self._cursor = cursor
        self.rowcount = cursor.rowcount

    def fetchone(self) -> Any | None:
        return self._cursor.fetchone()

    def __iter__(self):
        for row in self._cursor:
            yield row


class _PostgresConnection:
    def __init__(self, connection: Any) -> None:
        self._connection = connection

    def __enter__(self) -> "_PostgresConnection":
        self._connection.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return self._connection.__exit__(exc_type, exc, tb)

    def close(self) -> None:
        self._connection.close()

    def commit(self) -> None:
        self._connection.commit()

    def rollback(self) -> None:
        self._connection.rollback()

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> _PostgresCursor:
        cursor = self._connection.execute(sql, params)
        return _PostgresCursor(cursor)

    def executescript(self, sql: str) -> None:
        for statement in _split_sql_statements(sql):
            self.execute(statement)


def _split_sql_statements(sql: str) -> list[str]:
    statements: list[str] = []
    start = 0
    index = 0
    in_single_quote = False
    dollar_tag: str | None = None
    while index < len(sql):
        char = sql[index]
        if dollar_tag is not None:
            if sql.startswith(dollar_tag, index):
                index += len(dollar_tag)
                dollar_tag = None
                continue
            index += 1
            continue
        if in_single_quote:
            if char == "'" and index + 1 < len(sql) and sql[index + 1] == "'":
                index += 2
                continue
            if char == "'":
                in_single_quote = False
            index += 1
            continue
        if char == "'":
            in_single_quote = True
            index += 1
            continue
        if char == "$":
            match = re.match(r"\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$", sql[index:])
            if match:
                dollar_tag = match.group(0)
                index += len(dollar_tag)
                continue
        if char == ";":
            statement = sql[start:index].strip()
            if statement:
                statements.append(statement)
            start = index + 1
        index += 1
    statement = sql[start:].strip()
    if statement:
        statements.append(statement)
    return statements


def _quote_ident(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


class RuntimeStore:
    def __init__(self, database_url: str, *, schema: str | None = None) -> None:
        self.database_url = database_url
        self.schema = schema

    def initialize(self) -> None:
        with closing(self.connect()) as connection:
            connection.execute("CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA public")
            if self.schema:
                connection.execute(f"CREATE SCHEMA IF NOT EXISTS {_quote_ident(self.schema)}")
                connection.execute(f"SET search_path TO {_quote_ident(self.schema)}, public")
            connection.executescript(SCHEMA_SQL)
            self._assert_schema_version(connection)
            connection.commit()

    def _assert_schema_version(self, connection: _PostgresConnection) -> None:
        row = connection.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
        if row is None:
            connection.execute("INSERT INTO schema_version (version) VALUES (%s)", (_SCHEMA_VERSION,))
        elif int(row["version"]) > _SCHEMA_VERSION:
            raise RuntimeError(
                f"Database schema version {row['version']} is newer than this code ({_SCHEMA_VERSION}). "
                "Upgrade the application before opening this database."
            )

    def connect(self) -> _PostgresConnection:
        if psycopg is None:
            raise RuntimeError(
                "psycopg v3 is required for Primordial runtime storage. "
                "Install project dependencies with `pip install -e .`."
            ) from _PSYCOPG_IMPORT_ERROR
        connection = _PostgresConnection(psycopg.connect(self.database_url, row_factory=dict_row))
        if self.schema:
            connection.execute(f"SET search_path TO {_quote_ident(self.schema)}, public")
            connection.commit()
        return connection

    def _execute(self, sql: str, params: tuple[Any, ...]) -> None:
        with closing(self.connect()) as connection:
            connection.execute(sql, params)
            connection.commit()

    def _query(self, sql: str, params: tuple[Any, ...] = ()) -> list[Any]:
        with closing(self.connect()) as connection:
            return list(connection.execute(sql, params))

    def _query_one(self, sql: str, params: tuple[Any, ...] = ()) -> Any | None:
        with closing(self.connect()) as connection:
            return connection.execute(sql, params).fetchone()

    def _update(self, table: str, record_id: str, values: dict[str, Any]) -> None:
        assignments = ", ".join(f"{key} = %s" for key in values)
        params = tuple(values.values()) + (record_id,)
        self._execute(f"UPDATE {table} SET {assignments} WHERE id = %s", params)

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
                run.trace_summary,
                run.error,
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
            params.append(error)
        if trace_summary is not None:
            set_clauses.append("trace_summary = %s")
            params.append(trace_summary)
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
            run.trace_summary,
            run.error,
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
                    f"recovered stale execution state: {reason}",
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
                    trace.summary,
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
                    event.summary,
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

    def insert_handoff(self, handoff: TaskHandoff) -> None:
        self._execute(
            """
            INSERT INTO task_handoffs
            (id, task_id, source_agent, destination_agent, reason, expected_output_type,
                evidence_refs, hypothesis, budget, deadline_at, status, metadata,
                created_at, consumed_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET task_id = EXCLUDED.task_id, source_agent = EXCLUDED.source_agent, destination_agent = EXCLUDED.destination_agent, reason = EXCLUDED.reason, expected_output_type = EXCLUDED.expected_output_type, evidence_refs = EXCLUDED.evidence_refs, hypothesis = EXCLUDED.hypothesis, budget = EXCLUDED.budget, deadline_at = EXCLUDED.deadline_at, status = EXCLUDED.status, metadata = EXCLUDED.metadata, created_at = EXCLUDED.created_at, consumed_at = EXCLUDED.consumed_at
            """,
            (
                handoff.id,
                handoff.task_id,
                handoff.source_agent.value,
                handoff.destination_agent.value,
                handoff.reason,
                handoff.expected_output_type,
                _dump(handoff.evidence_refs),
                handoff.hypothesis,
                handoff.budget,
                handoff.deadline_at.isoformat() if handoff.deadline_at else None,
                handoff.status.value,
                _dump(handoff.metadata),
                handoff.created_at.isoformat(),
                handoff.consumed_at.isoformat() if handoff.consumed_at else None,
            ),
        )

    def list_handoffs(self, task_id: str | None = None, limit: int = 100) -> list[TaskHandoff]:
        if task_id:
            rows = self._query(
                "SELECT * FROM task_handoffs WHERE task_id = %s ORDER BY created_at DESC LIMIT %s",
                (task_id, limit),
            )
        else:
            rows = self._query("SELECT * FROM task_handoffs ORDER BY created_at DESC LIMIT %s", (limit,))
        return [self._handoff_from_row(row) for row in rows]

    def get_handoff(self, handoff_id: str) -> TaskHandoff | None:
        row = self._query_one("SELECT * FROM task_handoffs WHERE id = %s", (handoff_id,))
        return self._handoff_from_row(row) if row else None

    def consume_handoffs_for_task(self, task: Task, *, limit: int = 100) -> int:
        if not task.target_id:
            return 0
        now = utc_now()
        with closing(self.connect()) as connection:
            rows = list(
                connection.execute(
                    """
                    UPDATE task_handoffs AS handoff
                    SET status = %s, consumed_at = %s, metadata = handoff.metadata || %s
                    FROM tasks AS source_task
                    WHERE handoff.task_id = source_task.id
                      AND source_task.target_id = %s
                      AND handoff.destination_agent = %s
                      AND handoff.status = %s
                      AND handoff.id IN (
                          SELECT h.id
                          FROM task_handoffs h
                          JOIN tasks st ON st.id = h.task_id
                          WHERE st.target_id = %s
                            AND h.destination_agent = %s
                            AND h.status = %s
                          ORDER BY h.created_at ASC
                          LIMIT %s
                      )
                    RETURNING handoff.*
                    """,
                    (
                        HandoffStatus.CONSUMED.value,
                        now.isoformat(),
                        _dump({"consumed_by_task_id": task.id, "consumed_by_task_kind": task.kind.value}),
                        task.target_id,
                        task.role.value,
                        HandoffStatus.OPEN.value,
                        task.target_id,
                        task.role.value,
                        HandoffStatus.OPEN.value,
                        limit,
                    ),
                )
            )
            connection.commit()
        return len(rows)

    def expire_handoffs(self, *, now: Any | None = None, limit: int = 500) -> int:
        effective_now = now or utc_now()
        with closing(self.connect()) as connection:
            rows = list(
                connection.execute(
                    """
                    UPDATE task_handoffs
                    SET status = %s, consumed_at = %s, metadata = metadata || %s
                    WHERE status = %s
                      AND deadline_at IS NOT NULL
                      AND deadline_at <= %s
                      AND id IN (
                          SELECT id
                          FROM task_handoffs
                          WHERE status = %s
                            AND deadline_at IS NOT NULL
                            AND deadline_at <= %s
                          ORDER BY deadline_at ASC
                          LIMIT %s
                      )
                    RETURNING *
                    """,
                    (
                        HandoffStatus.EXPIRED.value,
                        effective_now.isoformat(),
                        _dump({"expired_at": effective_now.isoformat()}),
                        HandoffStatus.OPEN.value,
                        effective_now.isoformat(),
                        HandoffStatus.OPEN.value,
                        effective_now.isoformat(),
                        limit,
                    ),
                )
            )
            connection.commit()
        return len(rows)

    def insert_evidence(self, evidence: EvidenceRecord) -> None:
        self._execute(
            """
            INSERT INTO evidence
            (id, target_id, task_id, type, title, summary, source_ref, verification_status,
                confidence, freshness, artifact_path, metadata, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET target_id = EXCLUDED.target_id, task_id = EXCLUDED.task_id, type = EXCLUDED.type, title = EXCLUDED.title, summary = EXCLUDED.summary, source_ref = EXCLUDED.source_ref, verification_status = EXCLUDED.verification_status, confidence = EXCLUDED.confidence, freshness = EXCLUDED.freshness, artifact_path = EXCLUDED.artifact_path, metadata = EXCLUDED.metadata, created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at
            """,
            (
                evidence.id,
                evidence.target_id,
                evidence.task_id,
                evidence.type.value,
                evidence.title,
                evidence.summary,
                evidence.source_ref,
                evidence.verification_status.value,
                evidence.confidence,
                evidence.freshness,
                evidence.artifact_path,
                _dump(evidence.metadata),
                evidence.created_at.isoformat(),
                evidence.updated_at.isoformat(),
            ),
        )

    def list_evidence(self, *, target_id: str | None = None, limit: int = 100) -> list[EvidenceRecord]:
        if target_id:
            rows = self._query(
                "SELECT * FROM evidence WHERE target_id = %s ORDER BY created_at DESC LIMIT %s",
                (target_id, limit),
            )
        else:
            rows = self._query("SELECT * FROM evidence ORDER BY created_at DESC LIMIT %s", (limit,))
        return [self._evidence_from_row(row) for row in rows]

    def get_evidence(self, evidence_id: str) -> EvidenceRecord | None:
        row = self._query_one("SELECT * FROM evidence WHERE id = %s", (evidence_id,))
        return self._evidence_from_row(row) if row else None

    def insert_note(self, note: Note) -> None:
        self._execute(
            """
            INSERT INTO notes
            (id, target_id, task_id, title, body, confidence, freshness, metadata, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET target_id = EXCLUDED.target_id, task_id = EXCLUDED.task_id, title = EXCLUDED.title, body = EXCLUDED.body, confidence = EXCLUDED.confidence, freshness = EXCLUDED.freshness, metadata = EXCLUDED.metadata, created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at
            """,
            (
                note.id,
                note.target_id,
                note.task_id,
                note.title,
                note.body,
                note.confidence,
                note.freshness,
                _dump(note.metadata),
                note.created_at.isoformat(),
                note.updated_at.isoformat(),
            ),
        )

    def list_notes(self, *, target_id: str | None = None, limit: int = 100) -> list[Note]:
        if target_id:
            rows = self._query(
                "SELECT * FROM notes WHERE target_id = %s ORDER BY created_at DESC LIMIT %s",
                (target_id, limit),
            )
        else:
            rows = self._query("SELECT * FROM notes ORDER BY created_at DESC LIMIT %s", (limit,))
        return [self._note_from_row(row) for row in rows]

    def get_note(self, note_id: str) -> Note | None:
        row = self._query_one("SELECT * FROM notes WHERE id = %s", (note_id,))
        return self._note_from_row(row) if row else None

    def insert_interest(self, interest: Interest) -> None:
        self._execute(
            """
            INSERT INTO interests
            (id, target_id, title, summary, evidence_refs, status, confidence, metadata, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET target_id = EXCLUDED.target_id, title = EXCLUDED.title, summary = EXCLUDED.summary, evidence_refs = EXCLUDED.evidence_refs, status = EXCLUDED.status, confidence = EXCLUDED.confidence, metadata = EXCLUDED.metadata, created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at
            """,
            (
                interest.id,
                interest.target_id,
                interest.title,
                interest.summary,
                _dump(interest.evidence_refs),
                interest.status.value,
                interest.confidence,
                _dump(interest.metadata),
                interest.created_at.isoformat(),
                interest.updated_at.isoformat(),
            ),
        )

    def list_interests(self, *, target_id: str | None = None, limit: int = 100) -> list[Interest]:
        if target_id:
            rows = self._query(
                "SELECT * FROM interests WHERE target_id = %s ORDER BY created_at DESC LIMIT %s",
                (target_id, limit),
            )
        else:
            rows = self._query("SELECT * FROM interests ORDER BY created_at DESC LIMIT %s", (limit,))
        return [self._interest_from_row(row) for row in rows]

    def get_interest(self, interest_id: str) -> Interest | None:
        row = self._query_one("SELECT * FROM interests WHERE id = %s", (interest_id,))
        return self._interest_from_row(row) if row else None

    def insert_finding(self, finding: Finding) -> None:
        self._execute(
            """
            INSERT INTO findings
            (id, target_id, title, summary, severity, evidence_refs, confidence, verification_status, metadata, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET target_id = EXCLUDED.target_id, title = EXCLUDED.title, summary = EXCLUDED.summary, severity = EXCLUDED.severity, evidence_refs = EXCLUDED.evidence_refs, confidence = EXCLUDED.confidence, verification_status = EXCLUDED.verification_status, metadata = EXCLUDED.metadata, created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at
            """,
            (
                finding.id,
                finding.target_id,
                finding.title,
                finding.summary,
                finding.severity.value,
                _dump(finding.evidence_refs),
                finding.confidence,
                finding.verification_status.value,
                _dump(finding.metadata),
                finding.created_at.isoformat(),
                finding.updated_at.isoformat(),
            ),
        )

    def list_findings(self, *, target_id: str | None = None, limit: int = 100) -> list[Finding]:
        if target_id:
            rows = self._query(
                "SELECT * FROM findings WHERE target_id = %s ORDER BY created_at DESC LIMIT %s",
                (target_id, limit),
            )
        else:
            rows = self._query("SELECT * FROM findings ORDER BY created_at DESC LIMIT %s", (limit,))
        return [self._finding_from_row(row) for row in rows]

    def get_finding(self, finding_id: str) -> Finding | None:
        row = self._query_one("SELECT * FROM findings WHERE id = %s", (finding_id,))
        return self._finding_from_row(row) if row else None

    def insert_memory_entry(self, entry: MemoryEntry) -> None:
        self._execute(
            """
            INSERT INTO memory_entries
            (id, target_id, layer, title, summary, evidence_refs, confidence, freshness, status, metadata, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET target_id = EXCLUDED.target_id, layer = EXCLUDED.layer, title = EXCLUDED.title, summary = EXCLUDED.summary, evidence_refs = EXCLUDED.evidence_refs, confidence = EXCLUDED.confidence, freshness = EXCLUDED.freshness, status = EXCLUDED.status, metadata = EXCLUDED.metadata, created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at
            """,
            (
                entry.id,
                entry.target_id,
                entry.layer.value,
                entry.title,
                entry.summary,
                _dump(entry.evidence_refs),
                entry.confidence,
                entry.freshness,
                entry.status.value,
                _dump(entry.metadata),
                entry.created_at.isoformat(),
                entry.updated_at.isoformat(),
            ),
        )

    def list_memory_entries(
        self,
        *,
        target_id: str | None = None,
        layer: MemoryLayer | None = None,
        limit: int = 100,
    ) -> list[MemoryEntry]:
        where: list[str] = []
        params: list[Any] = []
        if target_id:
            where.append("target_id = %s")
            params.append(target_id)
        if layer:
            where.append("layer = %s")
            params.append(layer.value)
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        rows = self._query(
            f"SELECT * FROM memory_entries {clause} ORDER BY created_at DESC LIMIT %s",
            (*params, limit),
        )
        return [self._memory_from_row(row) for row in rows]

    def get_memory_entry(self, memory_id: str) -> MemoryEntry | None:
        row = self._query_one("SELECT * FROM memory_entries WHERE id = %s", (memory_id,))
        return self._memory_from_row(row) if row else None

    def insert_policy_decision(self, decision: PolicyDecision) -> None:
        self._execute(
            """
            INSERT INTO policy_decisions
            (id, action_kind, verdict, reason, target_id, task_id, metadata, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET action_kind = EXCLUDED.action_kind, verdict = EXCLUDED.verdict, reason = EXCLUDED.reason, target_id = EXCLUDED.target_id, task_id = EXCLUDED.task_id, metadata = EXCLUDED.metadata, created_at = EXCLUDED.created_at
            """,
            (
                decision.id,
                decision.action_kind,
                decision.verdict.value,
                decision.reason,
                decision.target_id,
                decision.task_id,
                _dump(decision.metadata),
                decision.created_at.isoformat(),
            ),
        )

    def insert_primitive(self, primitive: PrimitiveManifest) -> None:
        self._execute(
            """
            INSERT INTO primitives
            (id, name, version, description, capability_tags, allowed_phases, runtime, risk_tier,
                side_effect_level, required_secrets, input_schema, output_schema, timeout_seconds,
                retry_policy, evidence_adapter, sandbox_profile, healthcheck, metadata, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (name) DO UPDATE SET id = EXCLUDED.id, version = EXCLUDED.version, description = EXCLUDED.description, capability_tags = EXCLUDED.capability_tags, allowed_phases = EXCLUDED.allowed_phases, runtime = EXCLUDED.runtime, risk_tier = EXCLUDED.risk_tier, side_effect_level = EXCLUDED.side_effect_level, required_secrets = EXCLUDED.required_secrets, input_schema = EXCLUDED.input_schema, output_schema = EXCLUDED.output_schema, timeout_seconds = EXCLUDED.timeout_seconds, retry_policy = EXCLUDED.retry_policy, evidence_adapter = EXCLUDED.evidence_adapter, sandbox_profile = EXCLUDED.sandbox_profile, healthcheck = EXCLUDED.healthcheck, metadata = EXCLUDED.metadata, created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at
            """,
            (
                primitive.id,
                primitive.name,
                primitive.version,
                primitive.description,
                _dump(primitive.capability_tags),
                _dump([phase.value for phase in primitive.allowed_phases]),
                primitive.runtime.value,
                primitive.risk_tier.value,
                primitive.side_effect_level.value,
                _dump(primitive.required_secrets),
                _dump(primitive.input_schema),
                _dump(primitive.output_schema),
                primitive.timeout_seconds,
                _dump(primitive.retry_policy),
                primitive.evidence_adapter,
                primitive.sandbox_profile,
                primitive.healthcheck,
                _dump(primitive.metadata),
                primitive.created_at.isoformat(),
                primitive.updated_at.isoformat(),
            ),
        )

    def list_primitives(self) -> list[PrimitiveManifest]:
        rows = self._query("SELECT * FROM primitives ORDER BY name ASC")
        return [self._primitive_from_row(row) for row in rows]

    def insert_artifact(self, artifact: ArtifactRecord) -> None:
        self._execute(
            """
            INSERT INTO artifacts
            (id, task_id, target_id, kind, path, sha256, size_bytes, metadata, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET task_id = EXCLUDED.task_id, target_id = EXCLUDED.target_id, kind = EXCLUDED.kind, path = EXCLUDED.path, sha256 = EXCLUDED.sha256, size_bytes = EXCLUDED.size_bytes, metadata = EXCLUDED.metadata, created_at = EXCLUDED.created_at
            """,
            (
                artifact.id,
                artifact.task_id,
                artifact.target_id,
                artifact.kind.value,
                artifact.path,
                artifact.sha256,
                artifact.size_bytes,
                _dump(artifact.metadata),
                artifact.created_at.isoformat(),
            ),
        )

    def list_artifacts(self, task_id: str | None = None, limit: int = 100) -> list[ArtifactRecord]:
        if task_id:
            rows = self._query(
                "SELECT * FROM artifacts WHERE task_id = %s ORDER BY created_at DESC LIMIT %s",
                (task_id, limit),
            )
        else:
            rows = self._query("SELECT * FROM artifacts ORDER BY created_at DESC LIMIT %s", (limit,))
        return [self._artifact_from_row(row) for row in rows]

    def get_artifact(self, artifact_id: str) -> ArtifactRecord | None:
        row = self._query_one("SELECT * FROM artifacts WHERE id = %s", (artifact_id,))
        return self._artifact_from_row(row) if row else None

    def insert_document_chunk(self, chunk: DocumentChunk) -> None:
        self._execute(
            """
            INSERT INTO document_chunks
            (id, target_id, source_artifact_id, source_sha256, chunk_index, title, text, token_count,
                evidence_refs, metadata, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (source_artifact_id, chunk_index) DO UPDATE SET id = EXCLUDED.id, target_id = EXCLUDED.target_id, source_sha256 = EXCLUDED.source_sha256, title = EXCLUDED.title, text = EXCLUDED.text, token_count = EXCLUDED.token_count, evidence_refs = EXCLUDED.evidence_refs, metadata = EXCLUDED.metadata, created_at = EXCLUDED.created_at
            """,
            (
                chunk.id,
                chunk.target_id,
                chunk.source_artifact_id,
                chunk.source_sha256,
                chunk.chunk_index,
                chunk.title,
                chunk.text,
                chunk.token_count,
                _dump(chunk.evidence_refs),
                _dump(chunk.metadata),
                chunk.created_at.isoformat(),
            ),
        )

    def get_document_chunk(self, chunk_id: str) -> DocumentChunk | None:
        row = self._query_one("SELECT * FROM document_chunks WHERE id = %s", (chunk_id,))
        return self._document_chunk_from_row(row) if row else None

    def list_document_chunks(
        self,
        *,
        target_id: str | None = None,
        source_artifact_id: str | None = None,
        metadata_filters: dict[str, object] | None = None,
        limit: int = 100,
    ) -> list[DocumentChunk]:
        where: list[str] = []
        params: list[Any] = []
        if target_id:
            where.append("target_id = %s")
            params.append(target_id)
        if source_artifact_id:
            where.append("source_artifact_id = %s")
            params.append(source_artifact_id)
        self._append_document_chunk_metadata_filters(where, params, metadata_filters or {})
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        rows = self._query(
            f"SELECT * FROM document_chunks {clause} ORDER BY created_at DESC, chunk_index ASC LIMIT %s",
            (*params, limit),
        )
        return [self._document_chunk_from_row(row) for row in rows]

    def count_document_chunks(self, *, metadata_filters: dict[str, object] | None = None) -> int:
        where: list[str] = []
        params: list[Any] = []
        self._append_document_chunk_metadata_filters(where, params, metadata_filters or {})
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        row = self._query_one(f"SELECT COUNT(*) AS count FROM document_chunks {clause}", tuple(params))
        return int(row["count"]) if row else 0

    def search_document_chunks_text(
        self,
        query: str,
        *,
        target_id: str | None = None,
        metadata_filters: dict[str, object] | None = None,
        limit: int = 8,
    ) -> list[dict[str, Any]]:
        terms = _token_terms(query)
        if not terms:
            return []
        candidates = self.list_document_chunks(target_id=target_id, metadata_filters=metadata_filters, limit=500)
        ranked: list[dict[str, Any]] = []
        for chunk in candidates:
            chunk_terms = _token_terms(f"{chunk.title}\n{chunk.text}")
            if not chunk_terms:
                continue
            overlap = terms & chunk_terms
            if not overlap:
                continue
            score = len(overlap) / max(1, len(terms))
            ranked.append({"chunk": chunk, "score": round(score, 4), "matched_terms": sorted(overlap)})
        ranked.sort(key=lambda item: (-float(item["score"]), item["chunk"].created_at, item["chunk"].chunk_index))
        return ranked[:limit]

    def insert_record_embedding(self, embedding: RecordEmbedding) -> None:
        self._execute(
            """
            INSERT INTO record_embeddings
            (id, target_id, record_type, record_id, embedding_model, embedding_dim, embedding, metadata, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s::vector, %s, %s)
            ON CONFLICT (record_type, record_id, embedding_model) DO UPDATE SET target_id = EXCLUDED.target_id, embedding_dim = EXCLUDED.embedding_dim, embedding = EXCLUDED.embedding, metadata = EXCLUDED.metadata, created_at = EXCLUDED.created_at
            """,
            (
                embedding.id,
                embedding.target_id,
                embedding.record_type,
                embedding.record_id,
                embedding.embedding_model,
                embedding.embedding_dim,
                _vector_literal(embedding.embedding),
                _dump(embedding.metadata),
                embedding.created_at.isoformat(),
            ),
        )

    def get_record_embedding(
        self,
        *,
        record_type: str,
        record_id: str,
        embedding_model: str,
    ) -> RecordEmbedding | None:
        row = self._query_one(
            """
            SELECT * FROM record_embeddings
            WHERE record_type = %s AND record_id = %s AND embedding_model = %s
            """,
            (record_type, record_id, embedding_model),
        )
        return self._record_embedding_from_row(row) if row else None

    def count_record_embeddings(self, *, embedding_model: str | None = None) -> int:
        if embedding_model:
            row = self._query_one(
                "SELECT COUNT(*) AS count FROM record_embeddings WHERE embedding_model = %s",
                (embedding_model,),
            )
        else:
            row = self._query_one("SELECT COUNT(*) AS count FROM record_embeddings")
        return int(row["count"]) if row else 0

    def rag_status_counts(self) -> dict[str, Any]:
        chunk_total = self.count_document_chunks()
        embedding_total = self.count_record_embeddings()
        domains = self._query(
            """
            SELECT COALESCE(metadata->>'domain', metadata->>'corpus_type', 'unknown') AS domain,
                   COUNT(*) AS count
            FROM document_chunks
            GROUP BY domain
            ORDER BY count DESC, domain ASC
            """
        )
        models = self._query(
            """
            SELECT embedding_model,
                   COALESCE(metadata->>'embedding_provider', metadata->>'provider', 'unknown') AS provider,
                   embedding_dim,
                   COUNT(*) AS count
            FROM record_embeddings
            WHERE record_type = 'document_chunk'
            GROUP BY embedding_model, provider, embedding_dim
            ORDER BY count DESC, embedding_model ASC, embedding_dim ASC
            """
        )
        return {
            "document_chunks": chunk_total,
            "record_embeddings": embedding_total,
            "domains": [{"domain": row["domain"], "count": int(row["count"])} for row in domains],
            "embedding_models": [
                {
                    "model": row["embedding_model"],
                    "provider": row["provider"],
                    "dimension": int(row["embedding_dim"]),
                    "count": int(row["count"]),
                }
                for row in models
            ],
        }

    def search_document_chunks_by_embedding(
        self,
        query_embedding: list[float],
        *,
        embedding_model: str,
        target_id: str | None = None,
        metadata_filters: dict[str, object] | None = None,
        limit: int = 8,
    ) -> list[dict[str, Any]]:
        where = ["e.record_type = %s", "e.embedding_model = %s"]
        params: list[Any] = [_vector_literal(query_embedding), "document_chunk", embedding_model]
        if target_id:
            where.append("c.target_id = %s")
            params.append(target_id)
        self._append_document_chunk_metadata_filters(where, params, metadata_filters or {}, table_alias="c")
        rows = self._query(
            f"""
            WITH query_embedding AS (SELECT %s::vector AS embedding)
            SELECT c.*, e.embedding <=> query_embedding.embedding AS distance
            FROM record_embeddings e
            JOIN document_chunks c ON c.id = e.record_id
            CROSS JOIN query_embedding
            WHERE {' AND '.join(where)}
            ORDER BY e.embedding <=> query_embedding.embedding ASC
            LIMIT %s
            """,
            (*params, limit),
        )
        return [
            {
                "chunk": self._document_chunk_from_row(row),
                "score": round(1.0 / (1.0 + float(row["distance"] or 0.0)), 4),
                "distance": float(row["distance"] or 0.0),
                "embedding_model": embedding_model,
            }
            for row in rows
        ]

    def _append_document_chunk_metadata_filters(
        self,
        where: list[str],
        params: list[Any],
        metadata_filters: dict[str, object],
        *,
        table_alias: str = "",
    ) -> None:
        prefix = f"{table_alias}." if table_alias else ""
        metadata_filters = {
            self._document_chunk_metadata_filter_key(key): value for key, value in metadata_filters.items()
        }
        for key, json_keys in _DOCUMENT_CHUNK_METADATA_FILTER_KEYS.items():
            if key not in metadata_filters:
                continue
            value = metadata_filters[key]
            if value is None or value == "" or value == []:
                continue
            if isinstance(value, bool):
                clauses = [f"COALESCE({prefix}metadata->>%s, 'false') = %s" for _item in json_keys]
                where.append("(" + " OR ".join(clauses) + ")")
                for item in json_keys:
                    params.extend([item, "true" if value else "false"])
                continue
            values = [str(item) for item in value] if isinstance(value, list | tuple | set) else [str(value)]
            values = [self._document_chunk_metadata_filter_value(key, item) for item in values]
            clauses = [
                f"({prefix}metadata->>%s = ANY(%s) OR COALESCE({prefix}metadata->%s, '[]'::jsonb) ?| %s)"
                for _item in json_keys
            ]
            where.append("(" + " OR ".join(clauses) + ")")
            for item in json_keys:
                params.extend([item, values, item, values])
        for key, json_key in _DOCUMENT_CHUNK_NUMERIC_FILTER_KEYS.items():
            if key not in metadata_filters:
                continue
            value = metadata_filters[key]
            if isinstance(value, dict):
                threshold = value.get("gte")
            else:
                threshold = value
            try:
                numeric = float(threshold)
            except (TypeError, ValueError):
                continue
            where.append(f"NULLIF({prefix}metadata->>%s, '')::double precision >= %s")
            params.extend([json_key, numeric])

    @staticmethod
    def _document_chunk_metadata_filter_key(key: object) -> str:
        normalized = normalized_context_key(key)
        if normalized == "corpus_type":
            return "domain"
        return normalized

    @staticmethod
    def _document_chunk_metadata_filter_value(key: str, value: object) -> str:
        if key != "domain":
            return str(value)
        return canonical_rag_domain(value)

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

    def insert_checkpoint(self, checkpoint: CheckpointRecord) -> None:
        self._execute(
            """
            INSERT INTO checkpoints
            (id, task_id, run_id, kind, path, summary, metadata, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET task_id = EXCLUDED.task_id, run_id = EXCLUDED.run_id, kind = EXCLUDED.kind, path = EXCLUDED.path, summary = EXCLUDED.summary, metadata = EXCLUDED.metadata, created_at = EXCLUDED.created_at
            """,
            (
                checkpoint.id,
                checkpoint.task_id,
                checkpoint.run_id,
                checkpoint.kind.value,
                checkpoint.path,
                checkpoint.summary,
                _dump(checkpoint.metadata),
                checkpoint.created_at.isoformat(),
            ),
        )

    def list_checkpoints(self, limit: int = 100) -> list[CheckpointRecord]:
        rows = self._query("SELECT * FROM checkpoints ORDER BY created_at DESC LIMIT %s", (limit,))
        return [self._checkpoint_from_row(row) for row in rows]

    def get_checkpoint(self, checkpoint_id: str) -> CheckpointRecord | None:
        row = self._query_one("SELECT * FROM checkpoints WHERE id = %s", (checkpoint_id,))
        return self._checkpoint_from_row(row) if row else None

    @staticmethod
    def _normalize_trace_metadata(trace: AgentTrace) -> dict[str, object]:
        metadata = dict(trace.metadata)
        metadata.setdefault("model", "")
        metadata.setdefault("role_name", trace.role.value)
        metadata.setdefault("task_type", str(metadata.get("summary_key") or metadata.get("kind") or "runtime.trace"))
        metadata.setdefault("stage", str(metadata.get("stage") or "runtime"))
        return metadata

    def insert_trace(self, trace: AgentTrace) -> None:
        trace.metadata = self._normalize_trace_metadata(trace)
        self._execute(
            """
            INSERT INTO agent_traces
            (id, task_id, role, status, summary, metadata, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET task_id = EXCLUDED.task_id, role = EXCLUDED.role, status = EXCLUDED.status, summary = EXCLUDED.summary, metadata = EXCLUDED.metadata, created_at = EXCLUDED.created_at
            """,
            (
                trace.id,
                trace.task_id,
                trace.role.value,
                trace.status,
                trace.summary,
                _dump(trace.metadata),
                trace.created_at.isoformat(),
            ),
        )

    def insert_remote_cost(
        self,
        *,
        route: str,
        model: str,
        task_id: str | None = None,
        prompt_tokens: int | None = None,
        completion_tokens: int | None = None,
        estimated_cost_usd: float = 0.0,
    ) -> None:
        self._execute(
            """
            INSERT INTO remote_provider_costs
            (id, route, model, task_id, prompt_tokens, completion_tokens, estimated_cost_usd, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                _new_id("rcost"),
                route,
                model,
                task_id,
                prompt_tokens,
                completion_tokens,
                estimated_cost_usd,
                utc_now().isoformat(),
            ),
        )

    def get_daily_remote_cost_usd(self) -> float:
        rows = self._query(
            """
            SELECT COALESCE(SUM(estimated_cost_usd), 0.0) AS total
            FROM remote_provider_costs
            WHERE created_at >= CURRENT_DATE
            """,
        )
        if rows:
            return float(rows[0]["total"] or 0.0)
        return 0.0

    def insert_model_eval_ledger(
        self,
        *,
        summary: dict[str, Any],
        artifacts: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        run_id = _new_id("meval")
        created_at = utc_now().isoformat()
        recommendations = summary.get("recommendations", {})
        if not isinstance(recommendations, dict):
            recommendations = {}
        aggregate_rows = summary.get("aggregate_rows", [])
        if not isinstance(aggregate_rows, list):
            aggregate_rows = []
        results = summary.get("results", [])
        if not isinstance(results, list):
            results = []
        artifacts_payload = artifacts or summary.get("artifacts", {})
        if not isinstance(artifacts_payload, dict):
            artifacts_payload = {}

        with closing(self.connect()) as connection:
            connection.execute(
                """
                INSERT INTO model_eval_runs
                (id, providers, models, recommendations, artifacts, metadata, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    run_id,
                    _dump(summary.get("providers", [])),
                    _dump(summary.get("models", [])),
                    _dump(recommendations),
                    _dump(artifacts_payload),
                    _dump(metadata or {}),
                    created_at,
                ),
            )
            suggestions = summary.get("role_suggestions", [])
            for role, model_id in sorted((str(k), str(v)) for k, v in recommendations.items() if str(v).strip()):
                self._insert_model_eval_role_metric(
                    connection,
                    run_id=run_id,
                    role=role,
                    model_id=model_id,
                    aggregate_rows=aggregate_rows,
                    results=results,
                    suggestions=suggestions,
                    created_at=created_at,
                )
            connection.commit()
        return run_id

    def _insert_model_eval_role_metric(
        self,
        connection: Any,
        *,
        run_id: str,
        role: str,
        model_id: str,
        aggregate_rows: list[Any],
        results: list[Any],
        suggestions: Any,
        created_at: str,
    ) -> None:
        aggregate = self._aggregate_row_for_recommendation(aggregate_rows, model_id)
        suggestion = self._role_suggestion_for_recommendation(suggestions, role, model_id)
        role_results = self._eval_results_for_role_model(results, role, model_id)
        metrics = self._role_eval_metrics(role_results)
        connection.execute(
            """
            INSERT INTO model_eval_role_metrics
            (
                id, run_id, role, provider, model, aggregate_score, pass_rate, fail_rate,
                hallucination_count, hallucination_rate, over_refusal_rate, correct_refusal_rate,
                unsafe_compliance_failures, top_failure_modes, avg_latency_sec, avg_tokens_sec,
                best_context_length, quantization, params, metadata, created_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                _new_id("mrole"),
                run_id,
                role,
                str(aggregate.get("provider") or self._provider_from_model_id(model_id)),
                str(aggregate.get("model") or self._model_from_model_id(model_id)),
                float(aggregate.get("aggregate_score") or metrics["aggregate_score"] or 0.0),
                float(metrics["pass_rate"]),
                float(metrics["fail_rate"]),
                int(metrics["hallucination_count"]),
                float(aggregate.get("hallucination_rate") or metrics["hallucination_rate"]),
                float(aggregate.get("over_refusal_rate") or metrics["over_refusal_rate"]),
                float(aggregate.get("correct_refusal_rate") or metrics["correct_refusal_rate"]),
                int(metrics["unsafe_compliance_failures"]),
                _dump(metrics["top_failure_modes"]),
                self._optional_float(aggregate.get("avg_latency_sec")),
                self._optional_float(aggregate.get("avg_tokens_sec")),
                self._optional_int_value(aggregate.get("best_context_length")),
                str(aggregate.get("quantization") or ""),
                str(aggregate.get("params") or ""),
                _dump({"aggregate": aggregate, "model_id": model_id, "suggestion": suggestion}),
                created_at,
            ),
        )

    def latest_model_eval_role_metrics(self) -> dict[str, dict[str, Any]]:
        rows = self._query(
            """
            SELECT m.*
            FROM model_eval_role_metrics m
            JOIN (
                SELECT role, MAX(created_at) AS max_created_at
                FROM model_eval_role_metrics
                GROUP BY role
            ) latest ON latest.role = m.role AND latest.max_created_at = m.created_at
            ORDER BY m.role ASC
            """
        )
        return {str(row["role"]): self._model_eval_role_metric_from_row(row) for row in rows}

    def list_model_eval_history(self, limit: int = 10) -> list[dict[str, Any]]:
        rows = self._query(
            "SELECT * FROM model_eval_runs ORDER BY created_at DESC LIMIT %s",
            (limit,),
        )
        return [
            {
                "id": row["id"],
                "providers": _load(row["providers"], []),
                "models": _load(row["models"], []),
                "recommendations": _load(row["recommendations"], {}),
                "artifacts": _load(row["artifacts"], {}),
                "metadata": _load(row["metadata"], {}),
                "created_at": row["created_at"].isoformat() if hasattr(row["created_at"], "isoformat") else row["created_at"],
            }
            for row in rows
        ]

    def _model_eval_role_metric_from_row(self, row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "run_id": row["run_id"],
            "role": row["role"],
            "provider": row["provider"],
            "model": row["model"],
            "aggregate_score": float(row["aggregate_score"]),
            "pass_rate": float(row["pass_rate"]),
            "fail_rate": float(row["fail_rate"]),
            "hallucination_count": int(row["hallucination_count"]),
            "hallucination_rate": float(row["hallucination_rate"]),
            "over_refusal_rate": float(row["over_refusal_rate"]),
            "correct_refusal_rate": float(row["correct_refusal_rate"]),
            "unsafe_compliance_failures": int(row["unsafe_compliance_failures"]),
            "top_failure_modes": _load(row["top_failure_modes"], []),
            "avg_latency_sec": row["avg_latency_sec"],
            "avg_tokens_sec": row["avg_tokens_sec"],
            "best_context_length": row["best_context_length"],
            "quantization": row["quantization"],
            "params": row["params"],
            "metadata": _load(row["metadata"], {}),
            "last_evaluated": row["created_at"].isoformat() if hasattr(row["created_at"], "isoformat") else row["created_at"],
        }

    def _aggregate_row_for_recommendation(
        self,
        rows: list[Any],
        model_id: str,
    ) -> dict[str, Any]:
        for row in rows:
            if not isinstance(row, dict):
                continue
            provider = str(row.get("provider") or "ollama")
            model = str(row.get("model") or "")
            recommendation_id = model if provider == "ollama" else f"{provider}:{model}"
            provider_slash_id = f"{provider}/{model}" if model else ""
            if recommendation_id == model_id or provider_slash_id == model_id or model == model_id:
                return row
        return {}

    def _role_suggestion_for_recommendation(self, suggestions: Any, role: str, model_id: str) -> dict[str, Any]:
        if not isinstance(suggestions, list):
            return {}
        for suggestion in suggestions:
            if not isinstance(suggestion, dict):
                continue
            suggestion_role = str(suggestion.get("role") or "")
            suggestion_id = str(suggestion.get("recommendation_id") or suggestion.get("model") or "")
            if suggestion_role == role and suggestion_id == model_id:
                return suggestion
        return {}

    def _eval_results_for_role_model(
        self,
        results: list[Any],
        role: str,
        model_id: str,
    ) -> list[dict[str, Any]]:
        rows = []
        for item in results:
            if not isinstance(item, dict) or item.get("stage") != "eval":
                continue
            if str(item.get("role_name") or item.get("category") or "") != role:
                continue
            recommendation_id = str(item.get("recommendation_id") or item.get("model") or "")
            if recommendation_id == model_id or str(item.get("model") or "") == model_id:
                rows.append(item)
        return rows

    def _role_eval_metrics(self, rows: list[dict[str, Any]]) -> dict[str, Any]:
        total = len(rows)
        passed = sum(1 for row in rows if bool(row.get("passed")))
        scores = [float(row.get("score") or 0.0) for row in rows]
        reasons: dict[str, int] = {}
        hallucinations = 0
        over_refusals = 0
        correct_refusals = 0
        unsafe_compliance = 0
        for row in rows:
            for reason in row.get("reasons", []) if isinstance(row.get("reasons", []), list) else []:
                text = str(reason)
                if not text:
                    continue
                reasons[text] = reasons.get(text, 0) + 1
                lowered = text.lower()
                if "hallucinated unsupported facts" in lowered:
                    hallucinations += 1
                if "over-refusal" in lowered:
                    over_refusals += 1
                if "correct refusal" in lowered:
                    correct_refusals += 1
                if "unsafe request was not refused" in lowered:
                    unsafe_compliance += 1
        top_failure_modes = [
            {"reason": reason, "count": count}
            for reason, count in sorted(reasons.items(), key=lambda item: (-item[1], item[0]))[:5]
        ]
        return {
            "aggregate_score": round(sum(scores) / max(1, len(scores)), 4) if scores else 0.0,
            "pass_rate": round(passed / max(1, total), 4),
            "fail_rate": round((total - passed) / max(1, total), 4),
            "hallucination_count": hallucinations,
            "hallucination_rate": round(hallucinations / max(1, total), 4),
            "over_refusal_rate": round(over_refusals / max(1, total), 4),
            "correct_refusal_rate": round(correct_refusals / max(1, total), 4),
            "unsafe_compliance_failures": unsafe_compliance,
            "top_failure_modes": top_failure_modes,
        }

    def _provider_from_model_id(self, model_id: str) -> str:
        return model_id.split(":", 1)[0] if model_id.startswith("lmstudio:") else "ollama"

    def _model_from_model_id(self, model_id: str) -> str:
        return model_id.split(":", 1)[1] if model_id.startswith("lmstudio:") else model_id

    def _optional_float(self, value: Any) -> float | None:
        try:
            if value == "" or value is None:
                return None
            return float(value)
        except (TypeError, ValueError):
            return None

    def _optional_int_value(self, value: Any) -> int | None:
        try:
            if value == "" or value is None:
                return None
            return int(value)
        except (TypeError, ValueError):
            return None

    def list_traces(self, task_id: str | None = None, limit: int = 100) -> list[AgentTrace]:
        if task_id:
            rows = self._query(
                "SELECT * FROM agent_traces WHERE task_id = %s ORDER BY created_at DESC LIMIT %s",
                (task_id, limit),
            )
        else:
            rows = self._query("SELECT * FROM agent_traces ORDER BY created_at DESC LIMIT %s", (limit,))
        return [self._trace_from_row(row) for row in rows]

    def get_trace(self, trace_id: str) -> AgentTrace | None:
        row = self._query_one("SELECT * FROM agent_traces WHERE id = %s", (trace_id,))
        return self._trace_from_row(row) if row else None

    def insert_event(self, event: EventRecord) -> None:
        self._execute(
            """
            INSERT INTO events
            (id, event_type, target_id, task_id, summary, metadata, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET event_type = EXCLUDED.event_type, target_id = EXCLUDED.target_id, task_id = EXCLUDED.task_id, summary = EXCLUDED.summary, metadata = EXCLUDED.metadata, created_at = EXCLUDED.created_at
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

    def list_events(self, limit: int = 100) -> list[EventRecord]:
        rows = self._query("SELECT * FROM events ORDER BY created_at DESC LIMIT %s", (limit,))
        return [self._event_from_row(row) for row in rows]

    def get_event(self, event_id: str) -> EventRecord | None:
        row = self._query_one("SELECT * FROM events WHERE id = %s", (event_id,))
        return self._event_from_row(row) if row else None

    def insert_operator_message(self, message: OperatorMessage) -> None:
        self._execute(
            """
            INSERT INTO operator_messages
            (id, role, target_id, model, body, metadata, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET role = EXCLUDED.role, target_id = EXCLUDED.target_id, model = EXCLUDED.model, body = EXCLUDED.body, metadata = EXCLUDED.metadata, created_at = EXCLUDED.created_at
            """,
            (
                message.id,
                message.role,
                message.target_id,
                message.model,
                message.body,
                _dump(message.metadata),
                message.created_at.isoformat(),
            ),
        )

    def list_operator_messages(
        self,
        *,
        target_id: str | None = None,
        limit: int = 50,
    ) -> list[OperatorMessage]:
        if target_id:
            rows = self._query(
                """
                SELECT * FROM operator_messages
                WHERE target_id = %s OR target_id IS NULL
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (target_id, limit),
            )
        else:
            rows = self._query("SELECT * FROM operator_messages ORDER BY created_at DESC LIMIT %s", (limit,))
        return [self._operator_message_from_row(row) for row in rows]

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

    def _session_from_row(self, row: Any) -> Session:
        return Session(
            id=row["id"],
            methodology=MethodologyName(row["methodology"]),
            profile=ScopeProfile(row["profile"]),
            autonomy_mode=row["autonomy_mode"],
            status=SessionStatus(row["status"]),
            title=row["title"],
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _target_from_row(self, row: Any) -> Target:
        return Target(
            id=row["id"],
            handle=row["handle"],
            display_name=row["display_name"],
            profile=ScopeProfile(row["profile"]),
            in_scope=bool(row["in_scope"]),
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _scope_asset_from_row(self, row: Any) -> ScopeAsset:
        return ScopeAsset(
            id=row["id"],
            target_id=row["target_id"],
            asset=row["asset"],
            asset_type=row["asset_type"],
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
        )

    def _task_from_row(self, row: Any) -> Task:
        return Task(
            id=row["id"],
            target_id=row["target_id"],
            session_id=row["session_id"],
            phase=MethodologyPhase(row["phase"]),
            kind=TaskKind(row["kind"]),
            title=row["title"],
            summary=row["summary"],
            role=AgentRole(row["role"]),
            methodology=MethodologyName(row["methodology"]),
            required_capabilities=_load(row["required_capabilities"], []),
            evidence_refs=_load(row["evidence_refs"], []),
            metadata=_load(row["metadata"], {}),
            status=TaskStatus(row["status"]),
            priority=int(row["priority"]),
            risk_tier=RiskTier(row["risk_tier"]),
            attempts=int(row["attempts"]),
            max_attempts=int(row["max_attempts"]),
            requires_approval=bool(row["requires_approval"]),
            provider_route=ProviderRoute(row["provider_route"]) if row["provider_route"] else None,
            provider_model=row["provider_model"],
            parent_task_id=row["parent_task_id"],
            latest_run_id=row["latest_run_id"],
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _task_run_from_row(self, row: Any) -> TaskRun:
        return TaskRun(
            id=row["id"],
            task_id=row["task_id"],
            status=TaskRunStatus(row["status"]),
            attempt_number=int(row["attempt_number"]),
            role=AgentRole(row["role"]),
            provider_route=ProviderRoute(row["provider_route"]),
            model_name=row["model_name"],
            cold_path=bool(row["cold_path"]),
            heartbeat_at=parse_datetime(row["heartbeat_at"]) if row["heartbeat_at"] else None,
            lease_expires_at=parse_datetime(row["lease_expires_at"]) if row["lease_expires_at"] else None,
            started_at=parse_datetime(row["started_at"]),
            finished_at=parse_datetime(row["finished_at"]) if row["finished_at"] else None,
            trace_summary=row["trace_summary"],
            error=row["error"],
            metadata=_load(row["metadata"], {}),
        )

    def _handoff_from_row(self, row: Any) -> TaskHandoff:
        return TaskHandoff(
            id=row["id"],
            task_id=row["task_id"],
            source_agent=AgentRole(row["source_agent"]),
            destination_agent=AgentRole(row["destination_agent"]),
            reason=row["reason"],
            expected_output_type=row["expected_output_type"],
            evidence_refs=_load(row["evidence_refs"], []),
            hypothesis=row["hypothesis"],
            budget=row["budget"],
            deadline_at=parse_datetime(row["deadline_at"]) if row["deadline_at"] else None,
            status=HandoffStatus(row["status"]),
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
            consumed_at=parse_datetime(row["consumed_at"]) if row["consumed_at"] else None,
        )

    def _evidence_from_row(self, row: Any) -> EvidenceRecord:
        return EvidenceRecord(
            id=row["id"],
            target_id=row["target_id"],
            task_id=row["task_id"],
            type=EvidenceType(row["type"]),
            title=row["title"],
            summary=row["summary"],
            source_ref=row["source_ref"],
            verification_status=VerificationStatus(row["verification_status"]),
            confidence=float(row["confidence"]),
            freshness=float(row["freshness"]),
            artifact_path=row["artifact_path"],
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _note_from_row(self, row: Any) -> Note:
        return Note(
            id=row["id"],
            target_id=row["target_id"],
            task_id=row["task_id"],
            title=row["title"],
            body=row["body"],
            confidence=float(row["confidence"]),
            freshness=float(row["freshness"]),
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _interest_from_row(self, row: Any) -> Interest:
        return Interest(
            id=row["id"],
            target_id=row["target_id"],
            title=row["title"],
            summary=row["summary"],
            evidence_refs=_load(row["evidence_refs"], []),
            status=InterestStatus(row["status"]),
            confidence=float(row["confidence"]),
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _finding_from_row(self, row: Any) -> Finding:
        return Finding(
            id=row["id"],
            target_id=row["target_id"],
            title=row["title"],
            summary=row["summary"],
            severity=FindingSeverity(row["severity"]),
            evidence_refs=_load(row["evidence_refs"], []),
            confidence=float(row["confidence"]),
            verification_status=VerificationStatus(row["verification_status"]),
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _memory_from_row(self, row: Any) -> MemoryEntry:
        return MemoryEntry(
            id=row["id"],
            target_id=row["target_id"],
            layer=MemoryLayer(row["layer"]),
            title=row["title"],
            summary=row["summary"],
            evidence_refs=_load(row["evidence_refs"], []),
            confidence=float(row["confidence"]),
            freshness=float(row["freshness"]),
            status=MemoryStatus(row["status"]),
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _primitive_from_row(self, row: Any) -> PrimitiveManifest:
        return PrimitiveManifest(
            id=row["id"],
            name=row["name"],
            version=row["version"],
            description=row["description"],
            capability_tags=_load(row["capability_tags"], []),
            allowed_phases=[MethodologyPhase(item) for item in _load(row["allowed_phases"], [])],
            runtime=PrimitiveRuntime(row["runtime"]),
            risk_tier=RiskTier(row["risk_tier"]),
            side_effect_level=SideEffectLevel(row["side_effect_level"]),
            required_secrets=_load(row["required_secrets"], []),
            input_schema=_load(row["input_schema"], {}),
            output_schema=_load(row["output_schema"], {}),
            timeout_seconds=int(row["timeout_seconds"]),
            retry_policy=_load(row["retry_policy"], {}),
            evidence_adapter=row["evidence_adapter"],
            sandbox_profile=row["sandbox_profile"],
            healthcheck=row["healthcheck"],
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _artifact_from_row(self, row: Any) -> ArtifactRecord:
        return ArtifactRecord(
            id=row["id"],
            task_id=row["task_id"],
            target_id=row["target_id"],
            kind=ArtifactKind(row["kind"]),
            path=row["path"],
            sha256=row["sha256"],
            size_bytes=int(row["size_bytes"]),
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
        )

    def _document_chunk_from_row(self, row: Any) -> DocumentChunk:
        return DocumentChunk(
            id=row["id"],
            target_id=row["target_id"],
            source_artifact_id=row["source_artifact_id"],
            source_sha256=row["source_sha256"],
            chunk_index=int(row["chunk_index"]),
            title=row["title"],
            text=row["text"],
            token_count=int(row["token_count"]),
            evidence_refs=_load(row["evidence_refs"], []),
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
        )

    def _record_embedding_from_row(self, row: Any) -> RecordEmbedding:
        return RecordEmbedding(
            id=row["id"],
            target_id=row["target_id"],
            record_type=row["record_type"],
            record_id=row["record_id"],
            embedding_model=row["embedding_model"],
            embedding_dim=int(row["embedding_dim"]),
            embedding=self._embedding_from_value(row["embedding"]),
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
        )

    def _embedding_from_value(self, value: Any) -> list[float]:
        if isinstance(value, list | tuple):
            return [float(item) for item in value]
        text = str(value).strip()
        if text.startswith("[") and text.endswith("]"):
            body = text[1:-1].strip()
            if not body:
                return []
            return [float(item.strip()) for item in body.split(",")]
        return []

    def _notification_from_row(self, row: Any) -> NotificationRecord:
        return NotificationRecord(
            id=row["id"],
            channel=NotificationChannel(row["channel"]),
            event_type=row["event_type"],
            summary=row["summary"],
            target_id=row["target_id"],
            task_id=row["task_id"],
            finding_id=row["finding_id"],
            status=NotificationStatus(row["status"]),
            urgency=row["urgency"],
            dedupe_key=row["dedupe_key"],
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _sync_job_from_row(self, row: Any) -> ExternalSyncJob:
        return ExternalSyncJob(
            id=row["id"],
            kind=ExternalSyncKind(row["kind"]),
            target_id=row["target_id"],
            summary=row["summary"],
            payload=_load(row["payload"], {}),
            status=ExternalSyncStatus(row["status"]),
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
            last_error=row["last_error"],
        )

    def _notion_page_from_row(self, row: Any) -> NotionPage:
        return NotionPage(
            id=row["id"],
            target_id=row["target_id"],
            page_type=row["page_type"],
            title=row["title"],
            external_id=row["external_id"],
            status=row["status"],
            url=row["url"],
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _discord_delivery_from_row(self, row: Any) -> DiscordDelivery:
        return DiscordDelivery(
            id=row["id"],
            notification_id=row["notification_id"],
            status=NotificationStatus(row["status"]),
            external_ref=row["external_ref"],
            attempts=int(row["attempts"]),
            last_error=row["last_error"],
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _checkpoint_from_row(self, row: Any) -> CheckpointRecord:
        return CheckpointRecord(
            id=row["id"],
            task_id=row["task_id"],
            run_id=row["run_id"],
            kind=CheckpointKind(row["kind"]),
            path=row["path"],
            summary=row["summary"],
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
        )

    def _trace_from_row(self, row: Any) -> AgentTrace:
        return AgentTrace(
            id=row["id"],
            task_id=row["task_id"],
            role=AgentRole(row["role"]),
            status=row["status"],
            summary=row["summary"],
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
        )

    def _event_from_row(self, row: Any) -> EventRecord:
        return EventRecord(
            id=row["id"],
            type=EventType(row["event_type"]),
            summary=row["summary"],
            target_id=row["target_id"],
            task_id=row["task_id"],
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
        )

    def _operator_message_from_row(self, row: Any) -> OperatorMessage:
        return OperatorMessage(
            id=row["id"],
            role=row["role"],
            target_id=row["target_id"],
            model=row["model"],
            body=row["body"],
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
        )
