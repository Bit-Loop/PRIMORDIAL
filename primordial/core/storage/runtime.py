from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any, Iterable

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
    PolicyVerdict,
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
    TraceMetadata,
    new_id as _new_id,
    CheckpointRecord,
    DiscordDelivery,
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


def _dump(value: Any) -> str:
    return json.dumps(json_ready(value), sort_keys=True)


def _load(value: str | None, default: Any) -> Any:
    if not value:
        return default
    return json.loads(value)


_SCHEMA_VERSION = 1


class RuntimeStore:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path

    def initialize(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self.connect()) as connection:
            connection.executescript(SCHEMA_SQL)
            self._apply_compat_migrations(connection)
            self._assert_schema_version(connection)
            connection.commit()

    def _assert_schema_version(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)"
        )
        row = connection.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
        if row is None:
            connection.execute("INSERT INTO schema_version (version) VALUES (?)", (_SCHEMA_VERSION,))
        elif int(row[0]) > _SCHEMA_VERSION:
            raise RuntimeError(
                f"Database schema version {row[0]} is newer than this code ({_SCHEMA_VERSION}). "
                "Upgrade the application before opening this database."
            )

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _apply_compat_migrations(self, connection: sqlite3.Connection) -> None:
        self._ensure_column(connection, "tasks", "session_id", "TEXT")
        self._ensure_column(connection, "tasks", "methodology", "TEXT NOT NULL DEFAULT 'web_app_core'")
        self._ensure_column(connection, "tasks", "provider_model", "TEXT")
        self._ensure_column(connection, "tasks", "latest_run_id", "TEXT")
        self._ensure_column(connection, "memory_entries", "status", "TEXT NOT NULL DEFAULT 'active'")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS model_eval_runs (
                id TEXT PRIMARY KEY,
                providers_json TEXT NOT NULL,
                models_json TEXT NOT NULL,
                recommendations_json TEXT NOT NULL,
                artifacts_json TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS model_eval_role_metrics (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                role TEXT NOT NULL,
                provider TEXT NOT NULL,
                model TEXT NOT NULL,
                aggregate_score REAL NOT NULL,
                pass_rate REAL NOT NULL,
                fail_rate REAL NOT NULL,
                hallucination_count INTEGER NOT NULL,
                hallucination_rate REAL NOT NULL,
                over_refusal_rate REAL NOT NULL,
                correct_refusal_rate REAL NOT NULL,
                unsafe_compliance_failures INTEGER NOT NULL,
                top_failure_modes_json TEXT NOT NULL,
                avg_latency_sec REAL,
                avg_tokens_sec REAL,
                best_context_length INTEGER,
                quantization TEXT,
                params TEXT,
                metadata_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(run_id) REFERENCES model_eval_runs(id)
            );
            CREATE INDEX IF NOT EXISTS idx_model_eval_role_created ON model_eval_role_metrics(role, created_at);
            CREATE INDEX IF NOT EXISTS idx_model_eval_run_created ON model_eval_runs(created_at);
            """
        )

    def _ensure_column(
        self,
        connection: sqlite3.Connection,
        table_name: str,
        column_name: str,
        column_sql: str,
    ) -> None:
        rows = list(connection.execute(f"PRAGMA table_info({table_name})"))
        existing = {row[1] for row in rows}
        if column_name in existing:
            return
        connection.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_sql}")

    def _execute(self, sql: str, params: tuple[Any, ...]) -> None:
        with closing(self.connect()) as connection:
            connection.execute(sql, params)
            connection.commit()

    def _query(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with closing(self.connect()) as connection:
            return list(connection.execute(sql, params))

    def _query_one(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        with closing(self.connect()) as connection:
            return connection.execute(sql, params).fetchone()

    def _update(self, table: str, record_id: str, values: dict[str, Any]) -> None:
        assignments = ", ".join(f"{key} = ?" for key in values)
        params = tuple(values.values()) + (record_id,)
        self._execute(f"UPDATE {table} SET {assignments} WHERE id = ?", params)

    def get_setting(self, key: str, default: Any = None) -> Any:
        row = self._query_one("SELECT value_json FROM app_settings WHERE key = ?", (key,))
        if row is None:
            return default
        return _load(row["value_json"], default)

    def set_setting(self, key: str, value: Any) -> None:
        self._execute(
            """
            INSERT OR REPLACE INTO app_settings
            (key, value_json, updated_at)
            VALUES (?, ?, ?)
            """,
            (key, _dump(value), utc_now().isoformat()),
        )

    def purge_synthetic_external_records(self) -> dict[str, int]:
        with closing(self.connect()) as connection:
            fake_notion_rows = list(
                connection.execute(
                    """
                    SELECT id, metadata_json FROM notion_pages
                    WHERE url LIKE 'https://notion.local/%'
                       OR external_id LIKE 'notion-%'
                    """
                )
            )
            fake_job_ids: set[str] = set()
            for row in fake_notion_rows:
                metadata = _load(row["metadata_json"], {})
                if isinstance(metadata, dict) and metadata.get("job_id"):
                    fake_job_ids.add(str(metadata["job_id"]))

            fake_notion_pages = connection.execute(
                """
                DELETE FROM notion_pages
                WHERE url LIKE 'https://notion.local/%'
                   OR external_id LIKE 'notion-%'
                """
            ).rowcount

            fake_discord_rows = list(
                connection.execute(
                    "SELECT notification_id FROM discord_deliveries WHERE external_ref LIKE 'discord://%'"
                )
            )
            fake_notification_ids = [str(row["notification_id"]) for row in fake_discord_rows]
            fake_discord_deliveries = connection.execute(
                "DELETE FROM discord_deliveries WHERE external_ref LIKE 'discord://%'"
            ).rowcount

            fake_jobs_updated = 0
            if fake_job_ids:
                placeholders = ", ".join("?" for _ in fake_job_ids)
                fake_jobs_updated = connection.execute(
                    f"""
                    UPDATE external_sync_jobs
                    SET status = ?, last_error = ?, updated_at = ?
                    WHERE id IN ({placeholders})
                    """,
                    (
                        ExternalSyncStatus.FAILED.value,
                        "legacy synthetic Notion records were removed; real Notion credentials are required",
                        utc_now().isoformat(),
                        *tuple(fake_job_ids),
                    ),
                ).rowcount

            fake_notifications_updated = 0
            if fake_notification_ids:
                placeholders = ", ".join("?" for _ in fake_notification_ids)
                fake_notifications_updated = connection.execute(
                    f"""
                    UPDATE notifications
                    SET status = ?, updated_at = ?
                    WHERE id IN ({placeholders})
                    """,
                    (
                        NotificationStatus.FAILED.value,
                        utc_now().isoformat(),
                        *tuple(fake_notification_ids),
                    ),
                ).rowcount

            connection.commit()
        return {
            "notion_pages": fake_notion_pages,
            "discord_deliveries": fake_discord_deliveries,
            "sync_jobs_updated": fake_jobs_updated,
            "notifications_updated": fake_notifications_updated,
        }

    def insert_session(self, session: Session) -> None:
        self._execute(
            """
            INSERT OR REPLACE INTO sessions
            (id, methodology, profile, autonomy_mode, status, title, metadata_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        rows = self._query("SELECT * FROM sessions ORDER BY created_at DESC LIMIT ?", (limit,))
        return [self._session_from_row(row) for row in rows]

    def get_active_session(self) -> Session | None:
        row = self._query_one(
            "SELECT * FROM sessions WHERE status = ? ORDER BY created_at DESC LIMIT 1",
            (SessionStatus.ACTIVE.value,),
        )
        return self._session_from_row(row) if row else None

    def pause_active_sessions(self) -> int:
        with closing(self.connect()) as connection:
            updated = connection.execute(
                "UPDATE sessions SET status = ?, updated_at = ? WHERE status = ?",
                (SessionStatus.PAUSED.value, utc_now().isoformat(), SessionStatus.ACTIVE.value),
            ).rowcount
            connection.commit()
        return updated

    def insert_target(self, target: Target) -> None:
        self._execute(
            """
            INSERT OR REPLACE INTO targets
            (id, handle, display_name, profile, in_scope, metadata_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                target.id,
                target.handle,
                target.display_name,
                target.profile.value,
                int(target.in_scope),
                _dump(target.metadata),
                target.created_at.isoformat(),
                target.updated_at.isoformat(),
            ),
        )

    def list_targets(self) -> list[Target]:
        rows = self._query("SELECT * FROM targets ORDER BY created_at ASC")
        return [self._target_from_row(row) for row in rows]

    def get_target(self, target_id: str | None) -> Target | None:
        if not target_id:
            return None
        row = self._query_one("SELECT * FROM targets WHERE id = ?", (target_id,))
        return self._target_from_row(row) if row else None

    def get_target_by_handle(self, handle: str, profile: ScopeProfile | None = None) -> Target | None:
        if profile is None:
            row = self._query_one(
                "SELECT * FROM targets WHERE handle = ? ORDER BY created_at DESC LIMIT 1",
                (handle,),
            )
        else:
            row = self._query_one(
                "SELECT * FROM targets WHERE handle = ? AND profile = ? ORDER BY created_at DESC LIMIT 1",
                (handle, profile.value),
            )
        return self._target_from_row(row) if row else None

    def insert_scope_asset(self, asset: ScopeAsset) -> None:
        self._execute(
            """
            INSERT OR REPLACE INTO scope_assets
            (id, target_id, asset, asset_type, metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
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
            connection.execute("DELETE FROM scope_assets WHERE target_id = ?", (target_id,))
            total = connection.total_changes
            connection.commit()
            return total

    def list_scope_assets(self, target_id: str | None = None) -> list[ScopeAsset]:
        if target_id:
            rows = self._query(
                "SELECT * FROM scope_assets WHERE target_id = ? ORDER BY created_at ASC",
                (target_id,),
            )
        else:
            rows = self._query("SELECT * FROM scope_assets ORDER BY created_at ASC")
        return [self._scope_asset_from_row(row) for row in rows]

    def get_scope_asset(self, target_id: str, asset: str) -> ScopeAsset | None:
        row = self._query_one(
            "SELECT * FROM scope_assets WHERE target_id = ? AND asset = ? ORDER BY created_at DESC LIMIT 1",
            (target_id, asset),
        )
        return self._scope_asset_from_row(row) if row else None

    def insert_task(self, task: Task) -> None:
        self._execute(
            """
            INSERT OR REPLACE INTO tasks
            (
                id, target_id, session_id, phase, kind, title, summary, role, methodology,
                required_capabilities_json, evidence_refs_json, metadata_json, status, priority,
                risk_tier, attempts, max_attempts, requires_approval, provider_route, provider_model,
                parent_task_id, latest_run_id, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                int(task.requires_approval),
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

    def get_task(self, task_id: str) -> Task | None:
        row = self._query_one("SELECT * FROM tasks WHERE id = ?", (task_id,))
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
            where.append("status IN (%s)" % ", ".join("?" for _ in statuses))
            params.extend(status.value for status in statuses)
        if target_id:
            where.append("target_id = ?")
            params.append(target_id)
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        rows = self._query(
            f"SELECT * FROM tasks {clause} ORDER BY priority DESC, created_at ASC LIMIT ?",
            (*params, limit),
        )
        return [self._task_from_row(row) for row in rows]

    def claim_next_pending_task(self) -> Task | None:
        # Single atomic statement: SQLite serializes writers so no two callers
        # can claim the same row. Requires SQLite 3.35+ for RETURNING support.
        with closing(self.connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = list(connection.execute(
                """
                UPDATE tasks SET status = ?, updated_at = ?
                WHERE id = (
                    SELECT id FROM tasks WHERE status = ?
                    ORDER BY priority DESC, created_at ASC LIMIT 1
                )
                RETURNING *
                """,
                (TaskStatus.RUNNING.value, utc_now().isoformat(), TaskStatus.PENDING.value),
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
            WHERE target_id IS ?
              AND kind = ?
              AND status IN (?, ?, ?, ?)
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
        where = ["target_id IS ?", "kind = ?"]
        if statuses:
            where.append("status IN (%s)" % ", ".join("?" for _ in statuses))
            params.extend(status.value for status in statuses)
        row = self._query_one(
            f"SELECT 1 FROM tasks WHERE {' AND '.join(where)} LIMIT 1",
            tuple(params),
        )
        return row is not None

    def insert_task_run(self, run: TaskRun) -> None:
        self._execute(
            """
            INSERT OR REPLACE INTO task_runs
            (
                id, task_id, status, attempt_number, role, provider_route, model_name, cold_path,
                heartbeat_at, lease_expires_at, started_at, finished_at, trace_summary, error, metadata_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run.id,
                run.task_id,
                run.status.value,
                run.attempt_number,
                run.role.value,
                run.provider_route.value,
                run.model_name,
                int(run.cold_path),
                run.heartbeat_at.isoformat() if run.heartbeat_at else None,
                run.lease_expires_at.isoformat() if run.lease_expires_at else None,
                run.started_at.isoformat(),
                run.finished_at.isoformat() if run.finished_at else None,
                run.trace_summary,
                run.error,
                _dump(run.metadata),
            ),
        )

    def list_running_task_runs(self) -> list[TaskRun]:
        rows = self._query(
            "SELECT * FROM task_runs WHERE status = ? ORDER BY started_at DESC",
            (TaskRunStatus.RUNNING.value,),
        )
        return [self._task_run_from_row(row) for row in rows]

    def list_task_runs(self, task_id: str | None = None, limit: int = 100) -> list[TaskRun]:
        if task_id:
            rows = self._query(
                "SELECT * FROM task_runs WHERE task_id = ? ORDER BY started_at DESC LIMIT ?",
                (task_id, limit),
            )
        else:
            rows = self._query("SELECT * FROM task_runs ORDER BY started_at DESC LIMIT ?", (limit,))
        return [self._task_run_from_row(row) for row in rows]

    def insert_handoff(self, handoff: TaskHandoff) -> None:
        self._execute(
            """
            INSERT OR REPLACE INTO task_handoffs
            (
                id, task_id, source_agent, destination_agent, reason, expected_output_type,
                evidence_refs_json, hypothesis, budget, deadline_at, status, metadata_json,
                created_at, consumed_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                "SELECT * FROM task_handoffs WHERE task_id = ? ORDER BY created_at DESC LIMIT ?",
                (task_id, limit),
            )
        else:
            rows = self._query("SELECT * FROM task_handoffs ORDER BY created_at DESC LIMIT ?", (limit,))
        return [self._handoff_from_row(row) for row in rows]

    def insert_evidence(self, evidence: EvidenceRecord) -> None:
        self._execute(
            """
            INSERT OR REPLACE INTO evidence
            (
                id, target_id, task_id, type, title, summary, source_ref, verification_status,
                confidence, freshness, artifact_path, metadata_json, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                "SELECT * FROM evidence WHERE target_id = ? ORDER BY created_at DESC LIMIT ?",
                (target_id, limit),
            )
        else:
            rows = self._query("SELECT * FROM evidence ORDER BY created_at DESC LIMIT ?", (limit,))
        return [self._evidence_from_row(row) for row in rows]

    def insert_note(self, note: Note) -> None:
        self._execute(
            """
            INSERT OR REPLACE INTO notes
            (id, target_id, task_id, title, body, confidence, freshness, metadata_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                "SELECT * FROM notes WHERE target_id = ? ORDER BY created_at DESC LIMIT ?",
                (target_id, limit),
            )
        else:
            rows = self._query("SELECT * FROM notes ORDER BY created_at DESC LIMIT ?", (limit,))
        return [self._note_from_row(row) for row in rows]

    def insert_interest(self, interest: Interest) -> None:
        self._execute(
            """
            INSERT OR REPLACE INTO interests
            (id, target_id, title, summary, evidence_refs_json, status, confidence, metadata_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                "SELECT * FROM interests WHERE target_id = ? ORDER BY created_at DESC LIMIT ?",
                (target_id, limit),
            )
        else:
            rows = self._query("SELECT * FROM interests ORDER BY created_at DESC LIMIT ?", (limit,))
        return [self._interest_from_row(row) for row in rows]

    def insert_finding(self, finding: Finding) -> None:
        self._execute(
            """
            INSERT OR REPLACE INTO findings
            (id, target_id, title, summary, severity, evidence_refs_json, confidence, verification_status, metadata_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                "SELECT * FROM findings WHERE target_id = ? ORDER BY created_at DESC LIMIT ?",
                (target_id, limit),
            )
        else:
            rows = self._query("SELECT * FROM findings ORDER BY created_at DESC LIMIT ?", (limit,))
        return [self._finding_from_row(row) for row in rows]

    def insert_memory_entry(self, entry: MemoryEntry) -> None:
        self._execute(
            """
            INSERT OR REPLACE INTO memory_entries
            (id, target_id, layer, title, summary, evidence_refs_json, confidence, freshness, status, metadata_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            where.append("target_id = ?")
            params.append(target_id)
        if layer:
            where.append("layer = ?")
            params.append(layer.value)
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        rows = self._query(
            f"SELECT * FROM memory_entries {clause} ORDER BY created_at DESC LIMIT ?",
            (*params, limit),
        )
        return [self._memory_from_row(row) for row in rows]

    def insert_policy_decision(self, decision: PolicyDecision) -> None:
        self._execute(
            """
            INSERT OR REPLACE INTO policy_decisions
            (id, action_kind, verdict, reason, target_id, task_id, metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
            INSERT OR REPLACE INTO primitives
            (
                id, name, version, description, capability_tags_json, allowed_phases_json, runtime, risk_tier,
                side_effect_level, required_secrets_json, input_schema_json, output_schema_json, timeout_seconds,
                retry_policy_json, evidence_adapter, sandbox_profile, healthcheck, metadata_json, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            INSERT OR REPLACE INTO artifacts
            (id, task_id, target_id, kind, path, sha256, size_bytes, metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                "SELECT * FROM artifacts WHERE task_id = ? ORDER BY created_at DESC LIMIT ?",
                (task_id, limit),
            )
        else:
            rows = self._query("SELECT * FROM artifacts ORDER BY created_at DESC LIMIT ?", (limit,))
        return [self._artifact_from_row(row) for row in rows]

    def insert_notification(self, notification: NotificationRecord) -> None:
        self._execute(
            """
            INSERT OR REPLACE INTO notifications
            (id, channel, event_type, summary, target_id, task_id, finding_id, status, urgency, dedupe_key, metadata_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                "SELECT * FROM notifications WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                (status.value, limit),
            )
        else:
            rows = self._query("SELECT * FROM notifications ORDER BY created_at DESC LIMIT ?", (limit,))
        return [self._notification_from_row(row) for row in rows]

    def insert_external_sync_job(self, job: ExternalSyncJob) -> None:
        self._execute(
            """
            INSERT OR REPLACE INTO external_sync_jobs
            (id, kind, target_id, summary, payload_json, status, metadata_json, last_error, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                "SELECT * FROM external_sync_jobs WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                (status.value, limit),
            )
        else:
            rows = self._query(
                "SELECT * FROM external_sync_jobs ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
        return [self._sync_job_from_row(row) for row in rows]

    def insert_notion_page(self, page: NotionPage) -> None:
        self._execute(
            """
            INSERT OR REPLACE INTO notion_pages
            (id, target_id, page_type, title, external_id, status, url, metadata_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                "SELECT * FROM notion_pages WHERE target_id = ? ORDER BY created_at DESC LIMIT ?",
                (target_id, limit),
            )
        else:
            rows = self._query("SELECT * FROM notion_pages ORDER BY created_at DESC LIMIT ?", (limit,))
        return [self._notion_page_from_row(row) for row in rows]

    def insert_discord_delivery(self, delivery: DiscordDelivery) -> None:
        self._execute(
            """
            INSERT OR REPLACE INTO discord_deliveries
            (id, notification_id, status, external_ref, attempts, last_error, metadata_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        rows = self._query("SELECT * FROM discord_deliveries ORDER BY created_at DESC LIMIT ?", (limit,))
        return [self._discord_delivery_from_row(row) for row in rows]

    def insert_checkpoint(self, checkpoint: CheckpointRecord) -> None:
        self._execute(
            """
            INSERT OR REPLACE INTO checkpoints
            (id, task_id, run_id, kind, path, summary, metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
        rows = self._query("SELECT * FROM checkpoints ORDER BY created_at DESC LIMIT ?", (limit,))
        return [self._checkpoint_from_row(row) for row in rows]

    @staticmethod
    def _validate_trace_metadata(trace: AgentTrace) -> None:
        missing = TraceMetadata.REQUIRED_KEYS - trace.metadata.keys()
        if missing:
            import logging
            logging.getLogger(__name__).warning(
                "AgentTrace %s missing required metadata fields: %s",
                trace.id,
                sorted(missing),
            )

    def insert_trace(self, trace: AgentTrace) -> None:
        self._validate_trace_metadata(trace)
        self._execute(
            """
            INSERT OR REPLACE INTO agent_traces
            (id, task_id, role, status, summary, metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
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
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
            SELECT COALESCE(SUM(estimated_cost_usd), 0.0)
            FROM remote_provider_costs
            WHERE created_at >= date('now')
            """,
        )
        if rows:
            return float(rows[0][0] or 0.0)
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
                (id, providers_json, models_json, recommendations_json, artifacts_json, metadata_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
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
            for role, model_id in sorted((str(k), str(v)) for k, v in recommendations.items() if str(v).strip()):
                aggregate = self._aggregate_row_for_recommendation(aggregate_rows, model_id)
                role_results = self._eval_results_for_role_model(results, role, model_id)
                metrics = self._role_eval_metrics(role_results)
                connection.execute(
                    """
                    INSERT INTO model_eval_role_metrics
                    (
                        id, run_id, role, provider, model, aggregate_score, pass_rate, fail_rate,
                        hallucination_count, hallucination_rate, over_refusal_rate, correct_refusal_rate,
                        unsafe_compliance_failures, top_failure_modes_json, avg_latency_sec, avg_tokens_sec,
                        best_context_length, quantization, params, metadata_json, created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                        _dump({"aggregate": aggregate, "model_id": model_id}),
                        created_at,
                    ),
                )
            connection.commit()
        return run_id

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
            "SELECT * FROM model_eval_runs ORDER BY created_at DESC LIMIT ?",
            (limit,),
        )
        return [
            {
                "id": row["id"],
                "providers": _load(row["providers_json"], []),
                "models": _load(row["models_json"], []),
                "recommendations": _load(row["recommendations_json"], {}),
                "artifacts": _load(row["artifacts_json"], {}),
                "metadata": _load(row["metadata_json"], {}),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def _model_eval_role_metric_from_row(self, row: sqlite3.Row) -> dict[str, Any]:
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
            "top_failure_modes": _load(row["top_failure_modes_json"], []),
            "avg_latency_sec": row["avg_latency_sec"],
            "avg_tokens_sec": row["avg_tokens_sec"],
            "best_context_length": row["best_context_length"],
            "quantization": row["quantization"],
            "params": row["params"],
            "metadata": _load(row["metadata_json"], {}),
            "last_evaluated": row["created_at"],
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
            if recommendation_id == model_id or model == model_id:
                return row
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
                "SELECT * FROM agent_traces WHERE task_id = ? ORDER BY created_at DESC LIMIT ?",
                (task_id, limit),
            )
        else:
            rows = self._query("SELECT * FROM agent_traces ORDER BY created_at DESC LIMIT ?", (limit,))
        return [self._trace_from_row(row) for row in rows]

    def insert_event(self, event: EventRecord) -> None:
        self._execute(
            """
            INSERT OR REPLACE INTO events
            (id, event_type, target_id, task_id, summary, metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
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
        rows = self._query("SELECT * FROM events ORDER BY created_at DESC LIMIT ?", (limit,))
        return [self._event_from_row(row) for row in rows]

    def insert_operator_message(self, message: OperatorMessage) -> None:
        self._execute(
            """
            INSERT OR REPLACE INTO operator_messages
            (id, role, target_id, model, body, metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
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
                WHERE target_id = ? OR target_id IS NULL
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (target_id, limit),
            )
        else:
            rows = self._query("SELECT * FROM operator_messages ORDER BY created_at DESC LIMIT ?", (limit,))
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
        )
        counts: dict[str, int] = {}
        for table in tables:
            row = self._query_one(f"SELECT COUNT(*) AS count FROM {table}")
            counts[table] = int(row["count"]) if row else 0
        return counts

    def delete_target_cascade(self, target_id: str) -> dict[str, Any]:
        with closing(self.connect()) as connection:
            task_ids = self._select_ids(connection, "SELECT id FROM tasks WHERE target_id = ?", (target_id,))
            run_ids = self._select_ids_for_parent(connection, "task_runs", "task_id", task_ids)
            notification_ids = self._select_notifications_for_target(connection, target_id, task_ids)
            artifact_paths = self._select_paths_for_target(connection, "artifacts", target_id, task_ids)
            checkpoint_paths = self._select_checkpoint_paths(connection, task_ids, run_ids)

            deleted = {
                "discord_deliveries": self._delete_ids(connection, "discord_deliveries", "notification_id", notification_ids),
                "task_handoffs": self._delete_ids(connection, "task_handoffs", "task_id", task_ids),
                "task_runs": self._delete_ids(connection, "task_runs", "task_id", task_ids),
                "checkpoints": self._delete_checkpoints(connection, task_ids, run_ids),
                "agent_traces": self._delete_ids(connection, "agent_traces", "task_id", task_ids),
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
        }

    def _select_ids(
        self,
        connection: sqlite3.Connection,
        sql: str,
        params: tuple[Any, ...],
    ) -> list[str]:
        return [str(row["id"]) for row in connection.execute(sql, params)]

    def _select_ids_for_parent(
        self,
        connection: sqlite3.Connection,
        table: str,
        foreign_key: str,
        parent_ids: list[str],
    ) -> list[str]:
        if not parent_ids:
            return []
        placeholders = ", ".join("?" for _ in parent_ids)
        sql = f"SELECT id FROM {table} WHERE {foreign_key} IN ({placeholders})"
        return [str(row["id"]) for row in connection.execute(sql, tuple(parent_ids))]

    def _select_notifications_for_target(
        self,
        connection: sqlite3.Connection,
        target_id: str,
        task_ids: list[str],
    ) -> list[str]:
        where = ["target_id = ?"]
        params: list[Any] = [target_id]
        if task_ids:
            placeholders = ", ".join("?" for _ in task_ids)
            where.append(f"task_id IN ({placeholders})")
            params.extend(task_ids)
        sql = f"SELECT id FROM notifications WHERE {' OR '.join(where)}"
        return [str(row["id"]) for row in connection.execute(sql, tuple(params))]

    def _select_paths_for_target(
        self,
        connection: sqlite3.Connection,
        table: str,
        target_id: str,
        task_ids: list[str],
    ) -> list[str]:
        where = ["target_id = ?"]
        params: list[Any] = [target_id]
        if task_ids:
            placeholders = ", ".join("?" for _ in task_ids)
            where.append(f"task_id IN ({placeholders})")
            params.extend(task_ids)
        sql = f"SELECT path FROM {table} WHERE {' OR '.join(where)}"
        return [str(row["path"]) for row in connection.execute(sql, tuple(params)) if row["path"]]

    def _select_checkpoint_paths(
        self,
        connection: sqlite3.Connection,
        task_ids: list[str],
        run_ids: list[str],
    ) -> list[str]:
        where: list[str] = []
        params: list[Any] = []
        if task_ids:
            placeholders = ", ".join("?" for _ in task_ids)
            where.append(f"task_id IN ({placeholders})")
            params.extend(task_ids)
        if run_ids:
            placeholders = ", ".join("?" for _ in run_ids)
            where.append(f"run_id IN ({placeholders})")
            params.extend(run_ids)
        if not where:
            return []
        sql = f"SELECT path FROM checkpoints WHERE {' OR '.join(where)}"
        return [str(row["path"]) for row in connection.execute(sql, tuple(params)) if row["path"]]

    def _delete_target_rows(
        self,
        connection: sqlite3.Connection,
        table: str,
        target_id: str,
        *,
        key: str = "target_id",
    ) -> int:
        return connection.execute(f"DELETE FROM {table} WHERE {key} = ?", (target_id,)).rowcount

    def _delete_target_or_task_rows(
        self,
        connection: sqlite3.Connection,
        table: str,
        target_id: str,
        task_ids: list[str],
    ) -> int:
        where = ["target_id = ?"]
        params: list[Any] = [target_id]
        if task_ids:
            placeholders = ", ".join("?" for _ in task_ids)
            where.append(f"task_id IN ({placeholders})")
            params.extend(task_ids)
        sql = f"DELETE FROM {table} WHERE {' OR '.join(where)}"
        return connection.execute(sql, tuple(params)).rowcount

    def _delete_ids(
        self,
        connection: sqlite3.Connection,
        table: str,
        key: str,
        values: list[str],
    ) -> int:
        if not values:
            return 0
        placeholders = ", ".join("?" for _ in values)
        sql = f"DELETE FROM {table} WHERE {key} IN ({placeholders})"
        return connection.execute(sql, tuple(values)).rowcount

    def _delete_checkpoints(
        self,
        connection: sqlite3.Connection,
        task_ids: list[str],
        run_ids: list[str],
    ) -> int:
        where: list[str] = []
        params: list[Any] = []
        if task_ids:
            placeholders = ", ".join("?" for _ in task_ids)
            where.append(f"task_id IN ({placeholders})")
            params.extend(task_ids)
        if run_ids:
            placeholders = ", ".join("?" for _ in run_ids)
            where.append(f"run_id IN ({placeholders})")
            params.extend(run_ids)
        if not where:
            return 0
        sql = f"DELETE FROM checkpoints WHERE {' OR '.join(where)}"
        return connection.execute(sql, tuple(params)).rowcount

    def target_has_evidence(self, target_id: str) -> bool:
        row = self._query_one("SELECT 1 FROM evidence WHERE target_id = ? LIMIT 1", (target_id,))
        return row is not None

    def verified_interest_count(self, target_id: str) -> int:
        row = self._query_one(
            "SELECT COUNT(*) AS count FROM interests WHERE target_id = ? AND status = ?",
            (target_id, InterestStatus.VERIFIED.value),
        )
        return int(row["count"]) if row else 0

    def memory_entry_exists(self, *, target_id: str, layer: MemoryLayer, title: str) -> bool:
        row = self._query_one(
            """
            SELECT 1 FROM memory_entries
            WHERE target_id = ? AND layer = ? AND title = ? AND status != ?
            LIMIT 1
            """,
            (target_id, layer.value, title, MemoryStatus.SUPERSEDED.value),
        )
        return row is not None

    def find_latest_notification_by_dedupe(self, dedupe_key: str) -> NotificationRecord | None:
        row = self._query_one(
            """
            SELECT * FROM notifications
            WHERE dedupe_key = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (dedupe_key,),
        )
        return self._notification_from_row(row) if row else None

    def _session_from_row(self, row: sqlite3.Row) -> Session:
        return Session(
            id=row["id"],
            methodology=MethodologyName(row["methodology"]),
            profile=ScopeProfile(row["profile"]),
            autonomy_mode=row["autonomy_mode"],
            status=SessionStatus(row["status"]),
            title=row["title"],
            metadata=_load(row["metadata_json"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _target_from_row(self, row: sqlite3.Row) -> Target:
        return Target(
            id=row["id"],
            handle=row["handle"],
            display_name=row["display_name"],
            profile=ScopeProfile(row["profile"]),
            in_scope=bool(row["in_scope"]),
            metadata=_load(row["metadata_json"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _scope_asset_from_row(self, row: sqlite3.Row) -> ScopeAsset:
        return ScopeAsset(
            id=row["id"],
            target_id=row["target_id"],
            asset=row["asset"],
            asset_type=row["asset_type"],
            metadata=_load(row["metadata_json"], {}),
            created_at=parse_datetime(row["created_at"]),
        )

    def _task_from_row(self, row: sqlite3.Row) -> Task:
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
            required_capabilities=_load(row["required_capabilities_json"], []),
            evidence_refs=_load(row["evidence_refs_json"], []),
            metadata=_load(row["metadata_json"], {}),
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

    def _task_run_from_row(self, row: sqlite3.Row) -> TaskRun:
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
            metadata=_load(row["metadata_json"], {}),
        )

    def _handoff_from_row(self, row: sqlite3.Row) -> TaskHandoff:
        return TaskHandoff(
            id=row["id"],
            task_id=row["task_id"],
            source_agent=AgentRole(row["source_agent"]),
            destination_agent=AgentRole(row["destination_agent"]),
            reason=row["reason"],
            expected_output_type=row["expected_output_type"],
            evidence_refs=_load(row["evidence_refs_json"], []),
            hypothesis=row["hypothesis"],
            budget=row["budget"],
            deadline_at=parse_datetime(row["deadline_at"]) if row["deadline_at"] else None,
            status=HandoffStatus(row["status"]),
            metadata=_load(row["metadata_json"], {}),
            created_at=parse_datetime(row["created_at"]),
            consumed_at=parse_datetime(row["consumed_at"]) if row["consumed_at"] else None,
        )

    def _evidence_from_row(self, row: sqlite3.Row) -> EvidenceRecord:
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
            metadata=_load(row["metadata_json"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _note_from_row(self, row: sqlite3.Row) -> Note:
        return Note(
            id=row["id"],
            target_id=row["target_id"],
            task_id=row["task_id"],
            title=row["title"],
            body=row["body"],
            confidence=float(row["confidence"]),
            freshness=float(row["freshness"]),
            metadata=_load(row["metadata_json"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _interest_from_row(self, row: sqlite3.Row) -> Interest:
        return Interest(
            id=row["id"],
            target_id=row["target_id"],
            title=row["title"],
            summary=row["summary"],
            evidence_refs=_load(row["evidence_refs_json"], []),
            status=InterestStatus(row["status"]),
            confidence=float(row["confidence"]),
            metadata=_load(row["metadata_json"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _finding_from_row(self, row: sqlite3.Row) -> Finding:
        return Finding(
            id=row["id"],
            target_id=row["target_id"],
            title=row["title"],
            summary=row["summary"],
            severity=FindingSeverity(row["severity"]),
            evidence_refs=_load(row["evidence_refs_json"], []),
            confidence=float(row["confidence"]),
            verification_status=VerificationStatus(row["verification_status"]),
            metadata=_load(row["metadata_json"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _memory_from_row(self, row: sqlite3.Row) -> MemoryEntry:
        return MemoryEntry(
            id=row["id"],
            target_id=row["target_id"],
            layer=MemoryLayer(row["layer"]),
            title=row["title"],
            summary=row["summary"],
            evidence_refs=_load(row["evidence_refs_json"], []),
            confidence=float(row["confidence"]),
            freshness=float(row["freshness"]),
            status=MemoryStatus(row["status"]),
            metadata=_load(row["metadata_json"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _primitive_from_row(self, row: sqlite3.Row) -> PrimitiveManifest:
        return PrimitiveManifest(
            id=row["id"],
            name=row["name"],
            version=row["version"],
            description=row["description"],
            capability_tags=_load(row["capability_tags_json"], []),
            allowed_phases=[MethodologyPhase(item) for item in _load(row["allowed_phases_json"], [])],
            runtime=PrimitiveRuntime(row["runtime"]),
            risk_tier=RiskTier(row["risk_tier"]),
            side_effect_level=SideEffectLevel(row["side_effect_level"]),
            required_secrets=_load(row["required_secrets_json"], []),
            input_schema=_load(row["input_schema_json"], {}),
            output_schema=_load(row["output_schema_json"], {}),
            timeout_seconds=int(row["timeout_seconds"]),
            retry_policy=_load(row["retry_policy_json"], {}),
            evidence_adapter=row["evidence_adapter"],
            sandbox_profile=row["sandbox_profile"],
            healthcheck=row["healthcheck"],
            metadata=_load(row["metadata_json"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _artifact_from_row(self, row: sqlite3.Row) -> ArtifactRecord:
        return ArtifactRecord(
            id=row["id"],
            task_id=row["task_id"],
            target_id=row["target_id"],
            kind=ArtifactKind(row["kind"]),
            path=row["path"],
            sha256=row["sha256"],
            size_bytes=int(row["size_bytes"]),
            metadata=_load(row["metadata_json"], {}),
            created_at=parse_datetime(row["created_at"]),
        )

    def _notification_from_row(self, row: sqlite3.Row) -> NotificationRecord:
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
            metadata=_load(row["metadata_json"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _sync_job_from_row(self, row: sqlite3.Row) -> ExternalSyncJob:
        return ExternalSyncJob(
            id=row["id"],
            kind=ExternalSyncKind(row["kind"]),
            target_id=row["target_id"],
            summary=row["summary"],
            payload=_load(row["payload_json"], {}),
            status=ExternalSyncStatus(row["status"]),
            metadata=_load(row["metadata_json"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
            last_error=row["last_error"],
        )

    def _notion_page_from_row(self, row: sqlite3.Row) -> NotionPage:
        return NotionPage(
            id=row["id"],
            target_id=row["target_id"],
            page_type=row["page_type"],
            title=row["title"],
            external_id=row["external_id"],
            status=row["status"],
            url=row["url"],
            metadata=_load(row["metadata_json"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _discord_delivery_from_row(self, row: sqlite3.Row) -> DiscordDelivery:
        return DiscordDelivery(
            id=row["id"],
            notification_id=row["notification_id"],
            status=NotificationStatus(row["status"]),
            external_ref=row["external_ref"],
            attempts=int(row["attempts"]),
            last_error=row["last_error"],
            metadata=_load(row["metadata_json"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _checkpoint_from_row(self, row: sqlite3.Row) -> CheckpointRecord:
        return CheckpointRecord(
            id=row["id"],
            task_id=row["task_id"],
            run_id=row["run_id"],
            kind=CheckpointKind(row["kind"]),
            path=row["path"],
            summary=row["summary"],
            metadata=_load(row["metadata_json"], {}),
            created_at=parse_datetime(row["created_at"]),
        )

    def _trace_from_row(self, row: sqlite3.Row) -> AgentTrace:
        return AgentTrace(
            id=row["id"],
            task_id=row["task_id"],
            role=AgentRole(row["role"]),
            status=row["status"],
            summary=row["summary"],
            metadata=_load(row["metadata_json"], {}),
            created_at=parse_datetime(row["created_at"]),
        )

    def _event_from_row(self, row: sqlite3.Row) -> EventRecord:
        return EventRecord(
            id=row["id"],
            type=EventType(row["event_type"]),
            summary=row["summary"],
            target_id=row["target_id"],
            task_id=row["task_id"],
            metadata=_load(row["metadata_json"], {}),
            created_at=parse_datetime(row["created_at"]),
        )

    def _operator_message_from_row(self, row: sqlite3.Row) -> OperatorMessage:
        return OperatorMessage(
            id=row["id"],
            role=row["role"],
            target_id=row["target_id"],
            model=row["model"],
            body=row["body"],
            metadata=_load(row["metadata_json"], {}),
            created_at=parse_datetime(row["created_at"]),
        )
