from __future__ import annotations

from primordial.core.storage.runtime_common import *
from primordial.core.storage.runtime_settings import RuntimeSettingsMixin
from primordial.core.storage.runtime_sessions_targets import RuntimeSessionsTargetsMixin
from primordial.core.storage.runtime_tasks import RuntimeTasksMixin
from primordial.core.storage.runtime_task_runs import RuntimeTaskRunsMixin
from primordial.core.storage.runtime_handoffs import RuntimeHandoffsMixin
from primordial.core.storage.runtime_records import RuntimeRecordsMixin
from primordial.core.storage.runtime_catalog_records import RuntimeCatalogRecordsMixin
from primordial.core.storage.runtime_rag_queries import RuntimeRagQueriesMixin
from primordial.core.storage.runtime_notifications_sync import RuntimeNotificationsSyncMixin
from primordial.core.storage.runtime_checkpoints_traces import RuntimeCheckpointsTracesMixin
from primordial.core.storage.runtime_model_eval import RuntimeModelEvalMixin
from primordial.core.storage.runtime_events_messages import RuntimeEventsMessagesMixin
from primordial.core.storage.runtime_counts_delete import RuntimeCountsDeleteMixin
from primordial.core.storage.runtime_delete_counts import RuntimeDeleteCountsMixin
from primordial.core.storage.runtime_delete_selectors import RuntimeDeleteSelectorsMixin
from primordial.core.storage.runtime_lookup_helpers import RuntimeLookupHelpersMixin
from primordial.core.storage.runtime_row_mappers_core import RuntimeRowMappersCoreMixin
from primordial.core.storage.runtime_row_mappers_extended import RuntimeRowMappersExtendedMixin

__all__ = ["RuntimeStore", "_SCHEMA_VERSION"]


class RuntimeStore(
    RuntimeSettingsMixin,
    RuntimeSessionsTargetsMixin,
    RuntimeTasksMixin,
    RuntimeTaskRunsMixin,
    RuntimeHandoffsMixin,
    RuntimeRecordsMixin,
    RuntimeCatalogRecordsMixin,
    RuntimeRagQueriesMixin,
    RuntimeNotificationsSyncMixin,
    RuntimeCheckpointsTracesMixin,
    RuntimeModelEvalMixin,
    RuntimeEventsMessagesMixin,
    RuntimeCountsDeleteMixin,
    RuntimeDeleteCountsMixin,
    RuntimeDeleteSelectorsMixin,
    RuntimeLookupHelpersMixin,
    RuntimeRowMappersCoreMixin,
    RuntimeRowMappersExtendedMixin,
):
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
