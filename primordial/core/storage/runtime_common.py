from __future__ import annotations

import json
from json import JSONDecodeError
from contextlib import closing
import re
from typing import Any, Iterable

from primordial.core.context.normalization import canonical_rag_domain, normalized_context_key
from primordial.core.sensitive_text import redact_sensitive_text

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
_RAW_CONTENT_METADATA_KEYS = {
    "raw_text",
    "request_body",
    "response_body",
    "raw_request",
    "raw_response",
    "request_payload",
    "response_payload",
}


def _dump(value: Any) -> Any:
    ready = json_ready(_sanitize_storage_metadata(value))
    if Jsonb is not None:
        return Jsonb(ready)
    return json.dumps(ready, sort_keys=True)


def _sanitize_storage_metadata(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            text_key = str(key)
            if normalized_context_key(text_key) in _RAW_CONTENT_METADATA_KEYS:
                sanitized[text_key] = "[redacted]"
            else:
                sanitized[text_key] = _sanitize_storage_metadata(item)
        return sanitized
    if isinstance(value, list):
        return [_sanitize_storage_metadata(item) for item in value]
    if isinstance(value, tuple):
        return [_sanitize_storage_metadata(item) for item in value]
    if isinstance(value, set):
        return [_sanitize_storage_metadata(item) for item in value]
    if isinstance(value, bytes):
        return redact_sensitive_text(value.decode("utf-8", errors="replace"))
    if isinstance(value, str):
        return redact_sensitive_text(value)
    return value


def _storage_text(value: Any) -> str:
    return redact_sensitive_text(str(value or ""))


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


__all__ = [name for name in globals() if not name.startswith("__")]
