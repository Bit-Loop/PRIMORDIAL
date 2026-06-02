from __future__ import annotations

from primordial.core.storage.runtime_common import *


class RuntimeCatalogRecordsMixin:
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
                _storage_text(primitive.description),
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
                _storage_text(chunk.title),
                _storage_text(chunk.text),
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
