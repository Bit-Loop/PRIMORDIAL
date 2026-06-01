from __future__ import annotations

from primordial.core.storage.runtime_common import *


class RuntimeRagQueriesMixin:
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
