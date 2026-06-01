from __future__ import annotations

from primordial.core.domain.models import DocumentChunk, RecordEmbedding
from primordial.core.rag.importer_types import RagImportOptions, RagImportSummary


class RagImporterEmbeddingMixin:
    def _flush_embeddings(
        self,
        items: list[tuple[DocumentChunk, str]],
        options: RagImportOptions,
        summary: RagImportSummary,
    ) -> None:
        to_embed = self._embedding_work_items(items, options, summary)
        if not to_embed:
            return
        try:
            vectors = self.embedding_provider.embed_batch([chunk.text for chunk, _hash in to_embed])
        except Exception as exc:  # noqa: BLE001
            summary.errors.append(f"embedding batch failed; retrying per chunk: {exc}")
            self._flush_embeddings_individually(to_embed, summary)
            return
        for (chunk, content_hash), vector in zip(to_embed, vectors, strict=True):
            existing = self._existing_embedding(chunk)
            self._insert_embedding(chunk, content_hash, vector)
            if existing is None:
                summary.embeddings_inserted += 1
            else:
                summary.embeddings_updated += 1

    def _embedding_work_items(
        self,
        items: list[tuple[DocumentChunk, str]],
        options: RagImportOptions,
        summary: RagImportSummary,
    ) -> list[tuple[DocumentChunk, str]]:
        to_embed: list[tuple[DocumentChunk, str]] = []
        for chunk, content_hash in items:
            existing = self._existing_embedding(chunk)
            if (
                existing is not None
                and not options.force
                and not options.reembed
                and existing.metadata.get("chunk_content_hash") == content_hash
                and int(existing.metadata.get("embedding_dimension") or existing.embedding_dim or 0) > 0
            ):
                summary.embeddings_skipped += 1
                continue
            to_embed.append((chunk, content_hash))
        return to_embed

    def _flush_embeddings_individually(
        self,
        items: list[tuple[DocumentChunk, str]],
        summary: RagImportSummary,
    ) -> None:
        for chunk, content_hash in items:
            try:
                vector = self.embedding_provider.embed(chunk.text)
            except Exception as exc:  # noqa: BLE001 - record-level failure must not poison the rest of the import
                summary.failures += 1
                summary.failed_record_ids.append(chunk.id)
                summary.errors.append(f"embedding failed for {chunk.id}: {exc}")
                continue
            existing = self._existing_embedding(chunk)
            self._insert_embedding(chunk, content_hash, vector)
            if existing is None:
                summary.embeddings_inserted += 1
            else:
                summary.embeddings_updated += 1

    def _existing_embedding(self, chunk: DocumentChunk) -> object | None:
        return self.store.get_record_embedding(
            record_type="document_chunk",
            record_id=chunk.id,
            embedding_model=self.embedding_provider.model_name,
        )

    def _insert_embedding(self, chunk: DocumentChunk, content_hash: str, vector: list[float]) -> None:
        self.store.insert_record_embedding(
            RecordEmbedding(
                target_id=chunk.target_id,
                record_type="document_chunk",
                record_id=chunk.id,
                embedding_model=self.embedding_provider.model_name,
                embedding_dim=len(vector),
                embedding=vector,
                metadata={
                    "embedding_provider": self.embedding_provider.provider_name,
                    "provider": self.embedding_provider.provider_name,
                    "embedding_model": self.embedding_provider.model_name,
                    "embedding_dimension": len(vector),
                    "chunk_content_hash": content_hash,
                    "source_sha256": chunk.source_sha256,
                    "doc_id": chunk.metadata.get("doc_id"),
                    "source_file": chunk.metadata.get("source_file"),
                },
            )
        )
