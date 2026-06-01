from __future__ import annotations

import re
from typing import Any

from primordial.core.context.normalization import metadata_value, normalized_context_key
from primordial.core.domain.models import DocumentChunk
from primordial.core.rag.document_types import RagContextItem


class DocumentRetrievalMixin:
    def retrieve(
        self,
        query: str,
        *,
        target_id: str | None,
        limit: int = 5,
        use_embeddings: bool = True,
        corpus_types: list[str] | tuple[str, ...] | set[str] | None = None,
        filters: dict[str, object] | None = None,
    ) -> list[RagContextItem]:
        clean = query.strip()
        if not clean:
            return []
        normalized_corpus = self._normalize_corpus_filter(corpus_types)
        metadata_filters = self._normalize_metadata_filters(filters)
        lexical = self._lexical_context(clean, target_id=target_id, filters=metadata_filters, corpus_types=normalized_corpus, limit=limit)
        if lexical:
            return lexical
        embedded = self._embedding_context(clean, target_id=target_id, filters=metadata_filters, corpus_types=normalized_corpus, limit=limit, enabled=use_embeddings)
        if embedded:
            return embedded
        if normalized_corpus:
            return self._rank_corpus_chunks(clean, target_id=target_id, corpus_types=normalized_corpus, filters=metadata_filters, limit=limit)
        return []

    def _lexical_context(
        self,
        query: str,
        *,
        target_id: str | None,
        filters: dict[str, object],
        corpus_types: set[str] | None,
        limit: int,
    ) -> list[RagContextItem]:
        results = self.store.search_document_chunks_text(query, target_id=target_id, metadata_filters=filters, limit=limit)
        if not results:
            return []
        return self._filter_context_items(self._context_items(results, source="lexical", limit=limit * 4), corpus_types=corpus_types, limit=limit)

    def _embedding_context(
        self,
        query: str,
        *,
        target_id: str | None,
        filters: dict[str, object],
        corpus_types: set[str] | None,
        limit: int,
        enabled: bool,
    ) -> list[RagContextItem]:
        results: list[dict[str, Any]] = []
        if enabled:
            try:
                results = self.store.search_document_chunks_by_embedding(
                    self.embedding_provider.embed(query),
                    embedding_model=self.embedding_provider.model_name,
                    target_id=target_id,
                    metadata_filters=filters,
                    limit=limit,
                )
            except Exception:
                results = []
        return self._filter_context_items(self._context_items(results, source="", limit=limit * 4), corpus_types=corpus_types, limit=limit)

    def _context_items(
        self,
        results: list[dict[str, Any]],
        *,
        source: str,
        limit: int,
    ) -> list[RagContextItem]:
        context: list[RagContextItem] = []
        for item in results[:limit]:
            chunk = item.get("chunk")
            if not isinstance(chunk, DocumentChunk):
                continue
            context.append(
                RagContextItem(
                    chunk=chunk,
                    score=float(item.get("score") or 0.0),
                    source=source or str(item.get("embedding_model") or "lexical"),
                    matched_terms=[str(term) for term in item.get("matched_terms", [])],
                )
            )
        return context

    def _filter_context_items(
        self,
        items: list[RagContextItem],
        *,
        corpus_types: set[str] | None,
        limit: int,
    ) -> list[RagContextItem]:
        if not corpus_types:
            return items[:limit]
        return [
            item
            for item in items
            if str(metadata_value(item.chunk.metadata, "corpus_type") or "operator_note") in corpus_types
        ][:limit]

    def _rank_corpus_chunks(
        self,
        query: str,
        *,
        target_id: str | None,
        corpus_types: set[str],
        filters: dict[str, object],
        limit: int,
    ) -> list[RagContextItem]:
        terms = set(re.findall(r"[A-Za-z0-9_.:/-]+", query.lower()))
        chunks = self.store.list_document_chunks(target_id=target_id, metadata_filters=filters, limit=500)
        ranked = [self._ranked_item(chunk, terms, corpus_types=corpus_types) for chunk in chunks]
        ranked = [item for item in ranked if item is not None]
        ranked.sort(key=lambda item: (-item.score, item.chunk.created_at, item.chunk.chunk_index))
        return ranked[:limit]

    def _ranked_item(self, chunk: DocumentChunk, terms: set[str], *, corpus_types: set[str]) -> RagContextItem | None:
        if str(metadata_value(chunk.metadata, "corpus_type") or "operator_note") not in corpus_types:
            return None
        chunk_terms = set(re.findall(r"[A-Za-z0-9_.:/-]+", f"{chunk.title}\n{chunk.text}".lower()))
        overlap = sorted(term for term in terms & chunk_terms if len(term) > 2)
        score = len(overlap) / max(1, len(terms)) if terms else 0.0
        if score <= 0.0 and corpus_types:
            score = 0.01
        return RagContextItem(chunk=chunk, score=round(score, 4), source="corpus", matched_terms=overlap)

    def _normalize_corpus_filter(
        self,
        corpus_types: list[str] | tuple[str, ...] | set[str] | None,
    ) -> set[str] | None:
        if not corpus_types:
            return None
        return {self._normalize_corpus_type(item) for item in corpus_types}

    def _normalize_metadata_filters(self, filters: dict[str, object] | None) -> dict[str, object]:
        normalized: dict[str, object] = {}
        for key, value in (filters or {}).items():
            filter_key = normalized_context_key(key)
            if filter_key == "corpus_type":
                filter_key = "domain"
            if filter_key == "domain":
                values = value if isinstance(value, list | tuple | set) else [value]
                normalized[filter_key] = [self._normalize_corpus_type(str(item)) for item in values]
                continue
            normalized[filter_key] = value
        return normalized
