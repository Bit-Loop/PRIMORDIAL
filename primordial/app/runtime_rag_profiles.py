from __future__ import annotations

from primordial.app.runtime_deps import (
    DocumentChunk,
)

class RuntimeRagProfilesMixin:
    def rag_chunk_inspect(self, chunk_id: str) -> dict[str, object]:
        normalized = chunk_id.strip()
        if normalized.startswith("rag:"):
            normalized = normalized[4:]
        chunk = self.store.get_document_chunk(normalized)
        if chunk is None:
            citation_id = chunk_id.strip()
            if citation_id and not citation_id.startswith("rag:"):
                citation_id = f"rag:{citation_id}"
            matches = self.store.list_document_chunks(metadata_filters={"citation_id": [citation_id]}, limit=2)
            chunk = matches[0] if matches else None
        if chunk is None:
            raise ValueError(f"RAG chunk not found: {chunk_id}")
        embedding = self.store.get_record_embedding(
            record_type="document_chunk",
            record_id=chunk.id,
            embedding_model=self.rag_embedding_provider.model_name,
        )
        return {
            "chunk": {**chunk.as_payload(), "citation_id": self._rag_chunk_citation_id(chunk)},
            "embedding": embedding.as_payload() if embedding else None,
        }

    def _rag_chunk_citation_id(self, chunk: DocumentChunk) -> str:
        citation_id = str(chunk.metadata.get("citation_id") or "").strip()
        if not citation_id or citation_id in {"rag:None", "rag:null", "rag:unknown"}:
            citation_id = chunk.id
        return citation_id if citation_id.startswith("rag:") else f"rag:{citation_id}"

    def _rag_payload_citation_id(self, item: dict[str, object]) -> str:
        citation_id = str(item.get("citation_id") or "").strip()
        if not citation_id or citation_id in {"rag:None", "rag:null", "rag:unknown"}:
            citation_id = str(item.get("chunk_id") or item.get("id") or "unknown").strip() or "unknown"
        return citation_id if citation_id.startswith("rag:") else f"rag:{citation_id}"

    def rag_source_profile(self, doc_id: str, *, limit: int = 50) -> dict[str, object]:
        clean = str(doc_id or "").strip()
        if not clean:
            raise ValueError("doc_id is required")
        total = self.store.count_document_chunks(metadata_filters={"doc_id": [clean]})
        chunks = self.store.list_document_chunks(metadata_filters={"doc_id": [clean]}, limit=max(1, limit))
        if not chunks:
            raise ValueError(f"RAG source not found: {doc_id}")
        metadata_rows = [chunk.metadata for chunk in chunks if isinstance(chunk.metadata, dict)]
        first = metadata_rows[0] if metadata_rows else {}
        sections = []
        for metadata in metadata_rows:
            section = str(metadata.get("section") or "").strip()
            if section and section not in sections:
                sections.append(section)
        domains = sorted(
            {
                str(metadata.get("domain") or metadata.get("corpus_type") or "").strip()
                for metadata in metadata_rows
                if str(metadata.get("domain") or metadata.get("corpus_type") or "").strip()
            }
        )
        source_files = sorted(
            {
                str(metadata.get("source_file") or metadata.get("source_path") or "").strip()
                for metadata in metadata_rows
                if str(metadata.get("source_file") or metadata.get("source_path") or "").strip()
            }
        )
        page_values = []
        for metadata in metadata_rows:
            for key in ("page_start", "page_end"):
                try:
                    if metadata.get(key) is not None:
                        page_values.append(int(metadata[key]))
                except (TypeError, ValueError):
                    continue
        sample_chunks = []
        for chunk in chunks[: max(1, min(limit, 25))]:
            metadata = chunk.metadata if isinstance(chunk.metadata, dict) else {}
            text = chunk.text
            if len(text) > 900:
                text = text[:900].rstrip() + "\n...TRUNCATED_RAG_CHUNK..."
            sample_chunks.append(
                {
                    "chunk_id": chunk.id,
                    "citation_id": self._rag_chunk_citation_id(chunk),
                    "title": chunk.title,
                    "section": metadata.get("section"),
                    "page_start": metadata.get("page_start"),
                    "page_end": metadata.get("page_end"),
                    "chunk_index": chunk.chunk_index,
                    "text": text,
                }
            )
        return {
            "ok": True,
            "doc_id": clean,
            "chunk_count": total,
            "returned_chunks": len(chunks),
            "title": first.get("title") or first.get("source_file") or chunks[0].title,
            "source_file": source_files[0] if source_files else first.get("source_file"),
            "source_files": source_files,
            "source_sha256": chunks[0].source_sha256,
            "source_type": first.get("source_type"),
            "domains": domains,
            "profile": first.get("profile") if isinstance(first.get("profile"), dict) else {},
            "sections": sections[:200],
            "page_start": min(page_values) if page_values else None,
            "page_end": max(page_values) if page_values else None,
            "sample_chunks": sample_chunks,
        }
