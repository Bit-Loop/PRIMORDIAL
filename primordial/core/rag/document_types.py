from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from primordial.core.context.normalization import metadata_value
from primordial.core.domain.models import DocumentChunk


class DocumentIngestionError(RuntimeError):
    pass


@dataclass(slots=True)
class RedactionResult:
    text: str
    count: int
    labels: list[str] = field(default_factory=list)


@dataclass(slots=True)
class SourceDocument:
    path: Path
    name: str
    sha256: str
    source_ref: str
    source_url: str | None = None


@dataclass(slots=True)
class IngestedArtifacts:
    markdown: object
    json_artifact: object | None
    source: SourceDocument
    converted: dict[str, str]
    redacted_markdown: RedactionResult
    redacted_json: RedactionResult | None
    corpus_metadata: dict[str, Any]


@dataclass(slots=True)
class StoredChunks:
    chunks: list[DocumentChunk]
    embeddings_created: int


@dataclass(slots=True)
class RagContextItem:
    chunk: DocumentChunk
    score: float
    source: str
    matched_terms: list[str] = field(default_factory=list)

    def as_payload(self, *, max_chars: int = 1200) -> dict[str, Any]:
        text = self.chunk.text
        if len(text) > max_chars:
            text = text[:max_chars].rstrip() + "\n...TRUNCATED_RAG_CHUNK..."
        citation_id = str(metadata_value(self.chunk.metadata, "citation_id") or "").strip()
        if not citation_id or citation_id in {"rag:None", "rag:null", "rag:unknown"}:
            citation_id = f"rag:{self.chunk.id}"
        return {
            "chunk_id": self.chunk.id,
            "citation_id": citation_id if citation_id.startswith("rag:") else f"rag:{citation_id}",
            "target_id": self.chunk.target_id,
            "source_artifact_id": self.chunk.source_artifact_id,
            "source_sha256": self.chunk.source_sha256,
            "chunk_index": self.chunk.chunk_index,
            "title": self.chunk.title,
            "text": text,
            "evidence_refs": list(self.chunk.evidence_refs),
            "score": self.score,
            "retrieval_source": self.source,
            "matched_terms": self.matched_terms,
            "metadata": dict(self.chunk.metadata),
        }
