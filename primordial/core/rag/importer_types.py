from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CORPUS_TARGET_HANDLE = "__rag_corpus__"


@dataclass(slots=True)
class RagImportOptions:
    chunks_dir: Path
    dry_run: bool = False
    force: bool = False
    reembed: bool = False
    skip_embeddings: bool = False
    domains: set[str] = field(default_factory=set)
    source_files: set[str] = field(default_factory=set)
    doc_ids: set[str] = field(default_factory=set)
    limit: int | None = None


@dataclass(slots=True)
class RagImportSummary:
    files_seen: int = 0
    records_seen: int = 0
    chunks_inserted: int = 0
    chunks_updated: int = 0
    chunks_skipped: int = 0
    embeddings_inserted: int = 0
    embeddings_updated: int = 0
    embeddings_skipped: int = 0
    failures: int = 0
    failed_record_ids: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    dry_run: bool = False
    embedding_model: str | None = None
    embedding_provider: str | None = None

    def as_payload(self) -> dict[str, Any]:
        return {
            "files_seen": self.files_seen,
            "records_seen": self.records_seen,
            "chunks_inserted": self.chunks_inserted,
            "chunks_updated": self.chunks_updated,
            "chunks_skipped": self.chunks_skipped,
            "embeddings_inserted": self.embeddings_inserted,
            "embeddings_updated": self.embeddings_updated,
            "embeddings_skipped": self.embeddings_skipped,
            "failures": self.failures,
            "failed_record_ids": list(self.failed_record_ids),
            "errors": list(self.errors),
            "dry_run": self.dry_run,
            "embedding_model": self.embedding_model,
            "embedding_provider": self.embedding_provider,
        }
