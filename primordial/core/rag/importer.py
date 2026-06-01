from __future__ import annotations

import hashlib
import json
from pathlib import Path

from primordial.core.rag.embeddings import EmbeddingProvider
from primordial.core.rag.import_validation import RagImportRecordValidator
from primordial.core.rag.importer_embeddings import RagImporterEmbeddingMixin
from primordial.core.rag.importer_metadata import RagImporterMetadataMixin
from primordial.core.rag.importer_types import CORPUS_TARGET_HANDLE, RagImportOptions, RagImportSummary
from primordial.core.storage.runtime import RuntimeStore

__all__ = [
    "CORPUS_TARGET_HANDLE",
    "RagChunkImporter",
    "RagImportOptions",
    "RagImportSummary",
]


class RagChunkImporter(RagImporterEmbeddingMixin, RagImporterMetadataMixin):
    def __init__(
        self,
        store: RuntimeStore,
        embedding_provider: EmbeddingProvider,
        *,
        batch_size: int = 16,
    ) -> None:
        self.store = store
        self.embedding_provider = embedding_provider
        self.batch_size = max(1, int(batch_size))
        self._record_validator = RagImportRecordValidator()

    def import_chunks(self, options: RagImportOptions) -> RagImportSummary:
        summary = RagImportSummary(
            dry_run=options.dry_run,
            embedding_model=self.embedding_provider.model_name,
            embedding_provider=self.embedding_provider.provider_name,
        )
        files = self._chunk_files(options.chunks_dir)
        summary.files_seen = len(files)
        embedding_ready = self._embedding_ready(options, summary)
        corpus_target = None if options.dry_run else self._ensure_corpus_target()
        pending_embeddings = []
        for path in files:
            self._import_file(path, options, summary, corpus_target=corpus_target, embedding_ready=embedding_ready, pending_embeddings=pending_embeddings)
            if options.limit is not None and summary.records_seen >= options.limit:
                break
        if pending_embeddings:
            self._flush_embeddings(pending_embeddings, options, summary)
        return summary

    def _embedding_ready(self, options: RagImportOptions, summary: RagImportSummary) -> bool:
        if options.skip_embeddings or options.dry_run:
            return True
        try:
            self.embedding_provider.assert_ready()
            return True
        except Exception as exc:  # noqa: BLE001 - importer must still preserve chunks
            summary.failures += 1
            summary.errors.append(f"embedding provider not ready: {exc}")
            return False

    def _import_file(
        self,
        path: Path,
        options: RagImportOptions,
        summary: RagImportSummary,
        *,
        corpus_target: object | None,
        embedding_ready: bool,
        pending_embeddings: list[tuple[object, str]],
    ) -> None:
        for line_number, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            if options.limit is not None and summary.records_seen >= options.limit:
                break
            if not raw.strip():
                continue
            summary.records_seen += 1
            self._import_record(
                raw,
                path=path,
                line_number=line_number,
                options=options,
                summary=summary,
                corpus_target=corpus_target,
                embedding_ready=embedding_ready,
                pending_embeddings=pending_embeddings,
            )

    def _import_record(
        self,
        raw: str,
        *,
        path: Path,
        line_number: int,
        options: RagImportOptions,
        summary: RagImportSummary,
        corpus_target: object | None,
        embedding_ready: bool,
        pending_embeddings: list[tuple[object, str]],
    ) -> None:
        try:
            record = self._load_record(raw)
            if not self._record_matches_filters(record, options):
                summary.chunks_skipped += 1
                return
            domain = self._domain(record)
            metadata = self._metadata(record, domain=domain)
            self._record_validator.validate_rag_index_record(record, domain=domain, metadata=metadata)
            chunk = self._chunk_from_record(record, target_id=corpus_target.id if corpus_target else "dry_run")
            content_hash = self._content_hash(chunk.text)
            if options.dry_run:
                summary.chunks_skipped += 1
                return
            self._store_chunk_record(record, chunk, target_id=corpus_target.id, options=options, summary=summary)
            if not options.skip_embeddings and embedding_ready:
                self._queue_embedding(chunk, content_hash, options, summary, pending_embeddings)
        except Exception as exc:  # noqa: BLE001 - one bad row should not abort the import
            summary.failures += 1
            record_id = self._best_record_id(raw)
            summary.failed_record_ids.append(record_id)
            summary.errors.append(f"{path}:{line_number}: {exc}")

    def _load_record(self, raw: str) -> dict[str, object]:
        record = json.loads(raw)
        if not isinstance(record, dict):
            raise ValueError("JSONL row is not an object")
        if bool(self._record_value(record, "policy_blocked")):
            raise ValueError("policy-blocked chunk must not be imported")
        return record

    def _store_chunk_record(self, record: dict[str, object], chunk: object, *, target_id: str, options: RagImportOptions, summary: RagImportSummary) -> None:
        artifact = self._artifact_for_record(record, target_id=target_id)
        chunk.source_artifact_id = artifact.id
        before = self.store.get_document_chunk(chunk.id)
        self.store.insert_artifact(artifact)
        self.store.insert_document_chunk(chunk)
        if before is None:
            summary.chunks_inserted += 1
        elif options.force or before.text != chunk.text or before.metadata != chunk.metadata:
            summary.chunks_updated += 1
        else:
            summary.chunks_skipped += 1

    def _queue_embedding(
        self,
        chunk: object,
        content_hash: str,
        options: RagImportOptions,
        summary: RagImportSummary,
        pending_embeddings: list[tuple[object, str]],
    ) -> None:
        pending_embeddings.append((chunk, content_hash))
        if len(pending_embeddings) >= self.batch_size:
            self._flush_embeddings(pending_embeddings, options, summary)
            pending_embeddings.clear()

    def _chunk_files(self, chunks_dir: Path) -> list[Path]:
        root = Path(chunks_dir)
        canonical = root / "chunks.jsonl"
        if canonical.exists():
            return [canonical]
        return sorted(path for path in root.glob("*.jsonl") if path.is_file())

    def _content_hash(self, text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()
