from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from primordial.core.domain.enums import ArtifactKind, ScopeProfile
from primordial.core.domain.models import ArtifactRecord, DocumentChunk, RecordEmbedding, Target
from primordial.core.rag.documents import DocumentIngestionService
from primordial.core.rag.embeddings import EmbeddingProvider
from primordial.core.storage.runtime import RuntimeStore


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


class RagChunkImporter:
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

    def import_chunks(self, options: RagImportOptions) -> RagImportSummary:
        summary = RagImportSummary(
            dry_run=options.dry_run,
            embedding_model=self.embedding_provider.model_name,
            embedding_provider=self.embedding_provider.provider_name,
        )
        files = self._chunk_files(options.chunks_dir)
        summary.files_seen = len(files)
        embedding_ready = options.skip_embeddings or options.dry_run
        if not embedding_ready:
            try:
                self.embedding_provider.assert_ready()
                embedding_ready = True
            except Exception as exc:  # noqa: BLE001 - importer must still preserve chunks
                summary.failures += 1
                summary.errors.append(f"embedding provider not ready: {exc}")

        corpus_target = None if options.dry_run else self._ensure_corpus_target()
        pending_embeddings: list[tuple[DocumentChunk, str]] = []
        for path in files:
            for line_number, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
                if options.limit is not None and summary.records_seen >= options.limit:
                    break
                if not raw.strip():
                    continue
                summary.records_seen += 1
                try:
                    record = json.loads(raw)
                    if not isinstance(record, dict):
                        raise ValueError("JSONL row is not an object")
                    if bool(record.get("policy_blocked")):
                        raise ValueError("policy-blocked chunk must not be imported")
                    if not self._record_matches_filters(record, options):
                        summary.chunks_skipped += 1
                        continue
                    chunk = self._chunk_from_record(record, target_id=corpus_target.id if corpus_target else "dry_run")
                    content_hash = self._content_hash(chunk.text)
                    if options.dry_run:
                        summary.chunks_skipped += 1
                        continue
                    artifact = self._artifact_for_record(record, target_id=corpus_target.id)
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
                    if not options.skip_embeddings and embedding_ready:
                        pending_embeddings.append((chunk, content_hash))
                        if len(pending_embeddings) >= self.batch_size:
                            self._flush_embeddings(pending_embeddings, options, summary)
                            pending_embeddings.clear()
                except Exception as exc:  # noqa: BLE001 - one bad row should not abort the import
                    summary.failures += 1
                    record_id = self._best_record_id(raw)
                    summary.failed_record_ids.append(record_id)
                    summary.errors.append(f"{path}:{line_number}: {exc}")
            if options.limit is not None and summary.records_seen >= options.limit:
                break
        if pending_embeddings:
            self._flush_embeddings(pending_embeddings, options, summary)
        return summary

    def _flush_embeddings(
        self,
        items: list[tuple[DocumentChunk, str]],
        options: RagImportOptions,
        summary: RagImportSummary,
    ) -> None:
        to_embed: list[tuple[DocumentChunk, str]] = []
        for chunk, content_hash in items:
            existing = self.store.get_record_embedding(
                record_type="document_chunk",
                record_id=chunk.id,
                embedding_model=self.embedding_provider.model_name,
            )
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
        if not to_embed:
            return
        try:
            vectors = self.embedding_provider.embed_batch([chunk.text for chunk, _hash in to_embed])
        except Exception as exc:  # noqa: BLE001
            summary.errors.append(f"embedding batch failed; retrying per chunk: {exc}")
            self._flush_embeddings_individually(to_embed, summary)
            return
        for (chunk, content_hash), vector in zip(to_embed, vectors, strict=True):
            existing = self.store.get_record_embedding(
                record_type="document_chunk",
                record_id=chunk.id,
                embedding_model=self.embedding_provider.model_name,
            )
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
            if existing is None:
                summary.embeddings_inserted += 1
            else:
                summary.embeddings_updated += 1

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
            existing = self.store.get_record_embedding(
                record_type="document_chunk",
                record_id=chunk.id,
                embedding_model=self.embedding_provider.model_name,
            )
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
            if existing is None:
                summary.embeddings_inserted += 1
            else:
                summary.embeddings_updated += 1

    def _chunk_files(self, chunks_dir: Path) -> list[Path]:
        root = Path(chunks_dir)
        canonical = root / "chunks.jsonl"
        if canonical.exists():
            return [canonical]
        return sorted(path for path in root.glob("*.jsonl") if path.is_file())

    def _record_matches_filters(self, record: dict[str, Any], options: RagImportOptions) -> bool:
        domain = self._domain(record)
        source_file = str(record.get("source_file") or "")
        doc_id = str(record.get("doc_id") or record.get("source_id") or "")
        if options.domains and domain not in options.domains:
            return False
        if options.source_files and source_file not in options.source_files:
            return False
        return not (options.doc_ids and doc_id not in options.doc_ids)

    def _chunk_from_record(self, record: dict[str, Any], *, target_id: str) -> DocumentChunk:
        text = str(record.get("retrieval_text") or record.get("text") or "").strip()
        if not text:
            raise ValueError("chunk has no retrieval_text/text")
        source_sha256 = str(record.get("source_sha256") or "").strip()
        if not source_sha256:
            raise ValueError("chunk is missing source_sha256")
        chunk_index = self._int(record.get("chunk_index"), 0)
        chunk_id = str(record.get("chunk_id") or "").strip() or self._derive_chunk_id(record, text, chunk_index)
        domain = self._domain(record)
        metadata = self._metadata(record, domain=domain)
        return DocumentChunk(
            id=chunk_id,
            target_id=target_id,
            source_artifact_id="pending",
            source_sha256=source_sha256,
            chunk_index=chunk_index,
            title=str(record.get("title") or record.get("section") or record.get("source_file") or chunk_id),
            text=text,
            token_count=self._int(record.get("token_estimate"), max(1, len(re.findall(r"\S+", text)))),
            evidence_refs=[],
            metadata=metadata,
        )

    def _metadata(self, record: dict[str, Any], *, domain: str) -> dict[str, Any]:
        nested = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
        raw_text = str(record.get("raw_text") or "")
        metadata = {
            **nested,
            "import_source": "primordial-rag-preprocess",
            "citation_id": f"rag:{record.get('chunk_id')}",
            "doc_id": record.get("doc_id") or record.get("source_id"),
            "source_file": record.get("source_file"),
            "source_path": record.get("source_path"),
            "source_type": record.get("source_type"),
            "domain": domain,
            "original_domain": record.get("domain"),
            "secondary_domains": record.get("secondary_domains") if isinstance(record.get("secondary_domains"), list) else [],
            "corpus_type": domain,
            "authority_level": record.get("authority_level"),
            "chunk_type": record.get("chunk_type"),
            "section": record.get("section"),
            "section_path": record.get("section_path") if isinstance(record.get("section_path"), list) else [],
            "page_start": record.get("page_start"),
            "page_end": record.get("page_end"),
            "risk_level": record.get("risk_level"),
            "planner_visibility": record.get("planner_visibility") or ("taxonomy_only" if domain == "mitre_attack" else "normal"),
            "requires_authorized_scope": bool(record.get("requires_authorized_scope", True)),
            "scope_gate_required": bool(record.get("scope_gate_required", True)),
            "requires_operator_approval": bool(record.get("requires_operator_approval", False)),
            "allowed_use_modes": record.get("allowed_use_modes") if isinstance(record.get("allowed_use_modes"), list) else [],
            "allowed_contexts": record.get("allowed_contexts") if isinstance(record.get("allowed_contexts"), list) else [],
            "license_status": record.get("license_status"),
            "raw_text": raw_text,
            "raw_text_sha256": hashlib.sha256(raw_text.encode("utf-8")).hexdigest() if raw_text else "",
            "source_sha256": record.get("source_sha256"),
        }
        for key in (
            "vuln_id",
            "cve_id",
            "ghsa_ids",
            "osv_ids",
            "aliases",
            "alias",
            "cwe",
            "cwe_ids",
            "cvss",
            "cvss_severity",
            "kev",
            "epss_probability",
            "epss_percentile",
            "affected_vendors",
            "affected_products",
            "affected_packages",
            "affected_versions",
            "fixed_versions",
            "fixed_version_known",
            "package",
            "ecosystem",
            "cpe",
            "purl",
            "source_kind",
            "source_priority",
            "card_type",
            "output_mode",
            "blocked_output_modes",
            "safety_level",
            "content_hash",
            "embedding_policy",
            "source_refs",
        ):
            if key in record:
                metadata[key] = record[key]
            elif key in nested:
                metadata[key] = nested[key]
        if domain == "mitre_attack":
            metadata["planner_visibility"] = "taxonomy_only"
            metadata["allowed_uses"] = [
                "behavior_classification",
                "framework_mapping",
                "reporting",
                "detection_engineering",
                "mitigation_alignment",
            ]
            metadata["prohibited_uses"] = [
                "action_selection",
                "scope_expansion",
                "exploit_selection",
                "tool_execution",
                "persistence_or_evasion_workflows",
            ]
        return metadata

    def _artifact_for_record(self, record: dict[str, Any], *, target_id: str) -> ArtifactRecord:
        source_sha256 = str(record.get("source_sha256") or "missing")
        doc_id = str(record.get("doc_id") or record.get("source_id") or source_sha256[:20])
        digest = hashlib.sha256(f"{source_sha256}:{doc_id}".encode("utf-8")).hexdigest()[:20]
        return ArtifactRecord(
            id=f"artifact_rag_{digest}",
            task_id=None,
            target_id=target_id,
            kind=ArtifactKind.RAG_DOCUMENT,
            path=f"rag-preprocess:{record.get('source_file') or doc_id}",
            sha256=source_sha256,
            size_bytes=0,
            metadata={
                "import_source": "primordial-rag-preprocess",
                "doc_id": doc_id,
                "source_file": record.get("source_file"),
                "source_path": record.get("source_path"),
                "domain": self._domain(record),
            },
        )

    def _ensure_corpus_target(self) -> Target:
        existing = self.store.get_target_by_handle(CORPUS_TARGET_HANDLE, ScopeProfile.CORPUS)
        if existing is not None:
            return existing
        target = Target(
            id="target_rag_corpus",
            handle=CORPUS_TARGET_HANDLE,
            display_name="RAG Corpus",
            profile=ScopeProfile.CORPUS,
            in_scope=False,
            metadata={"system_target": True, "purpose": "rag_corpus"},
        )
        self.store.insert_target(target)
        return target

    def _domain(self, record: dict[str, Any]) -> str:
        corpus_type = record.get("corpus_type")
        if isinstance(corpus_type, list) and corpus_type:
            value = str(corpus_type[0])
        else:
            value = str(corpus_type or record.get("domain") or "general_security")
        normalized = value.strip().lower().replace("-", "_")
        return DocumentIngestionService.CORPUS_ALIASES.get(
            normalized,
            {
                "api_web": "api_security",
                "kubernetes_cloud": "kubernetes_cloud",
                "methodology_standards": "methodology_standards",
                "mitre_attack": "mitre_attack",
                "systems_exploitation": "binary_exploitation",
                "vulnerability_intel": "vuln_intel",
                "vuln_intel": "vuln_intel",
            }.get(normalized, normalized if normalized in DocumentIngestionService.CORPUS_TYPES else "general_security"),
        )

    def _derive_chunk_id(self, record: dict[str, Any], text: str, chunk_index: int) -> str:
        digest = hashlib.sha256(
            f"{record.get('source_sha256')}:{record.get('doc_id') or record.get('source_id')}:{chunk_index}:{self._content_hash(text)}".encode(
                "utf-8"
            )
        ).hexdigest()[:24]
        return f"chunk_{digest}"

    def _content_hash(self, text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def _best_record_id(self, raw: str) -> str:
        try:
            data = json.loads(raw)
        except Exception:
            return "invalid_json"
        if not isinstance(data, dict):
            return "invalid_record"
        return str(data.get("chunk_id") or data.get("record_id") or data.get("doc_id") or "unknown")

    def _int(self, value: object, default: int) -> int:
        if isinstance(value, bool):
            return default
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if isinstance(value, str) and value.strip().isdigit():
            return int(value.strip())
        return default
