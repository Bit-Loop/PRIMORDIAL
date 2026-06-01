from __future__ import annotations

import hashlib
from pathlib import Path
import re
from typing import Any

from primordial.core.context.normalization import (
    RAG_CORPUS_ALIASES,
    RAG_CORPUS_TYPES,
    RAG_LEGACY_CORPUS_TYPES,
    normalized_context_key,
)
from primordial.core.domain.enums import EvidenceType, VerificationStatus
from primordial.core.domain.models import EvidenceRecord, RecordEmbedding, Target, utc_now
from primordial.core.rag.document_retrieval import DocumentRetrievalMixin
from primordial.core.rag.document_sources import DocumentSourceMixin
from primordial.core.rag.document_types import DocumentIngestionError, IngestedArtifacts, StoredChunks
from primordial.core.rag.embeddings import DeterministicHashEmbeddingProvider, EmbeddingProvider
from primordial.core.storage.runtime import RuntimeStore


class DocumentIngestionService(DocumentRetrievalMixin, DocumentSourceMixin):
    LEGACY_CORPUS_TYPES = set(RAG_LEGACY_CORPUS_TYPES)
    CORPUS_TYPES = set(RAG_CORPUS_TYPES)
    CORPUS_ALIASES = dict(RAG_CORPUS_ALIASES)
    HINT_POLICIES = {"advisory", "direct_task_hints", "disabled"}
    TEXT_SUFFIXES = {".md", ".markdown", ".txt", ".text", ".qmd", ".rmd", ".json", ".yaml", ".yml", ".csv", ".log"}
    RICH_SUFFIXES = {
        ".pdf",
        ".docx",
        ".pptx",
        ".xlsx",
        ".html",
        ".htm",
        ".xml",
        ".tex",
        ".latex",
        ".wav",
        ".mp3",
        ".webvtt",
        ".vtt",
        ".png",
        ".jpg",
        ".jpeg",
        ".tif",
        ".tiff",
        ".bmp",
        ".webp",
    }
    MAX_FILE_BYTES = 25 * 1024 * 1024
    MAX_CHUNK_CHARS = 1800

    _SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
        ("authorization_bearer", re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[A-Za-z0-9._~+/\-]+=*"), r"\1<redacted>"),
        (
            "key_value_secret",
            re.compile(r"(?i)\b(password|passwd|pwd|api[_-]?key|secret|token|access[_-]?key)\b(\s*[:=]\s*)([^\s`\"']+)"),
            r"\1\2<redacted>",
        ),
        ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "<redacted-aws-access-key>"),
        ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL), "<redacted-private-key>"),
    )

    def __init__(
        self,
        store: RuntimeStore,
        artifacts_dir: Path,
        *,
        embedding_provider: EmbeddingProvider | None = None,
        max_file_bytes: int = MAX_FILE_BYTES,
    ) -> None:
        self.store = store
        self.artifacts_dir = Path(artifacts_dir)
        self.embedding_provider = embedding_provider or DeterministicHashEmbeddingProvider()
        self.max_file_bytes = max_file_bytes

    def ingest_path(
        self,
        path: Path | str,
        *,
        target: Target,
        task_id: str | None = None,
        use_docling: bool = True,
        embed: bool = True,
        corpus_type: str = "operator_note",
        source_trust: str | None = None,
        hint_policy: str | None = None,
        allow_remote_url: bool = False,
    ) -> dict[str, Any]:
        if not target.in_scope:
            raise DocumentIngestionError(f"target {target.handle} is out of scope")
        artifacts = self._ingest_artifacts(
            path,
            target=target,
            task_id=task_id,
            use_docling=use_docling,
            corpus_type=corpus_type,
            source_trust=source_trust,
            hint_policy=hint_policy,
            allow_remote_url=allow_remote_url,
        )
        evidence, evidence_refs = self._record_ingest_evidence(artifacts, target=target, task_id=task_id)
        stored = self._store_ingest_chunks(artifacts, target=target, evidence_refs=evidence_refs, embed=embed)
        if evidence is not None:
            self._update_ingest_evidence(evidence, artifacts=artifacts, target=target, stored=stored)
        return self._ingest_payload(artifacts, target=target, evidence=evidence, stored=stored, embed=embed)

    def _ingest_artifacts(
        self,
        path: Path | str,
        *,
        target: Target,
        task_id: str | None,
        use_docling: bool,
        corpus_type: str,
        source_trust: str | None,
        hint_policy: str | None,
        allow_remote_url: bool,
    ) -> IngestedArtifacts:
        normalized, raw_corpus_type, corpus_warning = self._corpus_metadata_values(corpus_type)
        hint_policy = self._normalize_hint_policy(hint_policy, corpus_type=normalized)
        source_trust = self._normalize_source_trust(source_trust, corpus_type=normalized)
        source = self._prepare_source(path, target=target, allow_remote_url=allow_remote_url)
        generated_export_reason = self._generated_export_block_reason(source.path)
        if generated_export_reason:
            raise DocumentIngestionError(generated_export_reason)
        converted = self._convert_document(source.path, use_docling=use_docling)
        redacted_markdown = self._redact(converted["markdown"])
        redacted_json = self._redact(converted["json"]) if converted.get("json") else None
        metadata = self._corpus_metadata(source, converted, normalized, raw_corpus_type, corpus_warning, source_trust, hint_policy, redacted_markdown)
        markdown, json_artifact = self._persist_ingest_artifacts(source, converted, redacted_markdown, redacted_json, target=target, task_id=task_id, metadata=metadata)
        return IngestedArtifacts(markdown, json_artifact, source, converted, redacted_markdown, redacted_json, metadata)

    def _corpus_metadata_values(self, corpus_type: str) -> tuple[str, str, str | None]:
        raw_corpus_type = normalized_context_key(corpus_type or "operator_note")
        normalized = self._normalize_corpus_type(corpus_type)
        warning = (
            f"unknown corpus type {raw_corpus_type!r} mapped to general_security"
            if raw_corpus_type not in self.CORPUS_TYPES and raw_corpus_type not in self.CORPUS_ALIASES
            else None
        )
        return normalized, raw_corpus_type, warning

    def _corpus_metadata(
        self,
        source: object,
        converted: dict[str, str],
        corpus_type: str,
        raw_corpus_type: str,
        corpus_warning: str | None,
        source_trust: str,
        hint_policy: str,
        redacted_markdown: object,
    ) -> dict[str, Any]:
        return {
            "corpus_type": corpus_type,
            "original_corpus_type": raw_corpus_type,
            "corpus_type_warning": corpus_warning,
            "source_trust": source_trust,
            "hint_policy": hint_policy,
            "source_ref": source.source_ref,
            "source_url": source.source_url,
            "source_name": source.name,
            "source_sha256": source.sha256,
            "converter": converted["converter"],
            "docling_used": converted["converter"] == "docling",
            "cve_ids": self._extract_cve_ids(redacted_markdown.text),
            "walkthrough_hint": corpus_type == "htb_writeup",
            "rag_advisory_only": corpus_type != "operator_note",
        }

    def _persist_ingest_artifacts(
        self,
        source: object,
        converted: dict[str, str],
        redacted_markdown: object,
        redacted_json: object | None,
        *,
        target: Target,
        task_id: str | None,
        metadata: dict[str, Any],
    ) -> tuple[object, object | None]:
        stem = self._safe_fragment(source.path.stem) or "document"
        artifact_root = self.artifacts_dir / "rag" / self._safe_fragment(target.handle) / f"{stem}-{source.sha256[:12]}"
        markdown = self._persist_artifact(
            artifact_root / "document.md",
            redacted_markdown.text.rstrip() + "\n",
            target_id=target.id,
            task_id=task_id,
            metadata={**metadata, "rag_role": "converted_markdown", "source_path": str(source.path), "redaction_count": redacted_markdown.count, "redaction_labels": redacted_markdown.labels},
        )
        json_artifact = None
        if redacted_json is not None:
            json_artifact = self._persist_artifact(
                artifact_root / "docling.json",
                redacted_json.text.rstrip() + "\n",
                target_id=target.id,
                task_id=task_id,
                metadata={**metadata, "rag_role": "docling_json", "source_path": str(source.path), "redaction_count": redacted_json.count, "redaction_labels": redacted_json.labels},
            )
        return markdown, json_artifact

    def _record_ingest_evidence(self, artifacts: IngestedArtifacts, *, target: Target, task_id: str | None) -> tuple[EvidenceRecord | None, list[str]]:
        if not self._corpus_creates_evidence(str(artifacts.corpus_metadata["corpus_type"])):
            return None, []
        evidence = EvidenceRecord(
            target_id=target.id,
            task_id=task_id,
            type=EvidenceType.DOCUMENT_IMPORT,
            title=f"Imported document: {artifacts.source.name}",
            summary=f"Imported {artifacts.source.name} for target {target.handle}; converter={artifacts.converted['converter']} chunks pending.",
            source_ref=artifacts.source.source_ref,
            verification_status=VerificationStatus.PARTIAL,
            confidence=0.75,
            freshness=0.9,
            artifact_path=artifacts.markdown.path,
            metadata=self._evidence_metadata(artifacts),
        )
        self.store.insert_evidence(evidence)
        return evidence, [evidence.id]

    def _evidence_metadata(self, artifacts: IngestedArtifacts) -> dict[str, Any]:
        redacted_json_count = artifacts.redacted_json.count if artifacts.redacted_json else 0
        return {
            "artifact_id": artifacts.markdown.id,
            "json_artifact_id": artifacts.json_artifact.id if artifacts.json_artifact else None,
            "source_size_bytes": artifacts.source.path.stat().st_size,
            **artifacts.corpus_metadata,
            "redaction_count": artifacts.redacted_markdown.count + redacted_json_count,
        }

    def _store_ingest_chunks(self, artifacts: IngestedArtifacts, *, target: Target, evidence_refs: list[str], embed: bool) -> StoredChunks:
        chunks = self._build_chunks(
            artifacts.redacted_markdown.text,
            title=artifacts.source.name,
            target_id=target.id,
            source_artifact_id=artifacts.markdown.id,
            source_sha256=artifacts.source.sha256,
            evidence_refs=evidence_refs,
            metadata={**artifacts.corpus_metadata, "source_artifact_path": artifacts.markdown.path, "redaction_count": artifacts.redacted_markdown.count},
        )
        embeddings_created = 0
        for chunk in chunks:
            self.store.insert_document_chunk(chunk)
            if embed:
                self._insert_chunk_embedding(chunk, artifacts.markdown.id, artifacts.source.sha256)
                embeddings_created += 1
        return StoredChunks(chunks=chunks, embeddings_created=embeddings_created)

    def _insert_chunk_embedding(self, chunk: object, source_artifact_id: str, source_sha256: str) -> None:
        vector = self.embedding_provider.embed(chunk.text)
        self.store.insert_record_embedding(
            RecordEmbedding(
                target_id=chunk.target_id,
                record_type="document_chunk",
                record_id=chunk.id,
                embedding_model=self.embedding_provider.model_name,
                embedding_dim=len(vector),
                embedding=vector,
                metadata={
                    "source_artifact_id": source_artifact_id,
                    "source_sha256": source_sha256,
                    "provider": self.embedding_provider.provider_name,
                    "embedding_provider": self.embedding_provider.provider_name,
                    "embedding_dimension": len(vector),
                    "chunk_content_hash": hashlib.sha256(chunk.text.encode("utf-8")).hexdigest(),
                },
            )
        )

    def _update_ingest_evidence(self, evidence: EvidenceRecord, *, artifacts: IngestedArtifacts, target: Target, stored: StoredChunks) -> None:
        evidence.summary = (
            f"Imported {artifacts.source.name} for target {target.handle}; "
            f"converter={artifacts.converted['converter']} chunks={len(stored.chunks)} embeddings={stored.embeddings_created}."
        )
        self.store.insert_evidence(evidence)

    def _ingest_payload(
        self,
        artifacts: IngestedArtifacts,
        *,
        target: Target,
        evidence: EvidenceRecord | None,
        stored: StoredChunks,
        embed: bool,
    ) -> dict[str, Any]:
        redacted_json_count = artifacts.redacted_json.count if artifacts.redacted_json else 0
        return {
            "target": target.as_payload(),
            "source_path": str(artifacts.source.path),
            "source_ref": artifacts.source.source_ref,
            "source_url": artifacts.source.source_url,
            "source_sha256": artifacts.source.sha256,
            "corpus_type": artifacts.corpus_metadata["corpus_type"],
            "source_trust": artifacts.corpus_metadata["source_trust"],
            "hint_policy": artifacts.corpus_metadata["hint_policy"],
            "cve_ids": artifacts.corpus_metadata["cve_ids"],
            "converter": artifacts.converted["converter"],
            "docling_used": artifacts.converted["converter"] == "docling",
            "artifacts": [artifacts.markdown.as_payload()] + ([artifacts.json_artifact.as_payload()] if artifacts.json_artifact else []),
            "evidence": evidence.as_payload() if evidence else None,
            "chunks": [chunk.as_payload() for chunk in stored.chunks],
            "chunk_count": len(stored.chunks),
            "embedding_model": self.embedding_provider.model_name if embed else None,
            "embedding_count": stored.embeddings_created,
            "redaction_count": artifacts.redacted_markdown.count + redacted_json_count,
        }
