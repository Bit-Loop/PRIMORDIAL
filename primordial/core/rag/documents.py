from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re
from typing import Any
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from primordial.core.domain.enums import ArtifactKind, EvidenceType, VerificationStatus
from primordial.core.domain.models import (
    ArtifactRecord,
    DocumentChunk,
    EvidenceRecord,
    RecordEmbedding,
    Target,
    utc_now,
)
from primordial.core.context.generated_exports import is_generated_export_path
from primordial.core.context.normalization import (
    RAG_CORPUS_ALIASES,
    RAG_CORPUS_TYPES,
    RAG_LEGACY_CORPUS_TYPES,
    canonical_rag_domain,
    metadata_value,
    normalized_context_key,
)
from primordial.core.rag.embeddings import DeterministicHashEmbeddingProvider, EmbeddingProvider
from primordial.core.storage.runtime import RuntimeStore


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


class DocumentIngestionService:
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
        (
            "authorization_bearer",
            re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[A-Za-z0-9._~+/\-]+=*"),
            r"\1<redacted>",
        ),
        (
            "key_value_secret",
            re.compile(
                r"(?i)\b(password|passwd|pwd|api[_-]?key|secret|token|access[_-]?key)\b(\s*[:=]\s*)([^\s`\"']+)"
            ),
            r"\1\2<redacted>",
        ),
        (
            "aws_access_key",
            re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
            "<redacted-aws-access-key>",
        ),
        (
            "private_key_block",
            re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
            "<redacted-private-key>",
        ),
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
        raw_corpus_type = normalized_context_key(corpus_type or "operator_note")
        corpus_type = self._normalize_corpus_type(corpus_type)
        corpus_warning = (
            f"unknown corpus type {raw_corpus_type!r} mapped to general_security"
            if raw_corpus_type not in self.CORPUS_TYPES and raw_corpus_type not in self.CORPUS_ALIASES
            else None
        )
        hint_policy = self._normalize_hint_policy(hint_policy, corpus_type=corpus_type)
        source_trust = self._normalize_source_trust(source_trust, corpus_type=corpus_type)
        source = self._prepare_source(path, target=target, allow_remote_url=allow_remote_url)
        source_path = source.path
        generated_export_reason = self._generated_export_block_reason(source_path)
        if generated_export_reason:
            raise DocumentIngestionError(generated_export_reason)
        source_sha256 = source.sha256
        converted = self._convert_document(source_path, use_docling=use_docling)
        redacted_markdown = self._redact(converted["markdown"])
        redacted_json = self._redact(converted["json"]) if converted.get("json") else None
        stem = self._safe_fragment(source_path.stem) or "document"
        artifact_root = self.artifacts_dir / "rag" / self._safe_fragment(target.handle) / f"{stem}-{source_sha256[:12]}"
        artifact_root.mkdir(parents=True, exist_ok=True)
        cve_ids = self._extract_cve_ids(redacted_markdown.text)
        corpus_metadata = {
            "corpus_type": corpus_type,
            "original_corpus_type": raw_corpus_type,
            "corpus_type_warning": corpus_warning,
            "source_trust": source_trust,
            "hint_policy": hint_policy,
            "source_ref": source.source_ref,
            "source_url": source.source_url,
            "source_name": source.name,
            "source_sha256": source_sha256,
            "converter": converted["converter"],
            "docling_used": converted["converter"] == "docling",
            "cve_ids": cve_ids,
            "walkthrough_hint": corpus_type == "htb_writeup",
            "rag_advisory_only": corpus_type != "operator_note",
        }

        markdown_artifact = self._persist_artifact(
            artifact_root / "document.md",
            redacted_markdown.text.rstrip() + "\n",
            target_id=target.id,
            task_id=task_id,
            metadata={
                "rag_role": "converted_markdown",
                "source_path": str(source_path),
                **corpus_metadata,
                "redaction_count": redacted_markdown.count,
                "redaction_labels": redacted_markdown.labels,
            },
        )
        json_artifact: ArtifactRecord | None = None
        if redacted_json is not None:
            json_artifact = self._persist_artifact(
                artifact_root / "docling.json",
                redacted_json.text.rstrip() + "\n",
                target_id=target.id,
                task_id=task_id,
                metadata={
                    "rag_role": "docling_json",
                    "source_path": str(source_path),
                    **corpus_metadata,
                    "redaction_count": redacted_json.count,
                    "redaction_labels": redacted_json.labels,
                },
            )

        evidence: EvidenceRecord | None = None
        evidence_refs: list[str] = []
        if self._corpus_creates_evidence(corpus_type):
            evidence = EvidenceRecord(
                target_id=target.id,
                task_id=task_id,
                type=EvidenceType.DOCUMENT_IMPORT,
                title=f"Imported document: {source.name}",
                summary=(
                    f"Imported {source.name} for target {target.handle}; "
                    f"converter={converted['converter']} chunks pending."
                ),
                source_ref=source.source_ref,
                verification_status=VerificationStatus.PARTIAL,
                confidence=0.75,
                freshness=0.9,
                artifact_path=markdown_artifact.path,
                metadata={
                    "artifact_id": markdown_artifact.id,
                    "json_artifact_id": json_artifact.id if json_artifact else None,
                    "source_size_bytes": source_path.stat().st_size,
                    **corpus_metadata,
                    "redaction_count": redacted_markdown.count + (redacted_json.count if redacted_json else 0),
                },
            )
            self.store.insert_evidence(evidence)
            evidence_refs = [evidence.id]

        chunks = self._build_chunks(
            redacted_markdown.text,
            title=source.name,
            target_id=target.id,
            source_artifact_id=markdown_artifact.id,
            source_sha256=source_sha256,
            evidence_refs=evidence_refs,
            metadata={
                **corpus_metadata,
                "source_artifact_path": markdown_artifact.path,
                "redaction_count": redacted_markdown.count,
            },
        )
        embeddings_created = 0
        for chunk in chunks:
            self.store.insert_document_chunk(chunk)
            if embed:
                vector = self.embedding_provider.embed(chunk.text)
                self.store.insert_record_embedding(
                    RecordEmbedding(
                        target_id=target.id,
                        record_type="document_chunk",
                        record_id=chunk.id,
                        embedding_model=self.embedding_provider.model_name,
                        embedding_dim=len(vector),
                        embedding=vector,
                        metadata={
                            "source_artifact_id": markdown_artifact.id,
                            "source_sha256": source_sha256,
                            "provider": self.embedding_provider.provider_name,
                            "embedding_provider": self.embedding_provider.provider_name,
                            "embedding_dimension": len(vector),
                            "chunk_content_hash": hashlib.sha256(chunk.text.encode("utf-8")).hexdigest(),
                        },
                    )
                )
                embeddings_created += 1

        if evidence is not None:
            evidence.summary = (
                f"Imported {source.name} for target {target.handle}; "
                f"converter={converted['converter']} chunks={len(chunks)} embeddings={embeddings_created}."
            )
            self.store.insert_evidence(evidence)
        return {
            "target": target.as_payload(),
            "source_path": str(source_path),
            "source_ref": source.source_ref,
            "source_url": source.source_url,
            "source_sha256": source_sha256,
            "corpus_type": corpus_type,
            "source_trust": source_trust,
            "hint_policy": hint_policy,
            "cve_ids": cve_ids,
            "converter": converted["converter"],
            "docling_used": converted["converter"] == "docling",
            "artifacts": [markdown_artifact.as_payload()]
            + ([json_artifact.as_payload()] if json_artifact else []),
            "evidence": evidence.as_payload() if evidence else None,
            "chunks": [chunk.as_payload() for chunk in chunks],
            "chunk_count": len(chunks),
            "embedding_model": self.embedding_provider.model_name if embed else None,
            "embedding_count": embeddings_created,
            "redaction_count": redacted_markdown.count + (redacted_json.count if redacted_json else 0),
        }

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
        results = self.store.search_document_chunks_text(
            clean,
            target_id=target_id,
            metadata_filters=metadata_filters,
            limit=limit,
        )
        if results:
            context = self._filter_context_items(
                self._context_items(results, source="lexical", limit=limit * 4),
                corpus_types=normalized_corpus,
                limit=limit,
            )
            if context:
                return context
        results: list[dict[str, Any]] = []
        if use_embeddings:
            try:
                results = self.store.search_document_chunks_by_embedding(
                    self.embedding_provider.embed(clean),
                    embedding_model=self.embedding_provider.model_name,
                    target_id=target_id,
                    metadata_filters=metadata_filters,
                    limit=limit,
                )
            except Exception:
                results = []
        context = self._filter_context_items(
            self._context_items(results, source="", limit=limit * 4),
            corpus_types=normalized_corpus,
            limit=limit,
        )
        if context:
            return context
        if normalized_corpus:
            return self._rank_corpus_chunks(
                clean,
                target_id=target_id,
                corpus_types=normalized_corpus,
                filters=metadata_filters,
                limit=limit,
            )
        return []

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
            item_source = source or str(item.get("embedding_model") or "lexical")
            context.append(
                RagContextItem(
                    chunk=chunk,
                    score=float(item.get("score") or 0.0),
                    source=item_source,
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
        ranked: list[RagContextItem] = []
        for chunk in chunks:
            if str(metadata_value(chunk.metadata, "corpus_type") or "operator_note") not in corpus_types:
                continue
            chunk_terms = set(re.findall(r"[A-Za-z0-9_.:/-]+", f"{chunk.title}\n{chunk.text}".lower()))
            overlap = sorted(term for term in terms & chunk_terms if len(term) > 2)
            score = len(overlap) / max(1, len(terms)) if terms else 0.0
            if score <= 0.0 and corpus_types:
                score = 0.01
            ranked.append(RagContextItem(chunk=chunk, score=round(score, 4), source="corpus", matched_terms=overlap))
        ranked.sort(key=lambda item: (-item.score, item.chunk.created_at, item.chunk.chunk_index))
        return ranked[:limit]

    def _validate_local_file(self, path: Path | str) -> Path:
        raw = str(path).strip()
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
            raise DocumentIngestionError("RAG ingestion only accepts selected local files")
        source_path = Path(raw).expanduser().resolve()
        if not source_path.exists() or not source_path.is_file():
            raise DocumentIngestionError(f"document path is not a file: {source_path}")
        size = source_path.stat().st_size
        if size <= 0:
            raise DocumentIngestionError("document is empty")
        if size > self.max_file_bytes:
            raise DocumentIngestionError(
                f"document is too large for selected import: {size} bytes > {self.max_file_bytes} bytes"
            )
        return source_path

    def _generated_export_block_reason(self, path: Path) -> str:
        if is_generated_export_path(path):
            return "generated export files cannot be ingested into active operational RAG"
        return ""

    def _prepare_source(self, path: Path | str, *, target: Target, allow_remote_url: bool) -> SourceDocument:
        raw = str(path).strip()
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
            if not allow_remote_url:
                raise DocumentIngestionError("remote URL RAG ingestion requires explicit operator approval")
            return self._fetch_remote_source(raw, target=target)
        source_path = self._validate_local_file(path)
        source_sha256 = self._sha256_file(source_path)
        return SourceDocument(
            path=source_path,
            name=source_path.name,
            sha256=source_sha256,
            source_ref=f"file:{source_path.name}:{source_sha256}",
        )

    def _fetch_remote_source(self, url: str, *, target: Target) -> SourceDocument:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise DocumentIngestionError("remote RAG ingestion only supports http and https URLs")
        safe_url = parsed._replace(query="", fragment="").geturl()
        request = Request(url, headers={"User-Agent": "Primordial-RAG/0.1"})
        try:
            with urlopen(request, timeout=30) as response:
                body = response.read(self.max_file_bytes + 1)
                content_type = str(response.headers.get("content-type") or "")
        except URLError as exc:
            raise DocumentIngestionError(f"remote document fetch failed: {exc}") from exc
        if not body:
            raise DocumentIngestionError("remote document is empty")
        if len(body) > self.max_file_bytes:
            raise DocumentIngestionError(
                f"remote document is too large for selected import: > {self.max_file_bytes} bytes"
            )
        digest = hashlib.sha256(body).hexdigest()
        name = Path(parsed.path).name or "remote-document"
        suffix = Path(name).suffix.lower() or self._suffix_from_content_type(content_type)
        stem = self._safe_fragment(Path(name).stem or "remote-document")
        filename = f"{stem}{suffix or '.bin'}"
        cache_dir = self.artifacts_dir / "rag" / "_url_cache" / self._safe_fragment(target.handle) / digest[:12]
        cache_dir.mkdir(parents=True, exist_ok=True)
        path = cache_dir / filename
        path.write_bytes(body)
        return SourceDocument(
            path=path,
            name=name,
            sha256=digest,
            source_ref=f"url:{safe_url}:{digest}",
            source_url=safe_url,
        )

    def _suffix_from_content_type(self, content_type: str) -> str:
        normalized = content_type.split(";", 1)[0].strip().lower()
        return {
            "application/pdf": ".pdf",
            "text/html": ".html",
            "application/xhtml+xml": ".html",
            "text/plain": ".txt",
            "application/json": ".json",
            "text/markdown": ".md",
            "application/xml": ".xml",
            "text/xml": ".xml",
        }.get(normalized, "")

    def _convert_document(self, path: Path, *, use_docling: bool) -> dict[str, str]:
        suffix = path.suffix.lower()
        if suffix in self.TEXT_SUFFIXES:
            return {"converter": "plain_text", "markdown": self._read_text(path), "json": ""}
        if suffix not in self.RICH_SUFFIXES:
            raise DocumentIngestionError(f"unsupported document type for RAG ingestion: {suffix or '<none>'}")
        if not use_docling:
            raise DocumentIngestionError(f"{suffix} requires Docling conversion; re-run without --no-docling")
        return self._convert_with_docling(path)

    def _convert_with_docling(self, path: Path) -> dict[str, str]:
        try:
            from docling.document_converter import DocumentConverter
        except ModuleNotFoundError as exc:
            raise DocumentIngestionError(
                "Docling is not installed. Install the optional `rag` extra to ingest rich document formats."
            ) from exc
        converter = DocumentConverter()
        result = converter.convert(str(path))
        document = result.document
        markdown = str(document.export_to_markdown())
        json_body = ""
        if hasattr(document, "export_to_dict"):
            json_body = json.dumps(document.export_to_dict(), indent=2, sort_keys=True)
        return {"converter": "docling", "markdown": markdown, "json": json_body}

    def _read_text(self, path: Path) -> str:
        return path.read_text(encoding="utf-8", errors="replace")

    def _redact(self, text: str) -> RedactionResult:
        redacted = text
        labels: list[str] = []
        total = 0
        for label, pattern, replacement in self._SECRET_PATTERNS:
            redacted, count = pattern.subn(replacement, redacted)
            if count:
                total += count
                labels.append(label)
        return RedactionResult(text=redacted, count=total, labels=labels)

    def _normalize_corpus_type(self, corpus_type: str) -> str:
        return canonical_rag_domain(corpus_type, blank="operator_note")

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

    def _normalize_hint_policy(self, hint_policy: str | None, *, corpus_type: str) -> str:
        default = "advisory"
        normalized = normalized_context_key(hint_policy or default)
        if normalized not in self.HINT_POLICIES:
            raise DocumentIngestionError(
                f"unsupported RAG hint policy: {hint_policy}; expected one of {', '.join(sorted(self.HINT_POLICIES))}"
            )
        return normalized

    def _normalize_source_trust(self, source_trust: str | None, *, corpus_type: str) -> str:
        if source_trust:
            return self._safe_fragment(normalized_context_key(source_trust))
        if corpus_type == "cve_advisory":
            return "advisory"
        if corpus_type == "exploit_note":
            return "public_exploit_reference"
        if corpus_type == "htb_writeup":
            return "walkthrough"
        return "operator_selected"

    def _corpus_creates_evidence(self, corpus_type: str) -> bool:
        return corpus_type == "operator_note"

    def _extract_cve_ids(self, text: str) -> list[str]:
        return sorted({match.upper() for match in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, flags=re.IGNORECASE)})

    def _build_chunks(
        self,
        markdown: str,
        *,
        title: str,
        target_id: str,
        source_artifact_id: str,
        source_sha256: str,
        evidence_refs: list[str],
        metadata: dict[str, Any],
    ) -> list[DocumentChunk]:
        blocks = [block.strip() for block in re.split(r"\n\s*\n", markdown) if block.strip()]
        chunks: list[DocumentChunk] = []
        current_title = title
        pending: list[str] = []

        def flush() -> None:
            if not pending:
                return
            text = "\n\n".join(pending).strip()
            if not text:
                pending.clear()
                return
            chunks.append(
                DocumentChunk(
                    target_id=target_id,
                    source_artifact_id=source_artifact_id,
                    source_sha256=source_sha256,
                    chunk_index=len(chunks),
                    title=current_title,
                    text=text,
                    token_count=max(1, len(re.findall(r"\S+", text))),
                    evidence_refs=list(evidence_refs),
                    metadata={**metadata, "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()},
                )
            )
            pending.clear()

        for block in blocks:
            heading = self._heading_title(block)
            if heading:
                flush()
                current_title = heading
            if sum(len(item) for item in pending) + len(block) > self.MAX_CHUNK_CHARS:
                flush()
            if len(block) > self.MAX_CHUNK_CHARS:
                for start in range(0, len(block), self.MAX_CHUNK_CHARS):
                    pending.append(block[start:start + self.MAX_CHUNK_CHARS])
                    flush()
                continue
            pending.append(block)
        flush()
        return chunks

    def _heading_title(self, block: str) -> str:
        first = block.splitlines()[0].strip()
        match = re.match(r"^#{1,6}\s+(.+)$", first)
        return match.group(1).strip()[:160] if match else ""

    def _persist_artifact(
        self,
        path: Path,
        body: str,
        *,
        target_id: str,
        task_id: str | None,
        metadata: dict[str, Any],
    ) -> ArtifactRecord:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        data = body.encode("utf-8")
        artifact = ArtifactRecord(
            task_id=task_id,
            target_id=target_id,
            kind=ArtifactKind.RAG_DOCUMENT,
            path=str(path),
            sha256=hashlib.sha256(data).hexdigest(),
            size_bytes=len(data),
            metadata=metadata,
            created_at=utc_now(),
        )
        self.store.insert_artifact(artifact)
        return artifact

    def _sha256_file(self, path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _safe_fragment(self, value: str) -> str:
        fragment = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
        return fragment.strip("._-")[:100] or "document"
