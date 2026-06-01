from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from primordial.core.context.generated_exports import is_generated_export_path
from primordial.core.context.normalization import canonical_rag_domain, normalized_context_key
from primordial.core.domain.enums import ArtifactKind
from primordial.core.domain.models import ArtifactRecord, DocumentChunk, Target, utc_now
from primordial.core.rag.document_types import DocumentIngestionError, RedactionResult, SourceDocument


class DocumentSourceMixin:
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
            with self._urlopen(request, timeout=30) as response:
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
        return self._cache_remote_source(body, content_type=content_type, parsed=parsed, safe_url=safe_url, target=target)

    def _cache_remote_source(self, body: bytes, *, content_type: str, parsed: object, safe_url: str, target: Target) -> SourceDocument:
        digest = hashlib.sha256(body).hexdigest()
        name = Path(parsed.path).name or "remote-document"
        suffix = Path(name).suffix.lower() or self._suffix_from_content_type(content_type)
        stem = self._safe_fragment(Path(name).stem or "remote-document")
        filename = f"{stem}{suffix or '.bin'}"
        cache_dir = self.artifacts_dir / "rag" / "_url_cache" / self._safe_fragment(target.handle) / digest[:12]
        cache_dir.mkdir(parents=True, exist_ok=True)
        path = cache_dir / filename
        path.write_bytes(body)
        return SourceDocument(path=path, name=name, sha256=digest, source_ref=f"url:{safe_url}:{digest}", source_url=safe_url)

    def _urlopen(self, request: Request, *, timeout: int) -> object:
        documents_module = sys.modules.get("primordial.core.rag.documents")
        patched = getattr(documents_module, "urlopen", None) if documents_module is not None else None
        return (patched or urlopen)(request, timeout=timeout)

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
        metadata: dict[str, object],
    ) -> list[DocumentChunk]:
        blocks = [block.strip() for block in re.split(r"\n\s*\n", markdown) if block.strip()]
        chunks: list[DocumentChunk] = []
        current_title = title
        pending: list[str] = []

        def flush() -> None:
            self._flush_pending_chunk(chunks, pending, current_title, target_id, source_artifact_id, source_sha256, evidence_refs, metadata)

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

    def _flush_pending_chunk(
        self,
        chunks: list[DocumentChunk],
        pending: list[str],
        title: str,
        target_id: str,
        source_artifact_id: str,
        source_sha256: str,
        evidence_refs: list[str],
        metadata: dict[str, object],
    ) -> None:
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
                title=title,
                text=text,
                token_count=max(1, len(re.findall(r"\S+", text))),
                evidence_refs=list(evidence_refs),
                metadata={**metadata, "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()},
            )
        )
        pending.clear()

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
        metadata: dict[str, object],
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
