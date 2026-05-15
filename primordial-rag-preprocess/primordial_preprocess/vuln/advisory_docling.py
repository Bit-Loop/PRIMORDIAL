from __future__ import annotations

from pathlib import Path

from primordial_preprocess.extraction.docling import DoclingExtractionUnavailable, extract_with_docling

from .advisory_extract import extract_advisory_facts
from .hashing import stable_id
from .io import write_json
from .models import AdvisoryDocRecord, AdvisoryExtractedFacts


def process_advisory_document(
    path: Path | str,
    output_root: Path | str,
    *,
    allow_ocr: bool = False,
    publisher: str = "",
) -> tuple[AdvisoryDocRecord, AdvisoryExtractedFacts, list[dict[str, object]]]:
    source = Path(path)
    if source.suffix.lower() in {".md", ".markdown", ".txt"}:
        from .advisory_extract import process_markdown_advisory

        return process_markdown_advisory(source, output_root, publisher=publisher)
    digest = _sha256_file(source)
    advisory_id = stable_id("advisory", digest, source.name, length=24)
    out = Path(output_root) / "vuln" / "advisories"
    docling_json_path = out / "docling_json" / f"{advisory_id}.json"
    markdown_path = out / "markdown" / f"{advisory_id}.md"
    warnings: list[str] = []
    try:
        extracted = extract_with_docling(
            source,
            allow_ocr=allow_ocr,
            docling_json_path=docling_json_path,
            markdown_path=markdown_path,
        )
        text = str(extracted.get("text") or "")
        warnings.extend(str(item) for item in extracted.get("warnings", []) if item)
    except DoclingExtractionUnavailable as exc:
        text = ""
        warnings.append(str(exc))
    except Exception as exc:  # noqa: BLE001 - one advisory must not abort the stream
        text = ""
        warnings.append(f"docling_conversion_failed:{exc}")
    facts = extract_advisory_facts(text, title=source.stem, publisher=publisher)
    facts_path = out / "extracted_facts" / f"{advisory_id}.facts.json"
    write_json(facts_path, facts)
    chunks = []
    if text.strip():
        from .advisory_extract import _advisory_chunks

        chunks = _advisory_chunks(text, advisory_id=advisory_id, source=source, source_sha256=digest, facts=facts)
    doc = AdvisoryDocRecord(
        advisory_doc_id=advisory_id,
        source_file=source.name,
        source_sha256=digest,
        source_type=source.suffix.lower().lstrip("."),
        publisher=publisher,
        title=facts.advisory_title or source.stem,
        docling_json_path=str(docling_json_path) if docling_json_path.exists() else "",
        markdown_path=str(markdown_path) if markdown_path.exists() else "",
        cve_ids=facts.cve_ids,
        ghsa_ids=facts.ghsa_ids,
        osv_ids=facts.osv_ids,
        extracted_facts_path=str(facts_path),
        chunk_count=len(chunks),
        confidence=0.72 if text.strip() else 0.2,
        warnings=warnings,
    )
    return doc, facts, chunks


def _sha256_file(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
