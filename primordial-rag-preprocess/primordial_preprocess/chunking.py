from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from . import PIPELINE_VERSION
from .cleaning import clean_text
from .config import CorpusPolicy
from .hashing import stable_id
from .models import ALLOWED_USE_MODES, ChunkRecord, domains_from_corpus_types
from .profile_extract import load_profiles

HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$", re.MULTILINE)


def _jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                records.append(json.loads(line))
    return records


def _json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")


def _section_blocks(text: str) -> list[tuple[list[str], str]]:
    matches = list(HEADING_RE.finditer(text))
    if not matches:
        return [([], text)]
    blocks: list[tuple[list[str], str]] = []
    heading_stack: list[tuple[int, str]] = []
    preface = text[: matches[0].start()].strip()
    if preface:
        blocks.append(([], preface))
    for index, match in enumerate(matches):
        level = len(match.group(1))
        title = match.group(2).strip()
        while heading_stack and heading_stack[-1][0] >= level:
            heading_stack.pop()
        heading_stack.append((level, title))
        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        blocks.append(([item[1] for item in heading_stack], text[start:end].strip()))
    return blocks


def _split_text(text: str, target_chars: int, overlap_chars: int) -> list[str]:
    text = text.strip()
    if not text:
        return []
    if len(text) <= target_chars:
        return [text]
    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = min(len(text), start + target_chars)
        if end < len(text):
            boundary = max(
                text.rfind("\n\n", start, end),
                text.rfind(". ", start, end),
                text.rfind(" ", start, end),
            )
            if boundary > start + int(target_chars * 0.55):
                end = boundary + 1
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        if end >= len(text):
            break
        start = max(end - overlap_chars, start + 1)
    return chunks


def _token_estimate(text: str) -> int:
    return max(1, int(len(text) / 4))


def _primary_domain(source: dict[str, Any], profile: dict[str, Any] | None = None) -> tuple[str, list[str]]:
    if profile and profile.get("primary_domain"):
        return str(profile["primary_domain"]), [str(item) for item in profile.get("secondary_domains", [])]
    return domains_from_corpus_types([str(item) for item in source.get("corpus_type", [])])


def _base_chunk(
    source: dict[str, Any],
    retrieval_text: str,
    chunk_index: int,
    *,
    source_type: str | None = None,
    raw_text: str | None = None,
    chunk_type: str = "text_section",
    profile: dict[str, Any] | None = None,
) -> dict[str, Any]:
    domain, secondary_domains = _primary_domain(source, profile)
    raw = raw_text if raw_text is not None else retrieval_text
    return {
        "chunk_id": stable_id("chunk", source.get("source_id"), chunk_index, retrieval_text),
        "doc_id": source.get("source_id"),
        "source_id": source.get("source_id"),
        "source_file": source.get("relative_path") or source.get("source_path"),
        "source_sha256": source.get("sha256") or source.get("source_sha256"),
        "title": source.get("title_guess") or source.get("title") or source.get("filename"),
        "author": source.get("author_guess") or source.get("author"),
        "publisher": source.get("publisher_guess") or source.get("publisher"),
        "year": source.get("year_guess") or source.get("year"),
        "source_path": source.get("relative_path") or source.get("source_path"),
        "source_type": source_type or source.get("detected_type") or source.get("source_type"),
        "page_start": None,
        "page_end": None,
        "section": None,
        "section_path": [],
        "chunk_index": chunk_index,
        "chunk_type": chunk_type,
        "retrieval_text": retrieval_text,
        "raw_text": raw,
        "text": retrieval_text,
        "token_estimate": _token_estimate(retrieval_text),
        "authority_level": source.get("authority_level"),
        "corpus_type": source.get("corpus_type", []),
        "domain": domain,
        "secondary_domains": secondary_domains,
        "risk_level": source.get("risk_level"),
        "planner_visibility": source.get("planner_visibility"),
        "scope_gate_required": bool(source.get("scope_gate_required", False)),
        "requires_operator_approval": bool(source.get("requires_operator_approval", False)),
        "requires_authorized_scope": True,
        "allowed_use_modes": list(ALLOWED_USE_MODES),
        "allowed_contexts": source.get("allowed_contexts", ["owned_lab", "ctf", "authorized_security_research"]),
        "license_status": source.get("license_status"),
        "policy_blocked": bool(source.get("policy_blocked", False)),
        "extraction_warnings": list(source.get("extraction_warnings", [])),
        "metadata": {"profile": profile or {}},
        "created_by_pipeline_version": PIPELINE_VERSION,
    }


def _chunks_for_extracted_source(
    source: dict[str, Any],
    extracted: dict[str, Any],
    policy: CorpusPolicy,
    profile: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    chunks: list[dict[str, Any]] = []
    chunk_index = 0
    if extracted.get("docling_json_path") and policy.docling_chunker == "hybrid":
        try:
            return _chunks_for_docling_json(source, extracted, profile)
        except Exception as exc:  # noqa: BLE001 - fallback to saved extraction units with warning
            extracted.setdefault("warnings", []).append(f"hybrid_chunker_failed:{type(exc).__name__}:{exc}")
    for unit in extracted.get("units", []):
        unit_text = clean_text(str(unit.get("text") or ""))
        if not unit_text:
            continue
        unit_meta = unit.get("metadata") or {}
        for section_path, block in _section_blocks(unit_text):
            for piece in _split_text(block, policy.chunking.target_chars, policy.chunking.overlap_chars):
                chunk = _base_chunk(source, piece, chunk_index, profile=profile)
                page = unit_meta.get("page") or unit_meta.get("page_no") or unit_meta.get("page_number")
                if isinstance(page, int):
                    chunk["page_start"] = page
                    chunk["page_end"] = page
                chunk["section_path"] = section_path
                chunk["section"] = " > ".join(section_path) if section_path else None
                chunk["extraction_warnings"] = list(extracted.get("warnings", []))
                chunks.append(chunk)
                chunk_index += 1
    return chunks


def _load_hybrid_chunker() -> Any:
    try:
        from docling.chunking import HybridChunker
    except Exception:
        from docling_core.transforms.chunker.hybrid_chunker import HybridChunker
    return HybridChunker


def _load_docling_document(path: Path) -> Any:
    try:
        from docling_core.types.doc.document import DoclingDocument
    except Exception:
        from docling.datamodel.document import DoclingDocument
    return DoclingDocument.load_from_json(path)


def _chunks_for_docling_json(
    source: dict[str, Any],
    extracted: dict[str, Any],
    profile: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    doc_path = Path(str(extracted["docling_json_path"]))
    document = _load_docling_document(doc_path)
    chunker = _load_hybrid_chunker()()
    chunks: list[dict[str, Any]] = []
    for index, doc_chunk in enumerate(chunker.chunk(document)):
        raw_text = str(getattr(doc_chunk, "text", "") or "")
        try:
            retrieval_text = str(chunker.contextualize(doc_chunk))
        except Exception:
            retrieval_text = raw_text
        retrieval_text = clean_text(retrieval_text)
        raw_text = clean_text(raw_text or retrieval_text)
        if not retrieval_text:
            continue
        chunk = _base_chunk(
            source,
            retrieval_text,
            index,
            raw_text=raw_text,
            chunk_type="docling_hybrid",
            profile=profile,
        )
        meta = getattr(doc_chunk, "meta", None)
        headings = [str(item) for item in getattr(meta, "headings", []) or []]
        chunk["section_path"] = headings
        chunk["section"] = " > ".join(headings) if headings else None
        page_start, page_end = _page_range_from_meta(meta)
        chunk["page_start"] = page_start
        chunk["page_end"] = page_end
        chunk["metadata"].update(
            {
                "docling_json_path": str(doc_path),
                "markdown_path": extracted.get("markdown_path"),
                "chunk_meta": _model_dump(meta),
            }
        )
        chunk["extraction_warnings"] = list(extracted.get("warnings", []))
        chunks.append(chunk)
    return chunks


def _page_range_from_meta(meta: Any) -> tuple[int | None, int | None]:
    pages: list[int] = []
    for item in getattr(meta, "doc_items", []) or []:
        for prov in getattr(item, "prov", []) or []:
            page_no = getattr(prov, "page_no", None)
            if isinstance(page_no, int):
                pages.append(page_no)
    if not pages:
        return None, None
    return min(pages), max(pages)


def _model_dump(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if hasattr(value, "dict"):
        return value.dict()
    return {}


def _attack_record_text(record: dict[str, Any]) -> str:
    fields = [
        ("Technique ID", record.get("technique_id")),
        ("Name", record.get("name")),
        ("Domain", record.get("attack_domain")),
        ("Object Type", record.get("object_type")),
        ("Tactics", ", ".join(record.get("tactics") or [])),
        ("Platforms", ", ".join(record.get("platforms") or [])),
        ("Data Sources", ", ".join(record.get("data_sources") or [])),
        ("Description", record.get("description")),
        ("Detection", record.get("detection")),
        ("Mitigations", json.dumps(record.get("mitigations") or [], sort_keys=True)),
        ("Relationships", json.dumps(record.get("relationships") or [], sort_keys=True)),
        ("Revoked", str(bool(record.get("revoked")))),
        ("Deprecated", str(bool(record.get("deprecated")))),
        ("Version", record.get("x_mitre_version")),
        ("Source Modified", record.get("source_modified")),
    ]
    return "\n".join(f"{label}: {value}" for label, value in fields if value not in (None, "", [], {}))


def _chunks_for_attack_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    chunks: list[dict[str, Any]] = []
    for index, record in enumerate(records):
        text = _attack_record_text(record)
        source = {
            "source_id": record.get("source_id"),
            "sha256": record.get("source_sha256"),
            "title_guess": f"MITRE ATT&CK {record.get('attack_domain')}",
            "relative_path": record.get("source_path"),
            "detected_type": "attack_json",
            "authority_level": "official_taxonomy",
            "corpus_type": ["attack_taxonomy"],
            "domain": [record.get("attack_domain")],
            "risk_level": "safe_planning",
            "planner_visibility": "taxonomy_only",
            "scope_gate_required": True,
            "requires_operator_approval": False,
            "license_status": "open_public",
            "policy_blocked": False,
        }
        chunk = _base_chunk(source, text, index, source_type="attack_record", chunk_type="attack_taxonomy")
        chunk["chunk_id"] = stable_id("chunk", source["source_id"], record.get("record_id"), text)
        chunk["attack_record_id"] = record.get("record_id")
        chunk["attack_domain"] = record.get("attack_domain")
        chunk["technique_id"] = record.get("technique_id")
        chunk["object_type"] = record.get("object_type")
        chunk["section_path"] = [record.get("attack_domain") or "attack", record.get("name") or record.get("record_id")]
        chunks.append(chunk)
    return chunks


def build_chunks(output_dir: Path, policy: CorpusPolicy) -> list[dict[str, Any]]:
    output_dir = Path(output_dir)
    sources = {record["source_id"]: record for record in _jsonl(output_dir / "classified_sources.jsonl")}
    profiles = load_profiles(output_dir)
    extracted = _jsonl(output_dir / "extracted_sources.jsonl")
    chunks: list[dict[str, Any]] = []
    for result in extracted:
        source_id = result.get("source_id")
        source = sources.get(source_id)
        if not source or result.get("policy_blocked") or not result.get("extracted"):
            continue
        if result.get("backend") == "structured_attack_parser":
            continue
        detail = result
        if not result.get("docling_json_path") and result.get("extracted_path"):
            loaded = _json(Path(str(result["extracted_path"])))
            if loaded:
                detail = loaded
        chunks.extend(_chunks_for_extracted_source(source, detail, policy, profiles.get(str(source_id))))

    attack_records: list[dict[str, Any]] = []
    attack_dir = output_dir / "attack"
    if attack_dir.exists():
        for path in sorted(attack_dir.glob("*_records.jsonl")):
            attack_records.extend(_jsonl(path))
    chunks.extend(_chunks_for_attack_records(attack_records))
    chunks = [_validated_chunk(chunk) for chunk in chunks]

    chunks_dir = output_dir / "chunks"
    _write_jsonl(chunks_dir / "chunks.jsonl", chunks)
    by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for chunk in chunks:
        by_source[str(chunk.get("source_id"))].append(chunk)
    source_dir = chunks_dir / "chunks_by_source"
    source_dir.mkdir(parents=True, exist_ok=True)
    for source_id, source_chunks in sorted(by_source.items()):
        _write_jsonl(source_dir / f"{source_id}.jsonl", source_chunks)
    _write_domain_files(chunks_dir, chunks)
    _write_named_indexes(output_dir, chunks)
    return chunks


def _validated_chunk(chunk: dict[str, Any]) -> dict[str, Any]:
    ChunkRecord.model_validate(
        {
            "chunk_id": chunk["chunk_id"],
            "doc_id": chunk.get("doc_id") or chunk.get("source_id"),
            "source_file": chunk.get("source_file") or chunk.get("source_path"),
            "source_sha256": chunk["source_sha256"],
            "source_type": chunk["source_type"],
            "domain": chunk["domain"],
            "secondary_domains": chunk.get("secondary_domains", []),
            "title": chunk.get("title"),
            "section": chunk.get("section"),
            "page_start": chunk.get("page_start"),
            "page_end": chunk.get("page_end"),
            "chunk_index": chunk["chunk_index"],
            "chunk_type": chunk["chunk_type"],
            "retrieval_text": chunk["retrieval_text"],
            "raw_text": chunk["raw_text"],
            "requires_authorized_scope": chunk["requires_authorized_scope"],
            "allowed_use_modes": chunk["allowed_use_modes"],
            "metadata": chunk.get("metadata", {}),
        }
    )
    return chunk


def _write_named_indexes(output_dir: Path, chunks: list[dict[str, Any]]) -> None:
    indexes_dir = output_dir / "indexes"
    indexes_dir.mkdir(parents=True, exist_ok=True)
    for domain in ("enterprise", "mobile", "ics"):
        domain_chunks = [
            chunk
            for chunk in chunks
            if chunk.get("planner_visibility") == "taxonomy_only" and chunk.get("attack_domain") == domain
        ]
        _write_jsonl(indexes_dir / f"attck_{domain}_index.jsonl", domain_chunks)


def _write_domain_files(chunks_dir: Path, chunks: list[dict[str, Any]]) -> None:
    domains = [
        "api_web",
        "kubernetes_cloud",
        "systems_exploitation",
        "methodology_standards",
        "mitre_attack",
        "formal_methods",
        "general_security",
    ]
    for domain in domains:
        _write_jsonl(chunks_dir / f"{domain}.jsonl", [chunk for chunk in chunks if chunk.get("domain") == domain])
