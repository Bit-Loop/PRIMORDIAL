from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from .config import CorpusPolicy
from .filetypes import is_attack_json_filename
from .models import ChunkRecord

REQUIRED_CHUNK_FIELDS = {
    "chunk_id",
    "doc_id",
    "source_file",
    "source_sha256",
    "source_type",
    "domain",
    "chunk_index",
    "chunk_type",
    "retrieval_text",
    "raw_text",
    "requires_authorized_scope",
    "allowed_use_modes",
    "authority_level",
    "corpus_type",
    "risk_level",
    "planner_visibility",
    "scope_gate_required",
}


def _jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not path.exists():
        return records
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSONL: {exc}") from exc
    return records


def validate_outputs(output_dir: Path, policy: CorpusPolicy) -> dict[str, Any]:
    output_dir = Path(output_dir)
    classified = _jsonl(output_dir / "classified_sources.jsonl")
    extracted = _jsonl(output_dir / "extracted_sources.jsonl")
    chunks = _jsonl(output_dir / "chunks" / "chunks.jsonl")
    sources = {record.get("source_id"): record for record in classified}
    extracted_by_source = {record.get("source_id"): record for record in extracted}
    errors: list[str] = []
    warnings: list[str] = []

    policy_blocked = {record.get("source_id") for record in classified if record.get("policy_blocked")}
    for chunk in chunks:
        missing = [field for field in REQUIRED_CHUNK_FIELDS if chunk.get(field) in (None, "", [])]
        if missing:
            errors.append(f"chunk {chunk.get('chunk_id')} missing required fields: {', '.join(missing)}")
        try:
            ChunkRecord.model_validate(
                {
                    "chunk_id": chunk.get("chunk_id"),
                    "doc_id": chunk.get("doc_id"),
                    "source_file": chunk.get("source_file"),
                    "source_sha256": chunk.get("source_sha256"),
                    "source_type": chunk.get("source_type"),
                    "domain": chunk.get("domain"),
                    "secondary_domains": chunk.get("secondary_domains", []),
                    "title": chunk.get("title"),
                    "section": chunk.get("section"),
                    "page_start": chunk.get("page_start"),
                    "page_end": chunk.get("page_end"),
                    "chunk_index": chunk.get("chunk_index"),
                    "chunk_type": chunk.get("chunk_type"),
                    "retrieval_text": chunk.get("retrieval_text"),
                    "raw_text": chunk.get("raw_text"),
                    "requires_authorized_scope": chunk.get("requires_authorized_scope"),
                    "allowed_use_modes": chunk.get("allowed_use_modes", []),
                    "metadata": chunk.get("metadata", {}),
                }
            )
        except Exception as exc:
            errors.append(f"chunk {chunk.get('chunk_id')} failed ChunkRecord validation: {exc}")
        if chunk.get("source_id") in policy_blocked or chunk.get("policy_blocked"):
            errors.append(f"chunk {chunk.get('chunk_id')} was emitted from a policy-blocked source")
        source = sources.get(chunk.get("source_id"))
        if source and source.get("planner_visibility") == "restricted" and chunk.get("planner_visibility") == "normal":
            errors.append(f"restricted source {source.get('source_id')} emitted normal-visibility chunk")
        if source and source.get("authority_level") == "junk":
            errors.append(f"junk source {source.get('source_id')} emitted chunk {chunk.get('chunk_id')}")
        if source and is_attack_json_filename(str(source.get("filename"))) and chunk.get("source_type") != "attack_record":
            errors.append(f"ATT&CK source {source.get('source_id')} emitted non-structured chunk {chunk.get('chunk_id')}")

    for source in classified:
        source_id = source.get("source_id")
        result = extracted_by_source.get(source_id)
        if not result:
            continue
        if source.get("authority_level") == "junk" and result.get("extracted"):
            errors.append(f"junk source {source_id} was extracted")
        if source.get("policy_blocked") and result.get("extracted"):
            errors.append(f"policy-blocked source {source_id} was extracted")

    if not policy.allow_duplicate_extraction:
        extracted_hashes: dict[str, list[str]] = defaultdict(list)
        for source in classified:
            result = extracted_by_source.get(source.get("source_id"))
            if result and result.get("extracted"):
                extracted_hashes[str(source.get("sha256"))].append(str(source.get("source_id")))
        for sha256, ids in extracted_hashes.items():
            if len(ids) > 1:
                errors.append(f"duplicate exact-hash source extracted more than once: {sha256} -> {ids}")

    report = _validation_report(classified, extracted, chunks, errors=errors, warnings=warnings)
    (output_dir / "validation_report.json").write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return report


def _validation_report(
    classified: list[dict[str, Any]],
    extracted: list[dict[str, Any]],
    chunks: list[dict[str, Any]],
    *,
    errors: list[str],
    warnings: list[str],
) -> dict[str, Any]:
    return {
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "chunk_count": len(chunks),
        "source_count": len(classified),
        "extracted_count": sum(1 for record in extracted if record.get("extracted")),
        "policy_blocked_count": sum(1 for record in classified if record.get("policy_blocked")),
        "restricted_chunks": sum(1 for chunk in chunks if chunk.get("planner_visibility") == "restricted"),
        "taxonomy_only_chunks": sum(1 for chunk in chunks if chunk.get("planner_visibility") == "taxonomy_only"),
    }
