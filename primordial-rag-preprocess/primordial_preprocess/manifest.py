from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any


def _jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                records.append(json.loads(line))
    return records


def _count_many(records: list[dict[str, Any]], key: str) -> Counter[str]:
    counter: Counter[str] = Counter()
    for record in records:
        value = record.get(key)
        if isinstance(value, list):
            counter.update(str(item) for item in value)
        elif value is not None:
            counter[str(value)] += 1
    return counter


def build_manifest(output_dir: Path, *, validation_report: dict[str, Any] | None = None) -> dict[str, Any]:
    output_dir = Path(output_dir)
    inventory = _jsonl(output_dir / "inventory.jsonl")
    classified = _jsonl(output_dir / "classified_sources.jsonl")
    extracted = _jsonl(output_dir / "extracted_sources.jsonl")
    chunks = _jsonl(output_dir / "chunks" / "chunks.jsonl")
    validation_report = validation_report or {}

    manifest = {
        "files_scanned": len(inventory),
        "files_classified": len(classified),
        "files_extracted": sum(1 for record in extracted if record.get("extracted")),
        "policy_blocked": sum(1 for record in classified if record.get("policy_blocked")),
        "quarantined": sum(1 for record in classified if record.get("planner_visibility") == "quarantine"),
        "duplicates": sum(1 for record in inventory if not record.get("recommended_keep", True)),
        "chunks_generated": len(chunks),
        "sources_by_authority_level": dict(_count_many(classified, "authority_level")),
        "sources_by_corpus_type": dict(_count_many(classified, "corpus_type")),
        "restricted_chunks": sum(1 for chunk in chunks if chunk.get("planner_visibility") == "restricted"),
        "taxonomy_only_chunks": sum(1 for chunk in chunks if chunk.get("planner_visibility") == "taxonomy_only"),
        "warnings": [
            warning
            for record in extracted
            for warning in record.get("warnings", [])
        ] + list(validation_report.get("warnings", [])),
        "validation": validation_report,
        "recommended_next_actions": _recommended_next_actions(classified, extracted, validation_report),
    }
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    _write_manifest_md(output_dir / "manifest.md", manifest)
    return manifest


def _recommended_next_actions(
    classified: list[dict[str, Any]],
    extracted: list[dict[str, Any]],
    validation_report: dict[str, Any],
) -> list[str]:
    actions: list[str] = []
    if any(record.get("license_status") == "unknown_commercial" and record.get("policy_blocked") for record in classified):
        actions.append("Add source_overrides.yaml entries only for commercial sources the operator confirms are licensed for local private RAG.")
    if any(record.get("planner_visibility") == "restricted" and record.get("policy_blocked") for record in classified):
        actions.append("Leave restricted exploit/kernel/binary material blocked unless a scoped lab use case requires a separate restricted index.")
    if any(record.get("backend") == "docling" and record.get("extraction_error") for record in extracted):
        actions.append("Install or repair Docling before rerunning extraction; fallback parsers are intentionally disabled.")
    if validation_report.get("errors"):
        actions.append("Fix validation errors before ingesting chunks into any vector index.")
    if not actions:
        actions.append("Review manifest counts, then import chunks with planner_visibility filters enforced by the runtime.")
    return actions


def _write_manifest_md(path: Path, manifest: dict[str, Any]) -> None:
    lines = [
        "# PRIMORDIAL RAG Preprocess Manifest",
        "",
        f"- Files scanned: {manifest['files_scanned']}",
        f"- Files extracted: {manifest['files_extracted']}",
        f"- Policy blocked: {manifest['policy_blocked']}",
        f"- Quarantined: {manifest['quarantined']}",
        f"- Duplicates: {manifest['duplicates']}",
        f"- Chunks generated: {manifest['chunks_generated']}",
        f"- Restricted chunks: {manifest['restricted_chunks']}",
        f"- Taxonomy-only chunks: {manifest['taxonomy_only_chunks']}",
        "",
        "## Sources by Authority Level",
        "",
    ]
    for key, value in sorted(manifest["sources_by_authority_level"].items()):
        lines.append(f"- {key}: {value}")
    lines.extend(["", "## Sources by Corpus Type", ""])
    for key, value in sorted(manifest["sources_by_corpus_type"].items()):
        lines.append(f"- {key}: {value}")
    lines.extend(["", "## Recommended Next Actions", ""])
    for action in manifest["recommended_next_actions"]:
        lines.append(f"- {action}")
    if manifest.get("warnings"):
        lines.extend(["", "## Warnings", ""])
        for warning in manifest["warnings"]:
            lines.append(f"- {warning}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
