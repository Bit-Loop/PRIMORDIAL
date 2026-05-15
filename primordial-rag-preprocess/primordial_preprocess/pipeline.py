from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .chunking import build_chunks
from .classification import classify_sources, write_classification_outputs
from .config import load_overrides, load_policy
from .extraction.runner import extract_sources
from .inventory import inventory_directory, write_inventory_outputs
from .manifest import build_manifest
from .policy import apply_policy
from .profile_extract import build_profiles
from .validation import validate_outputs


@dataclass(frozen=True)
class PipelineResult:
    output_dir: Path
    inventory_count: int = 0
    classified_count: int = 0
    extracted_count: int = 0
    chunk_count: int = 0
    validation_valid: bool | None = None


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                records.append(json.loads(line))
    return records


def run_pipeline(
    *,
    input_dir: Path,
    output_dir: Path,
    policy_path: Path,
    overrides_path: Path | None = None,
    inventory_only: bool = False,
    classify_only: bool = False,
    extract_only: bool = False,
    chunk_only: bool = False,
    validate_only: bool = False,
    force: bool = False,
    skip_vlm: bool = True,
    skip_docling: bool = False,
    only: str | None = None,
) -> PipelineResult:
    output_dir.mkdir(parents=True, exist_ok=True)
    policy = load_policy(policy_path)
    overrides = load_overrides(overrides_path)

    if only:
        inventory_only = only == "inventory"
        classify_only = only == "classify" or only == "dedupe"
        extract_only = only in {"convert", "epub", "profiles", "mitre"}
        chunk_only = only in {"chunk", "merge", "eval"}
        validate_only = only == "validate"

    if validate_only:
        validation = validate_outputs(output_dir, policy)
        build_manifest(output_dir, validation_report=validation)
        return PipelineResult(output_dir=output_dir, validation_valid=bool(validation.get("valid")))

    if chunk_only:
        if only == "profiles":
            classified = read_jsonl(output_dir / "classified_sources.jsonl")
            extracted = read_jsonl(output_dir / "extracted_sources.jsonl")
            build_profiles(classified, extracted, output_dir, policy, skip_vlm=skip_vlm, force=force)
        chunks = build_chunks(output_dir, policy)
        validation = validate_outputs(output_dir, policy)
        build_manifest(output_dir, validation_report=validation)
        return PipelineResult(output_dir=output_dir, chunk_count=len(chunks), validation_valid=bool(validation.get("valid")))

    if classify_only:
        inventory = read_jsonl(output_dir / "inventory.jsonl")
        classified = apply_policy(classify_sources(inventory), policy, overrides)
        write_classification_outputs(classified, output_dir)
        return PipelineResult(output_dir=output_dir, inventory_count=len(inventory), classified_count=len(classified))

    if extract_only:
        classified = read_jsonl(output_dir / "classified_sources.jsonl")
        if overrides:
            classified = apply_policy(classified, policy, overrides)
            write_classification_outputs(classified, output_dir)
        extracted = extract_sources(classified, output_dir, policy, force=force, skip_docling=skip_docling)
        build_profiles(classified, extracted, output_dir, policy, skip_vlm=skip_vlm, force=force)
        return PipelineResult(
            output_dir=output_dir,
            classified_count=len(classified),
            extracted_count=sum(1 for record in extracted if record.get("extracted")),
        )

    inventory = inventory_directory(input_dir)
    write_inventory_outputs(inventory, output_dir)
    if inventory_only:
        return PipelineResult(output_dir=output_dir, inventory_count=len(inventory))

    classified = apply_policy(classify_sources(inventory), policy, overrides)
    write_classification_outputs(classified, output_dir)
    extracted = extract_sources(classified, output_dir, policy, force=force, skip_docling=skip_docling)
    build_profiles(classified, extracted, output_dir, policy, skip_vlm=skip_vlm, force=force)
    chunks = build_chunks(output_dir, policy)
    validation = validate_outputs(output_dir, policy)
    build_manifest(output_dir, validation_report=validation)
    return PipelineResult(
        output_dir=output_dir,
        inventory_count=len(inventory),
        classified_count=len(classified),
        extracted_count=sum(1 for record in extracted if record.get("extracted")),
        chunk_count=len(chunks),
        validation_valid=bool(validation.get("valid")),
    )
