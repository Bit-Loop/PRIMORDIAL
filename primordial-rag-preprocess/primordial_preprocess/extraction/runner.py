from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from primordial_preprocess.config import CorpusPolicy
from primordial_preprocess.epub_convert import convert_epub_with_pandoc
from primordial_preprocess.extraction.docling import DoclingExtractionUnavailable, extract_with_docling
from primordial_preprocess.extraction.json_attack import parse_attack_file, write_attack_outputs
from primordial_preprocess.filetypes import attack_domain_from_filename, is_attack_json_filename
from primordial_preprocess.policy import docling_required_reason


@dataclass(frozen=True, slots=True)
class ExtractionPaths:
    output_dir: Path
    extracted_dir: Path
    docling_json_dir: Path
    markdown_dir: Path
    epub_dir: Path


def extract_sources(
    records: list[dict[str, Any]],
    output_dir: Path | str,
    policy: CorpusPolicy,
    *,
    force: bool = False,
    skip_docling: bool = False,
) -> list[dict[str, Any]]:
    paths = _prepare_paths(output_dir)
    results: list[dict[str, Any]] = []
    attack_records: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        results.append(_extract_one(record, paths, policy, attack_records, force=force, skip_docling=skip_docling))
    write_attack_outputs(attack_records, paths.output_dir)
    _write_jsonl(paths.output_dir / "extracted_sources.jsonl", results)
    return results


def _prepare_paths(output_dir: Path | str) -> ExtractionPaths:
    out = Path(output_dir)
    extracted_dir = out / "extracted"
    extracted_dir.mkdir(parents=True, exist_ok=True)
    converted_dir = out / "converted"
    return ExtractionPaths(
        output_dir=out,
        extracted_dir=extracted_dir,
        docling_json_dir=converted_dir / "docling_json",
        markdown_dir=converted_dir / "markdown",
        epub_dir=converted_dir / "epub_converted",
    )


def _extract_one(
    record: dict[str, Any],
    paths: ExtractionPaths,
    policy: CorpusPolicy,
    attack_records: dict[str, list[dict[str, Any]]],
    *,
    force: bool,
    skip_docling: bool,
) -> dict[str, Any]:
    result = _base_result(record)
    if record.get("policy_blocked"):
        return _policy_blocked_result(result, record)
    source_path = Path(str(record["original_path"]))
    if is_attack_json_filename(str(record.get("filename") or "")):
        return _extract_attack_record(record, result, source_path, attack_records)
    if skip_docling:
        return _docling_skipped_result(result)
    return _extract_docling_record(record, result, source_path, paths, policy, force=force)


def _policy_blocked_result(result: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    return {
        **result,
        "policy_blocked": True,
        "extracted": False,
        "extraction_error": record.get("policy_block_reason", "policy blocked"),
        "units": [],
    }


def _extract_attack_record(
    record: dict[str, Any],
    result: dict[str, Any],
    source_path: Path,
    attack_records: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    domain = attack_domain_from_filename(str(record["filename"])) or "attack"
    parsed = parse_attack_file(source_path)
    for item in parsed:
        item["source_id"] = record["source_id"]
        item["source_path"] = record["relative_path"]
    attack_records.setdefault(domain, []).extend(parsed)
    return {
        **result,
        "extracted": True,
        "backend": "structured_attack_parser",
        "units": [],
        "attack_record_count": len(parsed),
    }


def _docling_skipped_result(result: dict[str, Any]) -> dict[str, Any]:
    return {
        **result,
        "extracted": False,
        "backend": "docling",
        "extraction_error": "Docling conversion skipped by operator flag",
        "units": [],
    }


def _extract_docling_record(
    record: dict[str, Any],
    result: dict[str, Any],
    source_path: Path,
    paths: ExtractionPaths,
    policy: CorpusPolicy,
    *,
    force: bool,
) -> dict[str, Any]:
    conversion = _conversion_input(record, source_path, paths, force=force or policy.overwrite_existing)
    if not conversion["converted"]:
        return _epub_failure_result(result, conversion)
    docling_json_path = paths.docling_json_dir / f"{record['source_id']}.json"
    markdown_path = paths.markdown_dir / f"{record['source_id']}.md"
    epub_conversion = conversion["epub_conversion"]
    if docling_json_path.exists() and markdown_path.exists() and not (force or policy.overwrite_existing):
        return _cached_docling_result(record, result, paths, docling_json_path, markdown_path, epub_conversion)
    try:
        extracted = extract_with_docling(
            conversion["input_path"],
            allow_ocr=policy.docling_allow_ocr,
            docling_json_path=docling_json_path,
            markdown_path=markdown_path,
        )
    except DoclingExtractionUnavailable as exc:
        return _docling_error_result(result, str(exc) or docling_required_reason())
    except Exception as exc:  # noqa: BLE001 - extraction failure should not abort the corpus
        return _docling_error_result(result, f"{type(exc).__name__}: {exc}")
    return _write_docling_result(record, result, paths, extracted, docling_json_path, markdown_path, epub_conversion)


def _conversion_input(record: dict[str, Any], source_path: Path, paths: ExtractionPaths, *, force: bool) -> dict[str, Any]:
    if str(record.get("detected_type")) != "epub":
        return {"converted": True, "input_path": source_path, "epub_conversion": None}
    epub_path = paths.epub_dir / f"{record['source_id']}.md"
    epub_conversion = convert_epub_with_pandoc(source_path, epub_path, force=force)
    if not epub_conversion.get("converted"):
        return {"converted": False, "epub_conversion": epub_conversion}
    return {"converted": True, "input_path": Path(str(epub_conversion["output_path"])), "epub_conversion": epub_conversion}


def _epub_failure_result(result: dict[str, Any], conversion: dict[str, Any]) -> dict[str, Any]:
    epub_conversion = conversion["epub_conversion"]
    return {
        **result,
        "extracted": False,
        "backend": "pandoc_epub",
        "epub_conversion": epub_conversion,
        "extraction_error": epub_conversion.get("error") or "EPUB conversion failed",
        "units": [],
    }


def _cached_docling_result(
    record: dict[str, Any],
    result: dict[str, Any],
    paths: ExtractionPaths,
    docling_json_path: Path,
    markdown_path: Path,
    epub_conversion: dict[str, Any] | None,
) -> dict[str, Any]:
    cached = {
        **result,
        "extracted": True,
        "backend": "docling_cached",
        "warnings": [],
        "units": [],
        "docling_json_path": str(docling_json_path),
        "markdown_path": str(markdown_path),
        "epub_conversion": epub_conversion,
    }
    unit_path = paths.extracted_dir / f"{record['source_id']}.json"
    unit_path.write_text(json.dumps(cached, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    cached["extracted_path"] = str(unit_path)
    return cached


def _docling_error_result(result: dict[str, Any], message: str) -> dict[str, Any]:
    return {**result, "extracted": False, "backend": "docling", "extraction_error": message, "units": []}


def _write_docling_result(
    record: dict[str, Any],
    result: dict[str, Any],
    paths: ExtractionPaths,
    extracted: dict[str, Any],
    docling_json_path: Path,
    markdown_path: Path,
    epub_conversion: dict[str, Any] | None,
) -> dict[str, Any]:
    unit_path = paths.extracted_dir / f"{record['source_id']}.json"
    payload = {
        **result,
        "extracted": True,
        "backend": extracted.get("backend", "docling"),
        "warnings": extracted.get("warnings", []),
        "units": extracted.get("units", []),
        "docling_json_path": extracted.get("docling_json_path", str(docling_json_path)),
        "markdown_path": extracted.get("markdown_path", str(markdown_path)),
        "epub_conversion": epub_conversion,
    }
    unit_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary = dict(payload)
    summary["extracted_path"] = str(unit_path)
    summary["units"] = []
    return summary


def _base_result(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_id": record["source_id"],
        "source_sha256": record["sha256"],
        "source_path": record["relative_path"],
        "original_path": record["original_path"],
        "detected_type": record["detected_type"],
        "authority_level": record.get("authority_level"),
        "corpus_type": record.get("corpus_type", []),
        "planner_visibility": record.get("planner_visibility"),
        "risk_level": record.get("risk_level"),
        "scope_gate_required": record.get("scope_gate_required"),
        "requires_operator_approval": record.get("requires_operator_approval"),
        "license_status": record.get("license_status"),
        "policy_blocked": False,
    }


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True))
            handle.write("\n")
