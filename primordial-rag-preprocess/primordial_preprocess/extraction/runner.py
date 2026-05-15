from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from primordial_preprocess.config import CorpusPolicy
from primordial_preprocess.epub_convert import convert_epub_with_pandoc
from primordial_preprocess.extraction.docling import DoclingExtractionUnavailable, extract_with_docling
from primordial_preprocess.extraction.json_attack import parse_attack_file, write_attack_outputs
from primordial_preprocess.filetypes import attack_domain_from_filename, is_attack_json_filename
from primordial_preprocess.policy import docling_required_reason


def extract_sources(
    records: list[dict[str, Any]],
    output_dir: Path | str,
    policy: CorpusPolicy,
    *,
    force: bool = False,
    skip_docling: bool = False,
) -> list[dict[str, Any]]:
    out = Path(output_dir)
    extracted_dir = out / "extracted"
    extracted_dir.mkdir(parents=True, exist_ok=True)
    converted_dir = out / "converted"
    docling_json_dir = converted_dir / "docling_json"
    markdown_dir = converted_dir / "markdown"
    epub_dir = converted_dir / "epub_converted"
    results: list[dict[str, Any]] = []
    attack_records: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        result = _base_result(record)
        if record.get("policy_blocked"):
            result.update(
                {
                    "policy_blocked": True,
                    "extracted": False,
                    "extraction_error": record.get("policy_block_reason", "policy blocked"),
                    "units": [],
                }
            )
            results.append(result)
            continue
        source_path = Path(str(record["original_path"]))
        if is_attack_json_filename(str(record.get("filename") or "")):
            domain = attack_domain_from_filename(str(record["filename"])) or "attack"
            parsed = parse_attack_file(source_path)
            for item in parsed:
                item["source_id"] = record["source_id"]
                item["source_path"] = record["relative_path"]
            attack_records.setdefault(domain, []).extend(parsed)
            result.update(
                {
                    "extracted": True,
                    "backend": "structured_attack_parser",
                    "units": [],
                    "attack_record_count": len(parsed),
                }
            )
            results.append(result)
            continue
        if skip_docling:
            result.update(
                {
                    "extracted": False,
                    "backend": "docling",
                    "extraction_error": "Docling conversion skipped by operator flag",
                    "units": [],
                }
            )
            results.append(result)
            continue
        conversion_input = source_path
        epub_conversion: dict[str, Any] | None = None
        if str(record.get("detected_type")) == "epub":
            epub_path = epub_dir / f"{record['source_id']}.md"
            epub_conversion = convert_epub_with_pandoc(source_path, epub_path, force=force or policy.overwrite_existing)
            if not epub_conversion.get("converted"):
                result.update(
                    {
                        "extracted": False,
                        "backend": "pandoc_epub",
                        "epub_conversion": epub_conversion,
                        "extraction_error": epub_conversion.get("error") or "EPUB conversion failed",
                        "units": [],
                    }
                )
                results.append(result)
                continue
            conversion_input = Path(str(epub_conversion["output_path"]))
        docling_json_path = docling_json_dir / f"{record['source_id']}.json"
        markdown_path = markdown_dir / f"{record['source_id']}.md"
        if docling_json_path.exists() and markdown_path.exists() and not (force or policy.overwrite_existing):
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
            unit_path = extracted_dir / f"{record['source_id']}.json"
            unit_path.write_text(json.dumps(cached, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            cached["extracted_path"] = str(unit_path)
            results.append(cached)
            continue
        try:
            extracted = extract_with_docling(
                conversion_input,
                allow_ocr=policy.docling_allow_ocr,
                docling_json_path=docling_json_path,
                markdown_path=markdown_path,
            )
        except DoclingExtractionUnavailable as exc:
            result.update(
                {
                    "extracted": False,
                    "backend": "docling",
                    "extraction_error": str(exc) or docling_required_reason(),
                    "units": [],
                }
            )
            results.append(result)
            continue
        except Exception as exc:  # noqa: BLE001 - extraction failure should not abort the corpus
            result.update(
                {
                    "extracted": False,
                    "backend": "docling",
                    "extraction_error": f"{type(exc).__name__}: {exc}",
                    "units": [],
                }
            )
            results.append(result)
            continue
        unit_path = extracted_dir / f"{record['source_id']}.json"
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
        results.append(summary)
    write_attack_outputs(attack_records, out)
    _write_jsonl(out / "extracted_sources.jsonl", results)
    return results


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
