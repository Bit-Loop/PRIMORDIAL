from __future__ import annotations

import csv
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from primordial_preprocess.filetypes import detect_type, is_attack_json_filename
from primordial_preprocess.hashing import sha256_file
from primordial_preprocess.metadata import guess_year, normalize_title, source_id_for


def inventory_directory(input_dir: Path | str) -> list[dict[str, Any]]:
    root = Path(input_dir).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"input directory not found: {root}")
    records: list[dict[str, Any]] = []
    files = sorted(path for path in root.rglob("*") if path.is_file())
    for path in files:
        stat = path.stat()
        relative_path = str(path.relative_to(root))
        digest = sha256_file(path)
        detected_type = detect_type(path)
        provenance_flags = _provenance_flags(path, detected_type)
        record = {
            "source_id": source_id_for(relative_path, digest),
            "original_path": str(path),
            "relative_path": relative_path,
            "filename": path.name,
            "extension": path.suffix.lower(),
            "detected_type": detected_type,
            "byte_size": stat.st_size,
            "sha256": digest,
            "possible_duplicate_group": "",
            "recommended_keep": True,
            "manual_review": False,
            "created_time": _iso_timestamp(stat.st_ctime),
            "modified_time": _iso_timestamp(stat.st_mtime),
            "source_family_guess": _source_family_guess(path),
            "title_guess": normalize_title(path.name),
            "author_guess": "",
            "publisher_guess": _publisher_guess(path.name),
            "year_guess": guess_year(path.name),
            "provenance_flags": provenance_flags,
            "license_status": _default_license_status(provenance_flags),
            "extraction_allowed": False,
            "quarantine_reason": "",
        }
        records.append(record)
    _mark_duplicates(records)
    return records


def write_inventory_outputs(records: list[dict[str, Any]], output_dir: Path | str) -> None:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    _write_jsonl(out / "inventory.jsonl", records)
    _write_csv(out / "inventory.csv", records)
    duplicates = [
        {
            "sha256": digest,
            "files": [record["relative_path"] for record in group],
            "recommended_keep": next(record["relative_path"] for record in group if record["recommended_keep"]),
        }
        for digest, group in _groups_by_hash(records).items()
        if len(group) > 1
    ]
    near = [record for record in records if record.get("manual_review")]
    (out / "duplicates.json").write_text(
        json.dumps({"exact_duplicates": duplicates, "near_duplicate_manual_review": near}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )


def _groups_by_hash(records: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        groups[str(record["sha256"])].append(record)
    return groups


def _mark_duplicates(records: list[dict[str, Any]]) -> None:
    for digest, group in _groups_by_hash(records).items():
        if len(group) < 2:
            continue
        group.sort(key=lambda item: str(item["relative_path"]))
        group_id = f"sha256:{digest}"
        for index, record in enumerate(group):
            record["possible_duplicate_group"] = group_id
            record["recommended_keep"] = index == 0
    by_stem: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        key = Path(str(record["filename"]).lower()).stem
        key = key.replace("2nd-edition", "").replace("second-edition", "").replace("draft", "")
        by_stem[key].append(record)
    for group in by_stem.values():
        hashes = {item["sha256"] for item in group}
        if len(group) > 1 and len(hashes) > 1:
            for record in group:
                record["manual_review"] = True


def _source_family_guess(path: Path) -> str:
    name = path.name.lower()
    if is_attack_json_filename(path.name):
        return "mitre_attack"
    if "owasp" in name:
        return "owasp"
    if "nist" in name or "sp800" in name or "800-115" in name:
        return "nist"
    if "kubernetes" in name or "k8s" in name:
        return "kubernetes"
    if _has_token(name, "cis"):
        return "cis"
    if _has_token(name, "cisa") or _has_token(name, "nsa"):
        return "cisa_nsa"
    return "unknown"


def _publisher_guess(filename: str) -> str:
    lower = filename.lower()
    if "owasp" in lower:
        return "OWASP"
    if "nist" in lower or "sp800" in lower or "800-115" in lower:
        return "NIST"
    if "mitre" in lower or lower in {"enterprise-attack.json", "mobile-attack.json", "ics-attack.json"}:
        return "MITRE"
    if _has_token(lower, "cis"):
        return "CIS"
    if _has_token(lower, "cisa") or _has_token(lower, "nsa"):
        return "NSA/CISA"
    return ""


def _provenance_flags(path: Path, detected_type: str) -> list[str]:
    lower = path.name.lower()
    flags: list[str] = []
    if detected_type == "html" and any(token in lower for token in ("temporarily-unavailable", "researchgate")):
        flags.append("junk_html")
    if is_attack_json_filename(path.name):
        flags.append("official_taxonomy_json")
    if (
        any(token in lower for token in ("owasp", "nist", "sp800", "ptes", "kubernetes"))
        or _has_token(lower, "cis")
        or _has_token(lower, "cisa")
        or _has_token(lower, "nsa")
    ):
        flags.append("public_or_standard_candidate")
    if detected_type in {"pdf", "epub"} and "public_or_standard_candidate" not in flags:
        flags.append("unknown_commercial_or_proprietary")
    return flags


def _default_license_status(flags: list[str]) -> str:
    if "unknown_commercial_or_proprietary" in flags:
        return "unknown_commercial_or_proprietary"
    if "official_taxonomy_json" in flags or "public_or_standard_candidate" in flags:
        return "public_or_open_candidate"
    return "unknown"


def _iso_timestamp(value: float) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()


def _has_token(value: str, token: str) -> bool:
    tokens = [item for item in re.split(r"[^a-z0-9]+", value.lower()) if item]
    return token in tokens


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True))
            handle.write("\n")


def _write_csv(path: Path, records: list[dict[str, Any]]) -> None:
    if not records:
        path.write_text("", encoding="utf-8")
        return
    fieldnames = list(records[0].keys())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for record in records:
            writer.writerow({key: json.dumps(value) if isinstance(value, (list, dict)) else value for key, value in record.items()})
