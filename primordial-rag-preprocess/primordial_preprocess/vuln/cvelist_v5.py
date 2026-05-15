from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from .events import build_event
from .hashing import payload_hash, stable_id
from .models import ReferenceRecord, VulnerabilityRecord, VulnEvent
from .utils import extract_cve_ids, extract_cwe_ids, first_text, unique, upper_ids


def parse_cve_v5(payload: dict[str, Any], *, raw_ref: str = "") -> VulnerabilityRecord:
    metadata = payload.get("cveMetadata") if isinstance(payload.get("cveMetadata"), dict) else {}
    containers = payload.get("containers") if isinstance(payload.get("containers"), dict) else {}
    cna = containers.get("cna") if isinstance(containers.get("cna"), dict) else {}
    cve_id = str(metadata.get("cveId") or "").upper() or None
    aliases = upper_ids([cve_id, *extract_cve_ids(json.dumps(payload, sort_keys=True))])
    descriptions = cna.get("descriptions") if isinstance(cna.get("descriptions"), list) else []
    title = first_text([cna.get("title"), metadata.get("assignerShortName"), cve_id])
    description = _localized_value(descriptions)
    affected = cna.get("affected") if isinstance(cna.get("affected"), list) else []
    references = cna.get("references") if isinstance(cna.get("references"), list) else []
    problem_types = cna.get("problemTypes") if isinstance(cna.get("problemTypes"), list) else []
    rejected = str(metadata.get("state") or "").upper() == "REJECTED"
    return VulnerabilityRecord(
        vuln_id=cve_id or stable_id("vuln", payload_hash(payload), length=20),
        cve_id=cve_id,
        aliases=aliases,
        sources=["cvelist_v5"],
        source_priority=5,
        title=title,
        description=description,
        published_at=str(metadata.get("datePublished") or "") or None,
        modified_at=str(metadata.get("dateUpdated") or metadata.get("dateReserved") or "") or None,
        rejected=rejected,
        affected_vendors=unique(item.get("vendor") for item in affected if isinstance(item, dict)),
        affected_products=unique(item.get("product") for item in affected if isinstance(item, dict)),
        affected_versions=_affected_versions(affected),
        cwe_ids=extract_cwe_ids(json.dumps(problem_types, sort_keys=True)),
        references=[
            ReferenceRecord(
                url=str(item.get("url") or ""),
                source="cvelist_v5",
                tags=[str(tag) for tag in item.get("tags", []) if tag] if isinstance(item, dict) else [],
            )
            for item in references
            if isinstance(item, dict) and item.get("url")
        ],
        raw_by_source={"cvelist_v5": {"raw_ref": raw_ref, "payload_hash": payload_hash(payload)}},
        provenance=[{"source": "cvelist_v5", "raw_ref": raw_ref, "payload_hash": payload_hash(payload)}],
        confidence=0.9,
    )


def event_for_cve_v5(payload: dict[str, Any], *, raw_ref: str = "") -> VulnEvent:
    metadata = payload.get("cveMetadata") if isinstance(payload.get("cveMetadata"), dict) else {}
    cve_id = str(metadata.get("cveId") or "").upper()
    state = str(metadata.get("state") or "").upper()
    event_type = "cve.rejected" if state == "REJECTED" else "cve.updated"
    return build_event(
        source_name="cvelist_v5",
        event_type=event_type,
        source_record_id=cve_id or raw_ref or payload_hash(payload),
        payload=payload,
        vuln_ids=[cve_id] if cve_id else [],
        aliases=[cve_id] if cve_id else [],
        raw_ref=raw_ref,
        occurred_at=str(metadata.get("dateUpdated") or metadata.get("datePublished") or "") or None,
    )


def changed_cve_files(repo_path: Path | str, *, last_seen_commit: str = "", history_start_year: int = 2020) -> tuple[str, list[Path]]:
    repo = Path(repo_path)
    head = _git(repo, "rev-parse", "HEAD").strip()
    if last_seen_commit:
        names = _git(repo, "diff", "--name-only", f"{last_seen_commit}..{head}", "--", "cves").splitlines()
        files = [repo / name for name in names if name.endswith(".json") and (repo / name).is_file()]
        return head, sorted(files)
    root = repo / "cves"
    files = []
    if root.exists():
        for path in root.rglob("*.json"):
            try:
                year = int(path.relative_to(root).parts[0])
            except (ValueError, IndexError):
                year = history_start_year
            if year >= history_start_year:
                files.append(path)
    return head, sorted(files)


def records_from_files(paths: list[Path]) -> tuple[list[VulnEvent], list[VulnerabilityRecord]]:
    events: list[VulnEvent] = []
    records: list[VulnerabilityRecord] = []
    for path in paths:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            continue
        raw_ref = str(path)
        events.append(event_for_cve_v5(payload, raw_ref=raw_ref))
        records.append(parse_cve_v5(payload, raw_ref=raw_ref))
    return events, records


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)
    return result.stdout


def _localized_value(rows: list[Any]) -> str:
    for preferred in ("en", "eng"):
        for row in rows:
            if isinstance(row, dict) and str(row.get("lang") or "").lower() == preferred and row.get("value"):
                return str(row["value"])
    for row in rows:
        if isinstance(row, dict) and row.get("value"):
            return str(row["value"])
    return ""


def _affected_versions(affected: list[Any]) -> list[str]:
    values: list[str] = []
    for item in affected:
        if not isinstance(item, dict):
            continue
        for version in item.get("versions", []) or []:
            if isinstance(version, dict):
                values.extend([version.get("version"), version.get("lessThan"), version.get("lessThanOrEqual")])
    return unique(value for value in values if value)
