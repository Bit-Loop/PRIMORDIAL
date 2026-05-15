from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from .events import build_event
from .hashing import payload_hash, stable_id
from .models import AffectedPackage, CvssMetric, ReferenceRecord, VulnerabilityRecord, VulnEvent
from .utils import extract_cve_ids, unique, upper_ids


def parse_osv(payload: dict[str, Any], *, raw_ref: str = "", source_name: str = "osv") -> VulnerabilityRecord:
    osv_id = str(payload.get("id") or "").upper()
    aliases = upper_ids([osv_id, *(payload.get("aliases", []) if isinstance(payload.get("aliases"), list) else []), *extract_cve_ids(str(payload))])
    cve_id = next((alias for alias in aliases if alias.startswith("CVE-")), None)
    affected = payload.get("affected") if isinstance(payload.get("affected"), list) else []
    packages = [_affected_package(item) for item in affected if isinstance(item, dict)]
    severity = payload.get("severity") if isinstance(payload.get("severity"), list) else []
    references = payload.get("references") if isinstance(payload.get("references"), list) else []
    return VulnerabilityRecord(
        vuln_id=cve_id or osv_id or stable_id("vuln", payload_hash(payload), length=20),
        cve_id=cve_id,
        aliases=aliases,
        sources=[source_name],
        source_priority=4,
        title=str(payload.get("summary") or osv_id or cve_id or ""),
        description=str(payload.get("details") or payload.get("summary") or ""),
        published_at=str(payload.get("published") or "") or None,
        modified_at=str(payload.get("modified") or "") or None,
        withdrawn_at=str(payload.get("withdrawn") or "") or None,
        affected_packages=packages,
        affected_purls=unique(pkg.purl for pkg in packages if pkg.purl),
        affected_versions=unique(version for pkg in packages for version in pkg.affected_versions),
        fixed_versions=unique(version for pkg in packages for version in pkg.fixed_versions),
        cvss=[
            CvssMetric(version="", vector=str(item.get("score") or ""), severity=str(item.get("type") or ""), source=source_name)
            for item in severity
            if isinstance(item, dict)
        ],
        references=[
            ReferenceRecord(url=str(item.get("url") or ""), source=source_name, tags=[str(item.get("type") or "")])
            for item in references
            if isinstance(item, dict) and item.get("url")
        ],
        raw_by_source={source_name: {"raw_ref": raw_ref, "payload_hash": payload_hash(payload)}},
        provenance=[{"source": source_name, "raw_ref": raw_ref, "payload_hash": payload_hash(payload)}],
        confidence=0.84,
    )


def event_for_osv(payload: dict[str, Any], *, raw_ref: str = "", source_name: str = "osv") -> VulnEvent:
    osv_id = str(payload.get("id") or "").upper()
    aliases = upper_ids([osv_id, *(payload.get("aliases", []) if isinstance(payload.get("aliases"), list) else [])])
    return build_event(
        source_name=source_name,
        event_type="ghsa.updated" if source_name == "ghsa" else "osv.updated",
        source_record_id=osv_id or raw_ref or payload_hash(payload),
        payload=payload,
        vuln_ids=aliases,
        aliases=aliases,
        raw_ref=raw_ref,
        occurred_at=str(payload.get("modified") or "") or None,
    )


def modified_ids_after(path: Path | str, cursor_value: str = "") -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    with Path(path).open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            modified = str(row.get("modified") or row.get("timestamp") or "")
            if cursor_value and modified <= cursor_value:
                break
            rows.append({str(key): str(value) for key, value in row.items()})
    return rows


def _affected_package(item: dict[str, Any]) -> AffectedPackage:
    package = item.get("package") if isinstance(item.get("package"), dict) else {}
    ranges = item.get("ranges") if isinstance(item.get("ranges"), list) else []
    versions = item.get("versions") if isinstance(item.get("versions"), list) else []
    fixed: list[str] = []
    for range_item in ranges:
        if not isinstance(range_item, dict):
            continue
        for event in range_item.get("events", []) or []:
            if isinstance(event, dict) and event.get("fixed"):
                fixed.append(str(event["fixed"]))
    return AffectedPackage(
        ecosystem=str(package.get("ecosystem") or ""),
        name=str(package.get("name") or ""),
        purl=str(package.get("purl") or ""),
        affected_versions=unique(versions),
        ranges=[range_item for range_item in ranges if isinstance(range_item, dict)],
        fixed_versions=unique(fixed),
    )
