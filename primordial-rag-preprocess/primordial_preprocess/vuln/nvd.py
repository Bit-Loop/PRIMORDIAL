from __future__ import annotations

from typing import Any

from .events import build_event
from .hashing import payload_hash, stable_id
from .models import CvssMetric, ReferenceRecord, VulnerabilityRecord, VulnEvent
from .utils import extract_cwe_ids, unique, upper_ids


def parse_nvd_vulnerability(payload: dict[str, Any], *, raw_ref: str = "") -> VulnerabilityRecord:
    vuln = payload.get("cve") if isinstance(payload.get("cve"), dict) else payload
    cve_id = str(vuln.get("id") or "").upper() or None
    descriptions = vuln.get("descriptions") if isinstance(vuln.get("descriptions"), list) else []
    references = vuln.get("references", {}).get("referenceData", []) if isinstance(vuln.get("references"), dict) else vuln.get("references", [])
    weaknesses = vuln.get("weaknesses") if isinstance(vuln.get("weaknesses"), list) else []
    configurations = vuln.get("configurations") if isinstance(vuln.get("configurations"), list) else []
    metrics = vuln.get("metrics") if isinstance(vuln.get("metrics"), dict) else {}
    cpes = _cpe_matches(configurations)
    cvss = _cvss_metrics(metrics)
    aliases = upper_ids([cve_id])
    return VulnerabilityRecord(
        vuln_id=cve_id or stable_id("vuln", payload_hash(payload), length=20),
        cve_id=cve_id,
        aliases=aliases,
        sources=["nvd"],
        source_priority=4,
        title=cve_id or "",
        description=_localized_value(descriptions),
        published_at=str(vuln.get("published") or "") or None,
        modified_at=str(vuln.get("lastModified") or "") or None,
        affected_cpes=cpes,
        cwe_ids=extract_cwe_ids(str(weaknesses)),
        cvss=cvss,
        references=[
            ReferenceRecord(
                url=str(item.get("url") or ""),
                source="nvd",
                tags=[str(tag) for tag in item.get("tags", []) if tag] if isinstance(item, dict) else [],
            )
            for item in references
            if isinstance(item, dict) and item.get("url")
        ],
        raw_by_source={"nvd": {"raw_ref": raw_ref, "payload_hash": payload_hash(payload)}},
        provenance=[{"source": "nvd", "raw_ref": raw_ref, "payload_hash": payload_hash(payload)}],
        confidence=0.86,
    )


def event_for_nvd(payload: dict[str, Any], *, raw_ref: str = "") -> VulnEvent:
    vuln = payload.get("cve") if isinstance(payload.get("cve"), dict) else payload
    cve_id = str(vuln.get("id") or "").upper()
    return build_event(
        source_name="nvd",
        event_type="nvd.enriched",
        source_record_id=cve_id or raw_ref or payload_hash(payload),
        payload=payload,
        vuln_ids=[cve_id] if cve_id else [],
        aliases=[cve_id] if cve_id else [],
        raw_ref=raw_ref,
        occurred_at=str(vuln.get("lastModified") or "") or None,
    )


def _localized_value(rows: list[Any]) -> str:
    for row in rows:
        if isinstance(row, dict) and str(row.get("lang") or "").lower() == "en" and row.get("value"):
            return str(row["value"])
    return ""


def _cvss_metrics(metrics: dict[str, Any]) -> list[CvssMetric]:
    out: list[CvssMetric] = []
    for key, version in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        for item in metrics.get(key, []) or []:
            if not isinstance(item, dict):
                continue
            data = item.get("cvssData") if isinstance(item.get("cvssData"), dict) else {}
            out.append(
                CvssMetric(
                    version=version,
                    vector=str(data.get("vectorString") or ""),
                    base_score=float(data["baseScore"]) if isinstance(data.get("baseScore"), int | float) else None,
                    severity=str(item.get("baseSeverity") or data.get("baseSeverity") or ""),
                    source="nvd",
                )
            )
    return out


def _cpe_matches(configurations: list[Any]) -> list[str]:
    values: list[str] = []
    stack = list(configurations)
    while stack:
        item = stack.pop()
        if not isinstance(item, dict):
            continue
        stack.extend(item.get("nodes", []) or [])
        for match in item.get("cpeMatch", []) or []:
            if isinstance(match, dict) and match.get("criteria"):
                values.append(str(match["criteria"]))
    return unique(values)
