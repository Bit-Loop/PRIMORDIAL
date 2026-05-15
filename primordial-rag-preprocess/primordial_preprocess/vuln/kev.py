from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from .events import build_event
from .hashing import payload_hash
from .models import ReferenceRecord, VulnerabilityRecord, VulnEvent
from .utils import extract_cve_ids, unique, upper_ids


def parse_kev_entry(entry: dict[str, Any], *, raw_ref: str = "") -> VulnerabilityRecord:
    cve_id = str(entry.get("cveID") or entry.get("cve_id") or "").upper()
    aliases = upper_ids([cve_id, *extract_cve_ids(str(entry))])
    vendor = str(entry.get("vendorProject") or entry.get("vendor_project") or "")
    product = str(entry.get("product") or "")
    title = str(entry.get("vulnerabilityName") or entry.get("vulnerability_name") or cve_id)
    notes = str(entry.get("notes") or "")
    refs = [ReferenceRecord(url=url, source="kev", tags=["known_exploited"]) for url in _urls(notes)]
    return VulnerabilityRecord(
        vuln_id=cve_id,
        cve_id=cve_id,
        aliases=aliases,
        sources=["kev"],
        source_priority=5,
        title=title,
        description=str(entry.get("shortDescription") or entry.get("short_description") or ""),
        modified_at=str(entry.get("dateAdded") or entry.get("date_added") or "") or None,
        affected_vendors=unique([vendor]),
        affected_products=unique([product]),
        kev={
            "known_exploited": True,
            "date_added": entry.get("dateAdded") or entry.get("date_added"),
            "required_action": entry.get("requiredAction") or entry.get("required_action"),
            "due_date": entry.get("dueDate") or entry.get("due_date"),
            "known_ransomware_campaign_use": entry.get("knownRansomwareCampaignUse")
            or entry.get("known_ransomware_campaign_use"),
            "notes": notes,
        },
        references=refs,
        raw_by_source={"kev": {"raw_ref": raw_ref, "payload_hash": payload_hash(entry)}},
        provenance=[{"source": "kev", "raw_ref": raw_ref, "payload_hash": payload_hash(entry)}],
        confidence=0.92,
    )


def event_for_kev_entry(entry: dict[str, Any], *, raw_ref: str = "") -> VulnEvent:
    cve_id = str(entry.get("cveID") or entry.get("cve_id") or "").upper()
    return build_event(
        source_name="kev",
        event_type="kev.added",
        source_record_id=cve_id or payload_hash(entry),
        payload=entry,
        vuln_ids=[cve_id] if cve_id else [],
        aliases=[cve_id] if cve_id else [],
        raw_ref=raw_ref,
        occurred_at=str(entry.get("dateAdded") or entry.get("date_added") or "") or None,
    )


def load_kev_records(path: Path | str) -> tuple[list[VulnEvent], list[VulnerabilityRecord]]:
    source = Path(path)
    if source.suffix.lower() == ".csv":
        rows = list(csv.DictReader(source.read_text(encoding="utf-8").splitlines()))
    else:
        payload = json.loads(source.read_text(encoding="utf-8"))
        rows = payload.get("vulnerabilities", payload if isinstance(payload, list) else [])
    events: list[VulnEvent] = []
    records: list[VulnerabilityRecord] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        events.append(event_for_kev_entry(row, raw_ref=str(source)))
        records.append(parse_kev_entry(row, raw_ref=str(source)))
    return events, records


def _urls(text: str) -> list[str]:
    import re

    return re.findall(r"https?://[^\s),]+", text or "")
