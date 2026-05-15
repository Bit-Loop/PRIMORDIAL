from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from .events import build_event
from .hashing import payload_hash
from .models import EpssSignal, VulnerabilityRecord, VulnEvent


def parse_epss_row(row: dict[str, Any], *, raw_ref: str = "") -> VulnerabilityRecord:
    cve_id = str(row.get("cve") or row.get("CVE") or "").upper()
    epss = _float(row.get("epss"))
    percentile = _float(row.get("percentile"))
    date = str(row.get("date") or row.get("score_date") or "")
    return VulnerabilityRecord(
        vuln_id=cve_id,
        cve_id=cve_id,
        aliases=[cve_id] if cve_id else [],
        sources=["epss"],
        source_priority=3,
        title=cve_id,
        epss=EpssSignal(probability=epss, percentile=percentile, score_date=date),
        raw_by_source={"epss": {"raw_ref": raw_ref, "payload_hash": payload_hash(row)}},
        provenance=[{"source": "epss", "raw_ref": raw_ref, "payload_hash": payload_hash(row)}],
        confidence=0.8,
    )


def event_for_epss_row(row: dict[str, Any], *, raw_ref: str = "", jump_threshold: float = 0.10) -> VulnEvent:
    cve_id = str(row.get("cve") or row.get("CVE") or "").upper()
    event_type = "epss.jump" if _float(row.get("delta")) >= jump_threshold else "epss.updated"
    return build_event(
        source_name="epss",
        event_type=event_type,
        source_record_id=cve_id or payload_hash(row),
        payload=row,
        vuln_ids=[cve_id] if cve_id else [],
        aliases=[cve_id] if cve_id else [],
        raw_ref=raw_ref,
        occurred_at=str(row.get("date") or row.get("score_date") or "") or None,
    )


def load_epss_csv(path: Path | str) -> tuple[list[VulnEvent], list[VulnerabilityRecord]]:
    source = Path(path)
    rows = list(csv.DictReader(line for line in source.read_text(encoding="utf-8").splitlines() if not line.startswith("#")))
    events = [event_for_epss_row(row, raw_ref=str(source)) for row in rows]
    records = [parse_epss_row(row, raw_ref=str(source)) for row in rows]
    return events, records


def _float(value: object) -> float | None:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None
