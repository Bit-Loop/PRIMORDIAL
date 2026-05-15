from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .advisory_docling import process_advisory_document
from .cards import cards_for_record
from .cvelist_v5 import event_for_cve_v5, parse_cve_v5
from .epss import event_for_epss_row, parse_epss_row
from .export import advisory_records, write_vuln_outputs
from .ghsa import event_for_ghsa, parse_ghsa
from .kev import load_kev_records
from .merge import merge_records
from .nvd import event_for_nvd, parse_nvd_vulnerability
from .osv import event_for_osv, parse_osv


def run_vuln_stream(
    *,
    raw_dir: Path | str,
    output_dir: Path | str,
    only: str | None = None,
    embed_all: bool = False,
    allow_ocr: bool = False,
) -> dict[str, Any]:
    raw = Path(raw_dir)
    events = []
    records = []
    advisory_docs = []
    advisory_facts = []
    advisory_chunks = []

    if only in {None, "structured", "cve"}:
        for path in sorted((raw / "structured" / "cve_v5").rglob("*.json")) if (raw / "structured" / "cve_v5").exists() else []:
            payload = _json(path)
            events.append(event_for_cve_v5(payload, raw_ref=str(path)))
            records.append(parse_cve_v5(payload, raw_ref=str(path)))

    if only in {None, "structured", "nvd"}:
        for path in sorted((raw / "structured" / "nvd").rglob("*.json")) if (raw / "structured" / "nvd").exists() else []:
            payload = _json(path)
            rows = payload.get("vulnerabilities", [payload]) if isinstance(payload, dict) else []
            for row in rows:
                if isinstance(row, dict):
                    events.append(event_for_nvd(row, raw_ref=str(path)))
                    records.append(parse_nvd_vulnerability(row, raw_ref=str(path)))

    if only in {None, "structured", "osv"}:
        for path in sorted((raw / "structured" / "osv").rglob("*.json")) if (raw / "structured" / "osv").exists() else []:
            payload = _json(path)
            events.append(event_for_osv(payload, raw_ref=str(path)))
            records.append(parse_osv(payload, raw_ref=str(path)))

    if only in {None, "structured", "ghsa"}:
        for path in sorted((raw / "structured" / "ghsa").rglob("*.json")) if (raw / "structured" / "ghsa").exists() else []:
            payload = _json(path)
            events.append(event_for_ghsa(payload, raw_ref=str(path)))
            records.append(parse_ghsa(payload, raw_ref=str(path)))

    if only in {None, "structured", "kev"}:
        kev_dir = raw / "structured" / "kev"
        if kev_dir.exists():
            for path in sorted([*kev_dir.rglob("*.json"), *kev_dir.rglob("*.csv")]):
                source_events, source_records = load_kev_records(path)
                events.extend(source_events)
                records.extend(source_records)

    if only in {None, "structured", "epss"}:
        epss_dir = raw / "structured" / "epss"
        if epss_dir.exists():
            import csv

            for path in sorted(epss_dir.rglob("*.csv")):
                rows = list(csv.DictReader(line for line in path.read_text(encoding="utf-8").splitlines() if not line.startswith("#")))
                for row in rows:
                    events.append(event_for_epss_row(row, raw_ref=str(path)))
                    records.append(parse_epss_row(row, raw_ref=str(path)))

    if only in {None, "advisories"}:
        for base in [raw / "advisories" / "markdown", raw / "advisories" / "html", raw / "advisories" / "pdf", raw / "advisories" / "vendor_bulletins"]:
            if not base.exists():
                continue
            for path in sorted(item for item in base.rglob("*") if item.is_file()):
                doc, facts, chunks = process_advisory_document(path, output_dir, allow_ocr=allow_ocr)
                advisory_docs.append(doc)
                advisory_facts.append(facts)
                advisory_chunks.extend(chunks)
    records.extend(advisory_records(advisory_docs, advisory_facts))
    merged = merge_records([record for record in records if record.vuln_id])
    cards = [card for record in merged for card in cards_for_record(record, embed_all=embed_all)]
    manifest = write_vuln_outputs(
        output_dir,
        events=events,
        records=merged,
        cards=cards,
        advisory_docs=advisory_docs,
        advisory_facts=advisory_facts,
        advisory_chunks=advisory_chunks,
    )
    return manifest


def _json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"JSON payload is not an object: {path}")
    return payload
