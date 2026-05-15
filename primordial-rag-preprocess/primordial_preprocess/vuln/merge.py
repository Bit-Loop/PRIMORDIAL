from __future__ import annotations

from collections import defaultdict
import json
from typing import Any

from .models import (
    AffectedPackage,
    CvssMetric,
    EpssSignal,
    ReferenceRecord,
    VulnerabilityRecord,
)
from .utils import unique


def merge_records(records: list[VulnerabilityRecord]) -> list[VulnerabilityRecord]:
    groups: dict[str, list[VulnerabilityRecord]] = defaultdict(list)
    alias_to_key: dict[str, str] = {}
    for record in records:
        key = _group_key(record)
        existing = next((alias_to_key[alias] for alias in [key, *record.aliases] if alias in alias_to_key), key)
        for alias in [key, *record.aliases]:
            alias_to_key[alias] = existing
        groups[existing].append(record)
    return [_merge_group(items) for items in groups.values()]


def _group_key(record: VulnerabilityRecord) -> str:
    for value in [record.cve_id, *record.aliases, record.vuln_id]:
        if value:
            text = str(value).upper()
            if text.startswith("CVE-"):
                return text
    for value in [*record.aliases, record.vuln_id]:
        if value:
            text = str(value).upper()
            if text.startswith("GHSA-"):
                return text
    return str(record.vuln_id).upper()


def _merge_group(records: list[VulnerabilityRecord]) -> VulnerabilityRecord:
    records = sorted(records, key=lambda item: (-item.source_priority, item.vuln_id))
    base = records[0].model_copy(deep=True)
    aliases = unique(alias.upper() for record in records for alias in [record.cve_id, record.vuln_id, *record.aliases] if alias)
    base.cve_id = next((alias for alias in aliases if alias.startswith("CVE-")), base.cve_id)
    base.vuln_id = base.cve_id or aliases[0] if aliases else base.vuln_id
    base.aliases = aliases
    base.sources = unique(source for record in records for source in record.sources)
    base.title = _merge_scalar("title", records, base.conflicts)
    base.description = _merge_scalar("description", records, base.conflicts)
    base.published_at = _earliest(record.published_at for record in records)
    base.modified_at = _latest(record.modified_at for record in records)
    base.withdrawn_at = _latest(record.withdrawn_at for record in records)
    base.rejected = any(record.rejected for record in records)
    base.affected_vendors = unique(value for record in records for value in record.affected_vendors)
    base.affected_products = unique(value for record in records for value in record.affected_products)
    base.affected_components = unique(value for record in records for value in record.affected_components)
    base.affected_packages = _dedupe_models([pkg for record in records for pkg in record.affected_packages], AffectedPackage)
    base.affected_cpes = unique(value for record in records for value in record.affected_cpes)
    base.affected_purls = unique(value for record in records for value in record.affected_purls)
    base.affected_versions = unique(value for record in records for value in record.affected_versions)
    base.fixed_versions = unique(value for record in records for value in record.fixed_versions)
    base.cwe_ids = unique(value.upper() for record in records for value in record.cwe_ids)
    base.cvss = _dedupe_models([metric for record in records for metric in record.cvss], CvssMetric)
    base.kev = next((record.kev for record in records if record.kev.get("known_exploited")), base.kev)
    base.epss = _best_epss(record.epss for record in records)
    base.references = _dedupe_models([ref for record in records for ref in record.references], ReferenceRecord)
    base.exploit_references = _dedupe_models([ref for record in records for ref in record.exploit_references], ReferenceRecord)
    base.patch_references = _dedupe_models([ref for record in records for ref in record.patch_references], ReferenceRecord)
    base.advisory_references = _dedupe_models([ref for record in records for ref in record.advisory_references], ReferenceRecord)
    base.risk_tags = unique(value for record in records for value in record.risk_tags)
    base.methodology_tags = unique(value for record in records for value in record.methodology_tags)
    base.raw_by_source = {source: payload for record in records for source, payload in record.raw_by_source.items()}
    base.provenance = [entry for record in records for entry in record.provenance]
    base.confidence = max(record.confidence for record in records)
    return base


def _merge_scalar(field: str, records: list[VulnerabilityRecord], conflicts: list[dict[str, Any]]) -> str:
    values = unique(getattr(record, field) for record in records if getattr(record, field))
    if len(values) > 1:
        conflicts.append({"field": field, "values": values})
    return values[0] if values else ""


def _earliest(values) -> str | None:
    clean = sorted(str(value) for value in values if value)
    return clean[0] if clean else None


def _latest(values) -> str | None:
    clean = sorted(str(value) for value in values if value)
    return clean[-1] if clean else None


def _best_epss(values) -> EpssSignal | None:
    clean = [value for value in values if value is not None]
    if not clean:
        return None
    return sorted(clean, key=lambda item: item.score_date or "")[-1]


def _dedupe_models(values: list[Any], _model_type: type) -> list[Any]:
    seen: set[str] = set()
    out: list[Any] = []
    for value in values:
        key = json.dumps(value.model_dump(mode="json"), sort_keys=True) if hasattr(value, "model_dump") else str(value)
        if key in seen:
            continue
        seen.add(key)
        out.append(value)
    return out
