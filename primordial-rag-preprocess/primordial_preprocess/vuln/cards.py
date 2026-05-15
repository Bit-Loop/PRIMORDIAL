from __future__ import annotations

from typing import Any

from .hashing import payload_hash, stable_id
from .models import ReferenceRecord, VulnerabilityIntelCard, VulnerabilityRecord
from .relevance import domains_for_record, should_embed_record
from .utils import unique


CARD_TYPES = [
    "vuln_summary",
    "affected_asset_mapping",
    "severity_context",
    "exploitability_signal",
    "remediation",
    "detection_context",
    "report_context",
    "methodology_hint",
    "reference_index",
]


def cards_for_record(record: VulnerabilityRecord, *, embed_all: bool = False) -> list[VulnerabilityIntelCard]:
    if record.rejected:
        card_types = ["vuln_summary", "reference_index"]
    elif should_embed_record(record, embed_all=embed_all):
        card_types = list(CARD_TYPES)
    else:
        card_types = ["vuln_summary", "reference_index"]
    return [_card_for_type(record, card_type) for card_type in card_types]


def card_to_rag_chunk(card: VulnerabilityIntelCard, *, source_sha256: str | None = None, chunk_index: int = 0) -> dict[str, Any]:
    cve_id = card.cve_id or ""
    aliases = card.aliases
    ghsa_ids = [alias for alias in aliases if alias.startswith("GHSA-")]
    osv_ids = [alias for alias in aliases if alias and not alias.startswith("CVE-") and not alias.startswith("GHSA-")]
    packages = [pkg.model_dump(mode="json") for pkg in card.affected_packages]
    metadata = {
        "domain": "vuln_intel",
        "corpus_type": "vuln_intel",
        "domains": card.domains,
        "vuln_id": card.vuln_id,
        "cve_id": cve_id,
        "ghsa_ids": ghsa_ids,
        "osv_ids": osv_ids,
        "aliases": aliases,
        "alias": aliases,
        "card_type": card.card_type,
        "source_priority": str(card.source_priority),
        "kev": bool(card.kev.get("known_exploited")),
        "epss_probability": card.epss.probability if card.epss else None,
        "epss_percentile": card.epss.percentile if card.epss else None,
        "cvss_severity": _max_severity(card),
        "cwe": card.cwe_ids,
        "cwe_ids": card.cwe_ids,
        "affected_products": card.affected_products,
        "affected_packages": packages,
        "package": unique(pkg.name for pkg in card.affected_packages if pkg.name),
        "ecosystem": unique(pkg.ecosystem for pkg in card.affected_packages if pkg.ecosystem),
        "purl": unique(pkg.purl for pkg in card.affected_packages if pkg.purl),
        "affected_versions": card.affected_versions,
        "fixed_versions": card.fixed_versions,
        "fixed_version_known": bool(card.fixed_versions),
        "output_mode": card.allowed_output_modes,
        "blocked_output_modes": card.blocked_output_modes,
        "safety_level": "safe_planning",
        "planner_visibility": "normal",
        "hint_policy": "advisory",
        "content_hash": card.content_hash,
        "embedding_policy": card.embedding_policy,
        "source_refs": [ref.model_dump(mode="json") for ref in card.source_refs],
    }
    return {
        "chunk_id": card.card_id,
        "doc_id": card.vuln_id,
        "source_file": f"{card.vuln_id}.vuln-intel-card",
        "source_sha256": source_sha256 or card.content_hash,
        "source_type": "vulnerability_intel_card",
        "domain": "vuln_intel",
        "secondary_domains": [domain for domain in card.domains if domain != "vuln_intel"],
        "title": card.title,
        "section": card.card_type,
        "chunk_index": chunk_index,
        "chunk_type": "vulnerability_intel_card",
        "retrieval_text": card.retrieval_text,
        "raw_text": card.retrieval_text,
        "requires_authorized_scope": True,
        "allowed_use_modes": [
            "authorized_bug_bounty",
            "ctf",
            "local_lab",
            "defensive_assessment",
            "academic_study",
        ],
        "metadata": metadata,
        "authority_level": "official_taxonomy" if "kev" in [ref.source for ref in card.source_refs] else "vendor_primary",
        "risk_level": "safe_planning",
        "planner_visibility": "normal",
        "scope_gate_required": True,
        "requires_operator_approval": False,
        "token_estimate": max(1, len(card.retrieval_text.split())),
    }


def _card_for_type(record: VulnerabilityRecord, card_type: str) -> VulnerabilityIntelCard:
    text = _retrieval_text(record, card_type)
    content_hash = payload_hash(
        {
            "vuln_id": record.vuln_id,
            "card_type": card_type,
            "text": text,
            "sources": record.sources,
            "safety": record.blocked_output_modes,
        }
    )
    return VulnerabilityIntelCard(
        card_id=stable_id("vuln_card", record.vuln_id, card_type, content_hash[:16], length=28),
        vuln_id=record.vuln_id,
        cve_id=record.cve_id,
        aliases=record.aliases,
        card_type=card_type,  # type: ignore[arg-type]
        title=f"{record.cve_id or record.vuln_id} {card_type.replace('_', ' ')}".strip(),
        retrieval_text=text,
        domains=domains_for_record(record),
        affected_products=record.affected_products,
        affected_packages=record.affected_packages,
        affected_versions=record.affected_versions,
        fixed_versions=record.fixed_versions,
        cwe_ids=record.cwe_ids,
        cvss=record.cvss,
        kev=record.kev,
        epss=record.epss,
        source_refs=_source_refs(record),
        confidence=record.confidence,
        safety_notes=[
            "Use for defensive triage, patch prioritization, reporting, detection context, and authorized methodology hints only.",
            "Do not use CVE, KEV, EPSS, or ATT&CK data to create executable actions or expand scope.",
        ],
        allowed_output_modes=record.allowed_output_modes,
        blocked_output_modes=record.blocked_output_modes,
        source_priority=record.source_priority,
        content_hash=content_hash,
        embedding_policy="embed_if_relevant",
    )


def _retrieval_text(record: VulnerabilityRecord, card_type: str) -> str:
    cvss = "; ".join(
        f"{metric.version} {metric.severity} {metric.base_score} {metric.vector}".strip()
        for metric in record.cvss
    )
    packages = "; ".join(
        f"{pkg.ecosystem}:{pkg.name} affected={','.join(pkg.affected_versions) or 'range'} fixed={','.join(pkg.fixed_versions) or 'unknown'}"
        for pkg in record.affected_packages
    )
    refs = "; ".join(ref.url for ref in _source_refs(record)[:12])
    epss = ""
    if record.epss:
        epss = f"EPSS probability={record.epss.probability} percentile={record.epss.percentile} score_date={record.epss.score_date}"
    kev = f"KEV={bool(record.kev.get('known_exploited'))}"
    return "\n".join(
        [
            f"Card type: {card_type}",
            f"Vulnerability: {record.cve_id or record.vuln_id}",
            f"Aliases: {', '.join(record.aliases) or 'none'}",
            f"Summary: {record.description or record.title}",
            f"Affected vendors/products/packages: {', '.join(record.affected_vendors + record.affected_products) or 'unknown'} {packages}",
            f"Affected versions: {', '.join(record.affected_versions) or 'unknown'}",
            f"Fixed versions: {', '.join(record.fixed_versions) or 'unknown'}",
            f"Weaknesses: {', '.join(record.cwe_ids) or 'unknown'}",
            f"Severity: {cvss or 'unknown'}",
            f"Exploitability signals: {kev}; {epss or 'EPSS unavailable'}",
            f"Remediation: prefer vendor fixed versions, patches, workarounds, and advisory references when present.",
            f"Detection context: use CWE, product, package, CPE/PURL, KEV, and advisory facts for defensive review.",
            f"References: {refs or 'none'}",
            "Safe use: defensive triage, report context, patch prioritization, authorized methodology hints.",
            "Blocked use: exploit execution, payload generation, scope expansion, autonomous scanning, persistence, evasion, credential theft.",
        ]
    )


def _source_refs(record: VulnerabilityRecord) -> list[ReferenceRecord]:
    refs = [*record.references, *record.patch_references, *record.advisory_references]
    seen: set[str] = set()
    out: list[ReferenceRecord] = []
    for ref in refs:
        if ref.url in seen:
            continue
        seen.add(ref.url)
        out.append(ref)
    return out


def _max_severity(card: VulnerabilityIntelCard) -> str:
    order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    severities = [metric.severity.upper() for metric in card.cvss if metric.severity]
    return sorted(severities, key=lambda item: order.get(item, 0), reverse=True)[0] if severities else ""
