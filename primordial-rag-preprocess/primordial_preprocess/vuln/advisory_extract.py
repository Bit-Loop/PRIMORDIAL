from __future__ import annotations

import re
from pathlib import Path

from .hashing import sha256_text, stable_id
from .io import write_json
from .models import AdvisoryDocRecord, AdvisoryExtractedFacts
from .utils import extract_cve_ids, extract_cvss_vectors, extract_cwe_ids, extract_ghsa_ids, unique


SECTION_MARKERS = {
    "remediation_steps": ("remediation", "patched", "fixed", "upgrade", "update"),
    "mitigation_steps": ("mitigation", "workaround", "work around"),
    "detection_notes": ("detection", "detect", "indicator", "ioc"),
}


def extract_advisory_facts(text: str, *, title: str = "", publisher: str = "") -> AdvisoryExtractedFacts:
    cve_ids = extract_cve_ids(text)
    ghsa_ids = extract_ghsa_ids(text)
    osv_ids = unique(re.findall(r"\b(?:OSV|PYSEC|RUSTSEC|GO)-[A-Za-z0-9_.:-]+\b", text or "", flags=re.IGNORECASE))
    facts = AdvisoryExtractedFacts(
        advisory_title=title,
        publisher=publisher,
        cve_ids=cve_ids,
        ghsa_ids=ghsa_ids,
        osv_ids=[item.upper() for item in osv_ids],
        cwe_ids=extract_cwe_ids(text),
        cvss_vectors=extract_cvss_vectors(text),
        affected_versions=_line_values(text, ("affected", "vulnerable")),
        fixed_versions=_line_values(text, ("fixed", "patched", "resolved")),
        references=unique(re.findall(r"https?://[^\s)>\"]+", text or "")),
        confidence_notes=["deterministic_regex_heading_extraction"],
    )
    for attr, markers in SECTION_MARKERS.items():
        setattr(facts, attr, _section_lines(text, markers))
    facts.exploit_status_claims = _line_values(text, ("exploited", "exploit", "weaponized"))
    return facts


def process_markdown_advisory(path: Path | str, output_root: Path | str, *, publisher: str = "") -> tuple[AdvisoryDocRecord, AdvisoryExtractedFacts, list[dict[str, object]]]:
    source = Path(path)
    text = source.read_text(encoding="utf-8", errors="replace")
    digest = _sha256_file(source)
    title = _title(text) or source.stem
    advisory_id = stable_id("advisory", digest, source.name, length=24)
    facts = extract_advisory_facts(text, title=title, publisher=publisher)
    out = Path(output_root) / "vuln" / "advisories"
    markdown_path = out / "markdown" / f"{advisory_id}.md"
    facts_path = out / "extracted_facts" / f"{advisory_id}.facts.json"
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.write_text(text, encoding="utf-8")
    write_json(facts_path, facts)
    chunks = _advisory_chunks(text, advisory_id=advisory_id, source=source, source_sha256=digest, facts=facts)
    doc = AdvisoryDocRecord(
        advisory_doc_id=advisory_id,
        source_file=source.name,
        source_sha256=digest,
        source_type="markdown",
        publisher=publisher,
        title=title,
        markdown_path=str(markdown_path),
        cve_ids=facts.cve_ids,
        ghsa_ids=facts.ghsa_ids,
        osv_ids=facts.osv_ids,
        extracted_facts_path=str(facts_path),
        chunk_count=len(chunks),
        confidence=0.7,
    )
    return doc, facts, chunks


def _advisory_chunks(
    text: str,
    *,
    advisory_id: str,
    source: Path,
    source_sha256: str,
    facts: AdvisoryExtractedFacts,
) -> list[dict[str, object]]:
    blocks = [block.strip() for block in re.split(r"\n\s*\n", text) if block.strip()]
    chunks: list[dict[str, object]] = []
    pending: list[str] = []
    for block in blocks:
        if sum(len(item) for item in pending) + len(block) > 3600 and pending:
            chunks.append(_chunk("\n\n".join(pending), advisory_id, source, source_sha256, len(chunks), facts))
            pending.clear()
        pending.append(block)
    if pending:
        chunks.append(_chunk("\n\n".join(pending), advisory_id, source, source_sha256, len(chunks), facts))
    return chunks


def _chunk(text: str, advisory_id: str, source: Path, source_sha256: str, index: int, facts: AdvisoryExtractedFacts) -> dict[str, object]:
    chunk_id = stable_id("advisory_chunk", advisory_id, index, sha256_text(text)[:16], length=28)
    return {
        "chunk_id": chunk_id,
        "doc_id": advisory_id,
        "source_file": source.name,
        "source_sha256": source_sha256,
        "source_type": "vendor_advisory_markdown",
        "domain": "vuln_intel",
        "secondary_domains": ["cve_advisory"],
        "title": facts.advisory_title or source.stem,
        "section": "vendor_advisory",
        "chunk_index": index,
        "chunk_type": "vendor_advisory_chunk",
        "retrieval_text": text,
        "raw_text": text,
        "requires_authorized_scope": True,
        "metadata": {
            "domain": "vuln_intel",
            "corpus_type": "vuln_intel",
            "card_type": "vendor_advisory",
            "cve_id": facts.cve_ids[0] if facts.cve_ids else "",
            "aliases": [*facts.cve_ids, *facts.ghsa_ids, *facts.osv_ids],
            "cwe": facts.cwe_ids,
            "source_kind": "vendor_advisory",
            "hint_policy": "advisory",
            "planner_visibility": "normal",
            "output_mode": ["vuln_triage", "patch_prioritization", "defensive_detection_context", "report_context"],
        },
        "risk_level": "safe_planning",
        "planner_visibility": "normal",
        "scope_gate_required": True,
        "requires_operator_approval": False,
        "token_estimate": max(1, len(text.split())),
    }


def _line_values(text: str, markers: tuple[str, ...]) -> list[str]:
    values: list[str] = []
    for line in (text or "").splitlines():
        lowered = line.lower()
        if any(marker in lowered for marker in markers):
            clean = line.strip(" -*\t")
            if clean:
                values.append(clean[:500])
    return unique(values[:20])


def _section_lines(text: str, markers: tuple[str, ...]) -> list[str]:
    lines = (text or "").splitlines()
    captured: list[str] = []
    active = False
    for line in lines:
        stripped = line.strip()
        lowered = stripped.lower().strip("# ")
        if stripped.startswith("#"):
            active = any(marker in lowered for marker in markers)
            continue
        if active and stripped:
            captured.append(stripped[:500])
        if len(captured) >= 20:
            break
    return unique(captured)


def _title(text: str) -> str:
    for line in text.splitlines():
        if line.startswith("#"):
            return line.strip("# ").strip()
    return ""


def _sha256_file(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
