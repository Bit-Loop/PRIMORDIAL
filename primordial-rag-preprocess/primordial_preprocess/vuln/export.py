from __future__ import annotations

from pathlib import Path
from typing import Any

from .cards import card_to_rag_chunk
from .io import write_json, write_jsonl
from .models import AdvisoryDocRecord, AdvisoryExtractedFacts, ReferenceRecord, VulnerabilityRecord, VulnEvent


def advisory_records(
    docs: list[AdvisoryDocRecord],
    facts: list[AdvisoryExtractedFacts],
) -> list[VulnerabilityRecord]:
    records: list[VulnerabilityRecord] = []
    for doc, fact in zip(docs, facts, strict=False):
        ids = [*fact.cve_ids, *fact.ghsa_ids, *fact.osv_ids]
        for vuln_id in ids:
            records.append(
                VulnerabilityRecord(
                    vuln_id=vuln_id,
                    cve_id=vuln_id if vuln_id.startswith("CVE-") else None,
                    aliases=ids,
                    sources=["vendor_advisory"],
                    source_priority=4,
                    title=fact.advisory_title or doc.title or vuln_id,
                    description="\n".join([*fact.remediation_steps[:3], *fact.mitigation_steps[:3]]) or fact.advisory_title,
                    published_at=fact.published_at,
                    modified_at=fact.updated_at,
                    affected_vendors=fact.affected_vendors,
                    affected_products=fact.affected_products,
                    affected_components=fact.affected_components,
                    affected_versions=fact.affected_versions,
                    fixed_versions=fact.fixed_versions,
                    cwe_ids=fact.cwe_ids,
                    references=[ReferenceRecord(url=url, source="vendor_advisory", tags=["advisory"]) for url in fact.references],
                    advisory_references=[
                        ReferenceRecord(url=doc.source_url or doc.source_file, source="vendor_advisory", tags=["advisory"])
                    ],
                    raw_by_source={
                        "vendor_advisory": {
                            "advisory_doc_id": doc.advisory_doc_id,
                            "source_sha256": doc.source_sha256,
                            "facts_path": doc.extracted_facts_path,
                        }
                    },
                    provenance=[
                        {
                            "source": "vendor_advisory",
                            "advisory_doc_id": doc.advisory_doc_id,
                            "source_sha256": doc.source_sha256,
                            "confidence": doc.confidence,
                        }
                    ],
                    confidence=doc.confidence,
                )
            )
    return records


def write_vuln_outputs(
    output_dir: Path | str,
    *,
    events: list[VulnEvent],
    records: list[VulnerabilityRecord],
    cards: list[Any],
    advisory_docs: list[AdvisoryDocRecord],
    advisory_facts: list[AdvisoryExtractedFacts],
    advisory_chunks: list[dict[str, object]] | None = None,
) -> dict[str, Any]:
    out = Path(output_dir) / "vuln"
    events_path = out / "events" / "vuln_events.jsonl"
    records_path = out / "records" / "vulnerability_records.jsonl"
    cards_path = out / "cards" / "vulnerability_intel_cards.jsonl"
    chunks_path = out / "cards" / "vulnerability_intel_card_chunks.jsonl"
    import_chunks_path = out / "chunks" / "chunks.jsonl"
    docs_path = out / "advisories" / "advisory_docs.jsonl"
    facts_path = out / "advisories" / "advisory_facts.jsonl"
    advisory_chunks_path = out / "advisories" / "advisory_chunks.jsonl"
    write_jsonl(events_path, events)
    write_jsonl(records_path, records)
    write_jsonl(cards_path, cards)
    card_chunks = [card_to_rag_chunk(card, chunk_index=index) for index, card in enumerate(cards)]
    write_jsonl(chunks_path, card_chunks)
    write_jsonl(docs_path, advisory_docs)
    write_jsonl(facts_path, advisory_facts)
    all_import_chunks = [*card_chunks, *(advisory_chunks or [])]
    write_jsonl(advisory_chunks_path, advisory_chunks or [])
    write_jsonl(import_chunks_path, all_import_chunks)
    manifest = {
        "events": len(events),
        "records": len(records),
        "cards": len(cards),
        "advisory_docs": len(advisory_docs),
        "advisory_facts": len(advisory_facts),
        "advisory_chunks": len(advisory_chunks or []),
        "files": {
            "events": str(events_path),
            "records": str(records_path),
            "cards": str(cards_path),
            "card_chunks": str(chunks_path),
            "runtime_import_chunks": str(import_chunks_path),
            "advisory_docs": str(docs_path),
            "advisory_facts": str(facts_path),
            "advisory_chunks": str(advisory_chunks_path),
        },
        "safety": {
            "embedded_artifacts": ["VulnerabilityIntelCard", "advisory_chunks"],
            "structured_raw_feeds_docling_processed": False,
            "control_plane_output": "hints_only",
        },
    }
    write_json(out / "manifests" / "vuln_stream_manifest.json", manifest)
    return manifest
