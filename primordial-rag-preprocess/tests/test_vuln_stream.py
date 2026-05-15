from __future__ import annotations

import json
from pathlib import Path

from primordial_preprocess.vuln.cards import card_to_rag_chunk, cards_for_record
from primordial_preprocess.vuln.cvelist_v5 import event_for_cve_v5, parse_cve_v5
from primordial_preprocess.vuln.epss import event_for_epss_row, parse_epss_row
from primordial_preprocess.vuln.kev import parse_kev_entry
from primordial_preprocess.vuln.merge import merge_records
from primordial_preprocess.vuln.nvd import parse_nvd_vulnerability
from primordial_preprocess.vuln.osv import parse_osv
from primordial_preprocess.vuln.run_vuln_stream import run_vuln_stream


def test_parse_cve_v5_published_and_rejected_records():
    payload = {
        "cveMetadata": {"cveId": "CVE-2026-1000", "state": "PUBLISHED", "datePublished": "2026-01-01"},
        "containers": {
            "cna": {
                "title": "Example API issue",
                "descriptions": [{"lang": "en", "value": "API authorization issue."}],
                "affected": [{"vendor": "Example", "product": "API", "versions": [{"version": "1.0", "lessThan": "1.2"}]}],
                "problemTypes": [{"descriptions": [{"description": "CWE-639"}]}],
                "references": [{"url": "https://vendor.example/advisory", "tags": ["vendor-advisory"]}],
            }
        },
    }
    record = parse_cve_v5(payload)
    event = event_for_cve_v5(payload)
    rejected = event_for_cve_v5({"cveMetadata": {"cveId": "CVE-2026-1001", "state": "REJECTED"}})

    assert record.cve_id == "CVE-2026-1000"
    assert "Example" in record.affected_vendors
    assert "CWE-639" in record.cwe_ids
    assert event.event_type == "cve.updated"
    assert rejected.event_type == "cve.rejected"


def test_parse_nvd_osv_kev_epss_and_merge_aliases():
    nvd = parse_nvd_vulnerability(
        {
            "cve": {
                "id": "CVE-2026-2000",
                "descriptions": [{"lang": "en", "value": "NVD description."}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}, "baseSeverity": "CRITICAL"}]},
                "weaknesses": [{"description": [{"value": "CWE-79"}]}],
                "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:example:api:1.0:*:*:*:*:*:*:*"}]}]}],
            }
        }
    )
    osv = parse_osv(
        {
            "id": "GHSA-abcd-efgh-ijkl",
            "aliases": ["CVE-2026-2000"],
            "summary": "Package issue",
            "affected": [{"package": {"ecosystem": "PyPI", "name": "example-api", "purl": "pkg:pypi/example-api"}, "ranges": [{"events": [{"fixed": "1.2.0"}]}]}],
        }
    )
    kev = parse_kev_entry({"cveID": "CVE-2026-2000", "vendorProject": "Example", "product": "API", "vulnerabilityName": "Known exploited API issue"})
    epss = parse_epss_row({"cve": "CVE-2026-2000", "epss": "0.42", "percentile": "0.95", "date": "2026-05-15"})
    merged = merge_records([nvd, osv, kev, epss])

    assert len(merged) == 1
    record = merged[0]
    assert record.cve_id == "CVE-2026-2000"
    assert record.kev["known_exploited"] is True
    assert record.epss and record.epss.percentile == 0.95
    assert record.affected_packages[0].name == "example-api"
    assert record.cvss[0].severity == "CRITICAL"


def test_cards_are_rag_ready_and_do_not_embed_raw_json():
    record = parse_kev_entry({"cveID": "CVE-2026-3000", "vendorProject": "Vendor", "product": "Widget", "vulnerabilityName": "Widget issue"})
    cards = cards_for_record(record)
    chunk = card_to_rag_chunk(cards[0])

    assert cards
    assert chunk["domain"] == "vuln_intel"
    assert chunk["chunk_type"] == "vulnerability_intel_card"
    assert "Vulnerability: CVE-2026-3000" in chunk["retrieval_text"]
    assert "payload_generation" in chunk["metadata"]["blocked_output_modes"]


def test_epss_jump_event():
    event = event_for_epss_row({"cve": "CVE-2026-4000", "epss": "0.8", "percentile": "0.99", "delta": "0.2"})

    assert event.event_type == "epss.jump"


def test_run_vuln_stream_from_local_fixtures(tmp_path: Path):
    raw = tmp_path / "data_raw" / "vuln"
    cve_dir = raw / "structured" / "cve_v5"
    cve_dir.mkdir(parents=True)
    (cve_dir / "CVE-2026-5000.json").write_text(
        json.dumps(
            {
                "cveMetadata": {"cveId": "CVE-2026-5000", "state": "PUBLISHED"},
                "containers": {"cna": {"descriptions": [{"lang": "en", "value": "Fixture vulnerability."}]}},
            }
        ),
        encoding="utf-8",
    )
    advisory_dir = raw / "advisories" / "markdown"
    advisory_dir.mkdir(parents=True)
    (advisory_dir / "vendor.md").write_text(
        "# Vendor Advisory\n\nCVE-2026-5000\n\n## Remediation\nUpgrade to 1.2.3.\n",
        encoding="utf-8",
    )

    manifest = run_vuln_stream(raw_dir=raw, output_dir=tmp_path / "output")

    assert manifest["events"] == 1
    assert manifest["records"] == 1
    assert manifest["cards"] >= 2
    assert Path(manifest["files"]["card_chunks"]).exists()
    assert Path(manifest["files"]["runtime_import_chunks"]).exists()
