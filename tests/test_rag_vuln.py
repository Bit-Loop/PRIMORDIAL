from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from urllib import error

from primordial.config import AppConfig
from primordial.core.rag.vuln_sync import VulnFeedSyncer, VulnSyncOptions
from primordial.core.rag.vuln_hints import vulnerability_hints_from_results
from primordial.core.storage.runtime import RuntimeStore
from primordial.runtime import PrimordialRuntime


class RagVulnRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.config = AppConfig.from_env(project_root=self.root)
        self.config.rag.embeddings.provider = "deterministic_hash"
        self.config.ensure_directories()
        self.store = RuntimeStore(self.config.database_url, schema=self.config.database_schema)
        self.store.initialize()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_runtime_imports_and_searches_vuln_intel_card(self) -> None:
        chunks = self.root / "chunks"
        chunks.mkdir()
        (chunks / "vulnerability_intel_card_chunks.jsonl").write_text(
            """
{"chunk_id":"vuln_card_test","doc_id":"CVE-2026-9000","source_file":"CVE-2026-9000.vuln-intel-card","source_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","source_type":"vulnerability_intel_card","domain":"vuln_intel","chunk_index":0,"chunk_type":"vulnerability_intel_card","title":"CVE-2026-9000 summary","section":"vuln_summary","retrieval_text":"Vulnerability: CVE-2026-9000\\nAffected vendors/products/packages: Example API PyPI:example-api\\nExploitability signals: KEV=true; EPSS probability=0.5 percentile=0.95","raw_text":"Vulnerability: CVE-2026-9000","requires_authorized_scope":true,"metadata":{"domain":"vuln_intel","corpus_type":"vuln_intel","vuln_id":"CVE-2026-9000","cve_id":"CVE-2026-9000","aliases":["CVE-2026-9000","GHSA-abcd-efgh-ijkl"],"alias":["CVE-2026-9000","GHSA-abcd-efgh-ijkl"],"ghsa_ids":["GHSA-abcd-efgh-ijkl"],"card_type":"vuln_summary","kev":true,"epss_percentile":0.95,"package":["example-api"],"ecosystem":["PyPI"],"cwe":["CWE-79"],"cvss_severity":"CRITICAL","fixed_version_known":true,"output_mode":["vuln_triage"],"blocked_output_modes":["exploit_execution","action_selection","scope_expansion"],"safety_level":"safe_planning"}}
""".strip()
            + "\n",
            encoding="utf-8",
        )
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()

        imported = runtime.rag_import_chunks(chunks, domains=["vuln_intel"])
        by_cve = runtime.rag_vuln_search("Example API", filters={"cve_id": ["CVE-2026-9000"]})
        by_ghsa = runtime.rag_vuln_search("Example API", filters={"ghsa_id": ["GHSA-abcd-efgh-ijkl"]})
        by_package = runtime.rag_vuln_search("Example API", filters={"package": ["example-api"], "ecosystem": ["PyPI"]})
        by_kev = runtime.rag_vuln_search("Example API", filters={"kev": True})
        by_epss = runtime.rag_vuln_search("Example API", filters={"epss_percentile": {"gte": 0.9}})

        self.assertEqual(imported["chunks_inserted"], 1)
        self.assertEqual(by_cve["results"][0]["citation_id"], "rag:vuln_card_test")
        self.assertEqual(by_ghsa["results"][0]["citation_id"], "rag:vuln_card_test")
        self.assertEqual(by_package["results"][0]["citation_id"], "rag:vuln_card_test")
        self.assertEqual(by_kev["results"][0]["citation_id"], "rag:vuln_card_test")
        self.assertEqual(by_epss["results"][0]["citation_id"], "rag:vuln_card_test")
        runtime.shutdown()

    def test_vulnerability_hints_are_not_tasks(self) -> None:
        hints = vulnerability_hints_from_results(
            [
                {
                    "citation_id": "rag:vuln_card_test",
                    "title": "CVE-2026-9000 summary",
                    "metadata": {
                        "domain": "vuln_intel",
                        "vuln_id": "CVE-2026-9000",
                        "cve_id": "CVE-2026-9000",
                        "kev": True,
                        "blocked_output_modes": ["exploit_execution", "action_selection", "scope_expansion"],
                    },
                }
            ]
        )

        self.assertTrue(hints["hints"])
        self.assertFalse(hints["hints"][0]["creates_executable_task"])
        self.assertFalse(hints["hints"][0]["can_expand_scope"])

    def test_vulnerability_hints_do_not_advertise_executable_output_modes(self) -> None:
        hints = vulnerability_hints_from_results(
            [
                {
                    "citation_id": "rag:vuln_card_exploit_mode",
                    "title": "CVE-2026-9001 summary",
                    "metadata": {
                        "domain": "vuln_intel",
                        "vuln_id": "CVE-2026-9001",
                        "cve_id": "CVE-2026-9001",
                        "output_mode": ["vuln_triage", "exploit_execution", "action_selection"],
                        "blocked_output_modes": ["exploit_execution", "action_selection", "scope_expansion"],
                    },
                }
            ]
        )

        self.assertTrue(hints["hints"])
        hint = hints["hints"][0]
        self.assertEqual(hint["allowed_output_modes"], ["vuln_triage"])
        self.assertFalse(hint["creates_executable_task"])
        self.assertFalse(hint["can_expand_scope"])

    def test_vulnerability_hints_preserve_human_readable_metadata_as_hints_only(self) -> None:
        hints = vulnerability_hints_from_results(
            [
                {
                    "citation_id": "rag:vuln_card_display_metadata",
                    "title": "CVE-2026-9010 summary",
                    "metadata": {
                        "Domain": "vuln_intel",
                        "Vuln ID": "CVE-2026-9010",
                        "CVE ID": "CVE-2026-9010",
                        "Aliases": ("CVE-2026-9010", "GHSA-display-meta-test"),
                        "Source refs": ("https://example.invalid/advisory",),
                        "KEV": "true",
                        "CVSS Severity": "CRITICAL",
                        "EPSS Percentile": "0.91",
                        "Fixed version known": "yes",
                        "Output mode": ("vuln_triage", "action_selection"),
                        "Blocked output modes": (
                            "exploit_execution",
                            "action_selection",
                            "scope_expansion",
                        ),
                    },
                }
            ]
        )

        self.assertEqual(hints["rejected"], [])
        self.assertTrue(hints["hints"])
        hint = hints["hints"][0]
        self.assertEqual(hint["hint_type"], "known_exploited_vulnerability_context")
        self.assertEqual(hint["vuln_id"], "CVE-2026-9010")
        self.assertEqual(hint["cve_id"], "CVE-2026-9010")
        self.assertEqual(hint["aliases"], ["CVE-2026-9010", "GHSA-display-meta-test"])
        self.assertEqual(hint["source_refs"], ["https://example.invalid/advisory"])
        self.assertEqual(hint["allowed_output_modes"], ["vuln_triage"])
        self.assertFalse(hint["creates_executable_task"])
        self.assertFalse(hint["can_expand_scope"])

    def test_vulnerability_hints_reject_uncited_cards(self) -> None:
        hints = vulnerability_hints_from_results(
            [
                {
                    "title": "CVE-2026-9002 summary",
                    "metadata": {
                        "domain": "vuln_intel",
                        "vuln_id": "CVE-2026-9002",
                        "cve_id": "CVE-2026-9002",
                        "output_mode": ["vuln_triage"],
                        "blocked_output_modes": ["exploit_execution", "action_selection", "scope_expansion"],
                    },
                }
            ]
        )

        self.assertEqual(hints["hints"], [])
        self.assertEqual(hints["rejected"], [{"citation_id": None, "reason": "missing rag citation"}])

    def test_vulnerability_hints_require_core_safety_blocks(self) -> None:
        hints = vulnerability_hints_from_results(
            [
                {
                    "citation_id": "rag:vuln_card_partial_blocks",
                    "title": "CVE-2026-9003 summary",
                    "metadata": {
                        "domain": "vuln_intel",
                        "vuln_id": "CVE-2026-9003",
                        "cve_id": "CVE-2026-9003",
                        "output_mode": ["vuln_triage"],
                        "blocked_output_modes": ["scope_expansion"],
                    },
                }
            ]
        )

        self.assertEqual(hints["hints"], [])
        self.assertEqual(
            hints["rejected"],
            [
                {
                    "citation_id": "rag:vuln_card_partial_blocks",
                    "reason": "missing required safety block metadata",
                }
            ],
        )

    def test_vulnerability_hint_rejection_normalizes_curated_citation_id(self) -> None:
        hints = vulnerability_hints_from_results(
            [
                {
                    "citation_id": "vuln-card-unprefixed",
                    "title": "CVE-2026-9004 summary",
                    "metadata": {
                        "domain": "vuln_intel",
                        "vuln_id": "CVE-2026-9004",
                        "cve_id": "CVE-2026-9004",
                        "output_mode": ["vuln_triage"],
                    },
                }
            ]
        )

        self.assertEqual(hints["hints"], [])
        self.assertEqual(
            hints["rejected"],
            [{"citation_id": "rag:vuln-card-unprefixed", "reason": "missing safety block metadata"}],
        )

    def test_vuln_feed_syncer_writes_raw_feeds_and_preprocesses_cards(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]

        def fake_opener(req, *, timeout=45):
            url = req.full_url
            if "services.nvd.nist.gov" in url:
                return _FakeHttpResponse(
                    {
                        "resultsPerPage": 2000,
                        "startIndex": 0,
                        "totalResults": 1,
                        "vulnerabilities": [
                            {
                                "cve": {
                                    "id": "CVE-2026-1111",
                                    "published": "2026-01-01T00:00:00.000",
                                    "lastModified": "2026-01-02T00:00:00.000",
                                    "descriptions": [{"lang": "en", "value": "Example API vulnerability."}],
                                    "metrics": {
                                        "cvssMetricV31": [
                                            {
                                                "cvssData": {
                                                    "baseScore": 9.8,
                                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                                },
                                                "baseSeverity": "CRITICAL",
                                            }
                                        ]
                                    },
                                    "references": {"referenceData": [{"url": "https://vendor.example/CVE-2026-1111"}]},
                                }
                            }
                        ],
                    }
                )
            if "known_exploited_vulnerabilities.csv" in url:
                return _FakeHttpResponse(
                    "cveID,vendorProject,product,vulnerabilityName,dateAdded,shortDescription,requiredAction,dueDate,knownRansomwareCampaignUse,notes\n"
                    "CVE-2026-1111,Example,API,Example known exploited API issue,2026-05-15,Fixture,Apply vendor update.,2026-06-01,Unknown,\n"
                )
            if "api.first.org/data/v1/epss" in url:
                return _FakeHttpResponse(
                    {
                        "data": [
                            {
                                "cve": "CVE-2026-1111",
                                "epss": "0.42",
                                "percentile": "0.95",
                                "date": "2026-05-15",
                            }
                        ]
                    }
                )
            raise error.HTTPError(url, 404, "not found", hdrs=None, fp=None)

        syncer = VulnFeedSyncer(
            self.root,
            preprocess_root=repo_root / "primordial-rag-preprocess",
            opener=fake_opener,
            sleeper=lambda _seconds: None,
        )
        summary = syncer.sync(
            VulnSyncOptions(
                since_year=2020,
                sources={"nvd", "kev", "epss"},
                rate_limit_seconds=0,
                max_nvd_pages=1,
                embed_all=True,
            )
        )

        self.assertTrue(summary["ok"])
        self.assertEqual(summary["sources"]["nvd"]["records"], 1)
        self.assertEqual(summary["sources"]["kev"]["records"], 1)
        self.assertEqual(summary["sources"]["epss"]["records"], 1)
        self.assertGreaterEqual(summary["preprocess_manifest"]["cards"], 2)
        self.assertTrue(Path(summary["preprocess_manifest"]["files"]["runtime_import_chunks"]).exists())


class _FakeHttpResponse:
    def __init__(self, payload: object) -> None:
        self._payload = payload.encode("utf-8") if isinstance(payload, str) else json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc, _tb):
        return False

    def read(self) -> bytes:
        return self._payload


if __name__ == "__main__":
    unittest.main()
