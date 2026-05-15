from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from primordial.config import AppConfig
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


if __name__ == "__main__":
    unittest.main()
