from __future__ import annotations

from tests.test_web_console_common import *


def _web_api_rag_chunk() -> dict[str, object]:
    return {
        "chunk_id": "chunk_web_api_1",
        "doc_id": "source_api",
        "source_file": "owasp-api.md",
        "source_sha256": "b" * 64,
        "source_type": "markdown",
        "domain": "api_web",
        "corpus_type": ["api_security"],
        "chunk_index": 0,
        "chunk_type": "docling_hybrid",
        "title": "BOLA",
        "section": "Broken Object Level Authorization",
        "retrieval_text": "BOLA testing checks object ownership before returning API objects.",
        "raw_text": "BOLA testing checks object ownership before returning API objects.",
        "requires_authorized_scope": True,
        "planner_visibility": "normal",
        "risk_level": "safe_planning",
        "metadata": {"profile": {"title": "OWASP API"}},
    }


class WebConsoleTestsPart1(WebConsoleTestsBase):
    def test_dashboard_and_audit_endpoints_return_json(self) -> None:
        dashboard_response = self.app.dispatch("GET", "/api/dashboard")
        work_status_response = self.app.dispatch("GET", "/api/work-status")
        scope_response = self.app.dispatch("GET", "/api/scope")
        audit_response = self.app.dispatch("GET", "/api/audit?limit=5")

        self.assertEqual(dashboard_response.status, 200)
        self.assertEqual(work_status_response.status, 200)
        self.assertEqual(scope_response.status, 200)
        self.assertEqual(audit_response.status, 200)

        dashboard = json.loads(dashboard_response.body)
        work_status = json.loads(work_status_response.body)
        scope = json.loads(scope_response.body)
        audit = json.loads(audit_response.body)

        self.assertIn("counts", dashboard)
        self.assertIn("tasks", dashboard)
        self.assertIn("work_status", dashboard)
        self.assertIn("summary", work_status)
        self.assertIn("active", work_status)
        self.assertIn("queued", work_status)
        self.assertIn("targets", scope)
        self.assertIn("recent_events", audit)
        self.assertIn("recent_runtime_events", audit)

    def test_caido_and_skills_endpoints_return_safe_status(self) -> None:
        caido_response = self.app.dispatch("GET", "/api/integrations/caido")
        skills_response = self.app.dispatch("GET", "/api/skills")
        findings_response = self.app.dispatch("GET", "/api/findings-context?target=pirate.htb")

        caido = json.loads(caido_response.body)
        skills = json.loads(skills_response.body)
        findings = json.loads(findings_response.body)

        self.assertEqual(caido_response.status, 200)
        self.assertEqual(skills_response.status, 200)
        self.assertEqual(findings_response.status, 200)
        self.assertFalse(caido["configured"])
        self.assertIn("skills", skills)
        self.assertIn("workspace", findings)
        self.assertIn("guidance_path", findings["workspace"])

    def test_rag_api_import_search_inspect_source_synthesize_and_eval(self) -> None:
        chunks_dir = self._write_rag_chunks([_web_api_rag_chunk()])

        config_response = self.app.dispatch("GET", "/api/rag/config")
        dry_response = self.app.dispatch(
            "POST",
            "/api/rag/import",
            json.dumps({"chunks_dir": str(chunks_dir), "dry_run": True, "limit": 1}).encode("utf-8"),
        )
        import_response = self.app.dispatch(
            "POST",
            "/api/rag/import",
            json.dumps({"chunks_dir": str(chunks_dir), "limit": 1}).encode("utf-8"),
        )
        status_response = self.app.dispatch("GET", "/api/rag/status")
        search_response = self.app.dispatch(
            "POST",
            "/api/rag/search",
            json.dumps({"query": "object ownership API", "domain": ["api_security"], "limit": 3}).encode("utf-8"),
        )
        search = json.loads(search_response.body)
        result = search["results"][0]
        chunk_response = self.app.dispatch("GET", f"/api/rag/chunks/{result['citation_id']}")
        source_response = self.app.dispatch("GET", "/api/rag/sources/source_api")
        self.runtime.config.rag.synthesis.model = "qwen3-coder-next:q4_K_M"
        synth_response = self.app.dispatch(
            "POST",
            "/api/rag/synthesize",
            json.dumps({"query": "Explain BOLA", "retrieved_chunks": search["results"]}).encode("utf-8"),
        )
        eval_response = self.app.dispatch(
            "POST",
            "/api/rag/eval",
            json.dumps({"queries": ["BOLA object ownership"], "domain": ["api_security"], "limit": 2}).encode("utf-8"),
        )
        task_count = len(self.runtime.store.list_tasks(limit=500))
        hints_response = self.app.dispatch(
            "POST",
            "/api/rag/hints",
            json.dumps({"target": "pirate.htb", "query": "directory discovery", "limit": 3}).encode("utf-8"),
        )

        config = json.loads(config_response.body)
        dry = json.loads(dry_response.body)
        imported = json.loads(import_response.body)
        status = json.loads(status_response.body)
        chunk = json.loads(chunk_response.body)
        source = json.loads(source_response.body)
        synth = json.loads(synth_response.body)
        evaluation = json.loads(eval_response.body)
        hints = json.loads(hints_response.body)

        self._assert_rag_api_import_search_status(
            config_response,
            config,
            dry_response,
            dry,
            import_response,
            imported,
            status,
            search_response,
            result,
            search,
        )
        self._assert_rag_api_detail_and_eval(
            chunk_response,
            chunk,
            source_response,
            source,
            synth,
            evaluation,
            hints_response,
            hints,
            task_count,
        )

    def _assert_rag_api_import_search_status(
        self,
        config_response,
        config,
        dry_response,
        dry,
        import_response,
        imported,
        status,
        search_response,
        result,
        search,
    ) -> None:
        self.assertEqual(config_response.status, 200)
        self.assertEqual(config["embeddings"]["provider"], "deterministic_hash")
        self.assertNotIn("api_key", json.dumps(config).lower())
        self.assertEqual(dry_response.status, 200)
        self.assertTrue(dry["result"]["dry_run"])
        self.assertEqual(import_response.status, 200)
        self.assertEqual(imported["result"]["chunks_inserted"], 1)
        self.assertEqual(imported["result"]["embeddings_inserted"], 1)
        self.assertEqual(status["document_chunks"], 1)
        self.assertEqual(status["record_embeddings"], 1)
        self.assertEqual(status["last_import"]["records_seen"], 1)
        self.assertEqual(search_response.status, 200)
        self.assertEqual(result["citation_id"], "rag:chunk_web_api_1")
        self.assertEqual(result["metadata"]["domain"], "api_security")
        self.assertEqual(search["citation_map"][0]["source_display"], "Broken Object Level Authorization (owasp-api.md)")

    def _assert_rag_api_detail_and_eval(
        self,
        chunk_response,
        chunk,
        source_response,
        source,
        synth,
        evaluation,
        hints_response,
        hints,
        task_count,
    ) -> None:
        self.assertEqual(chunk_response.status, 200)
        self.assertEqual(chunk["chunk"]["citation_id"], "rag:chunk_web_api_1")
        self.assertNotIn("embedding", chunk["embedding"])
        self.assertEqual(source_response.status, 200)
        self.assertEqual(source["doc_id"], "source_api")
        self.assertEqual(source["chunk_count"], 1)
        self.assertEqual(synth["status"], "disallowed_model")
        self.assertIn("qwen", synth["error"].lower())
        self.assertEqual(synth["citation_map"][0]["citation_id"], "rag:chunk_web_api_1")
        self.assertEqual(evaluation["mode"], "retrieval_only")
        self.assertEqual(evaluation["results"][0]["top_citations"], ["rag:chunk_web_api_1"])
        self.assertEqual(hints_response.status, 200)
        self.assertIn("candidate_actions", hints)
        self.assertEqual(len(self.runtime.store.list_tasks(limit=500)), task_count)

    def test_rag_vuln_api_status_search_hints_and_sync_route(self) -> None:
        chunks_dir = self._write_rag_chunks(
            [
                {
                    "chunk_id": "vuln_web_card_1",
                    "doc_id": "CVE-2026-2222",
                    "source_file": "CVE-2026-2222.vuln-intel-card",
                    "source_sha256": "c" * 64,
                    "source_type": "vulnerability_intel_card",
                    "domain": "vuln_intel",
                    "chunk_index": 0,
                    "chunk_type": "vulnerability_intel_card",
                    "title": "CVE-2026-2222 summary",
                    "section": "vuln_summary",
                    "retrieval_text": "Vulnerability: CVE-2026-2222\nAffected vendors/products/packages: Example API PyPI:example-api\nExploitability signals: KEV=true; EPSS probability=0.5 percentile=0.95",
                    "raw_text": "Vulnerability: CVE-2026-2222",
                    "requires_authorized_scope": True,
                    "metadata": {
                        "domain": "vuln_intel",
                        "corpus_type": "vuln_intel",
                        "vuln_id": "CVE-2026-2222",
                        "cve_id": "CVE-2026-2222",
                        "aliases": ["CVE-2026-2222", "GHSA-web-test-0001"],
                        "alias": ["CVE-2026-2222", "GHSA-web-test-0001"],
                        "ghsa_ids": ["GHSA-web-test-0001"],
                        "card_type": "vuln_summary",
                        "kev": True,
                        "epss_percentile": 0.95,
                        "package": ["example-api"],
                        "ecosystem": ["PyPI"],
                        "blocked_output_modes": ["exploit_execution", "action_selection", "scope_expansion"],
                        "safety_level": "safe_planning",
                    },
                }
            ]
        )
        self.runtime.rag_import_chunks(chunks_dir, domains=["vuln_intel"])

        status_response = self.app.dispatch("GET", "/api/rag/vuln/status")
        search_response = self.app.dispatch(
            "POST",
            "/api/rag/vuln/search",
            json.dumps({"query": "Example API", "cve_id": ["CVE-2026-2222"], "limit": 3}).encode("utf-8"),
        )
        hints_response = self.app.dispatch(
            "POST",
            "/api/rag/vuln/hints",
            json.dumps({"query": "Example API", "kev": True, "limit": 3}).encode("utf-8"),
        )
        with patch.object(
            self.runtime,
            "rag_vuln_sync",
            return_value={"ok": True, "sync": {"sources": {}}, "import": None, "vuln_intel_chunks": 1, "chunks_dir": "fixture"},
        ) as sync:
            sync_response = self.app.dispatch(
                "POST",
                "/api/rag/vuln/sync",
                json.dumps({"since_year": 2020, "embed_all": True, "sources": ["kev"], "skip_embeddings": True}).encode("utf-8"),
            )

        status = json.loads(status_response.body)
        search = json.loads(search_response.body)
        hints = json.loads(hints_response.body)
        synced = json.loads(sync_response.body)

        self.assertEqual(status_response.status, 200)
        self.assertEqual(status["vuln_intel_chunks"], 1)
        self.assertEqual(search_response.status, 200)
        self.assertEqual(search["results"][0]["citation_id"], "rag:vuln_web_card_1")
        self.assertEqual(hints_response.status, 200)
        self.assertTrue(hints["hints"])
        self.assertFalse(hints["hints"][0]["creates_executable_task"])
        self.assertEqual(sync_response.status, 200)
        self.assertEqual(synced["action"], "rag-vuln-sync")
        sync.assert_called_once()

    def test_caido_health_status_reports_auth_failure_and_legacy_port_migration(self) -> None:
        self.runtime.credentials.update_service(
            "caido",
            {
                "graphql_url": "http://127.0.0.1:8080/graphql",
                "api_token": "caido-secret-token",
            },
        )
        calls = []

        def unauthorized(req, timeout):
            calls.append(req.full_url)
            err = __import__("urllib.error").error.HTTPError(
                req.full_url,
                401,
                "Unauthorized",
                {},
                None,
            )
            err.fp = io.BytesIO(b'{"error":"Unauthorized"}')
            raise err

        with patch("primordial.adapters.caido.request.urlopen", side_effect=unauthorized):
            response = self.app.dispatch("GET", "/api/integrations/caido?check_health=1")

        payload = json.loads(response.body)
        self.assertEqual(response.status, 200)
        self.assertEqual(calls, [CaidoIntegrationService.DEFAULT_GRAPHQL_URL])
        self.assertEqual(payload["graphql_url"], CaidoIntegrationService.DEFAULT_GRAPHQL_URL)
        self.assertEqual(payload["graphql_url_migrated_from"], "http://127.0.0.1:8080/graphql")
        self.assertTrue(payload["auth_error"])
        self.assertFalse(payload["ok"])
        self.assertFalse(payload["schema"]["ok"])

__all__ = ["WebConsoleTestsPart1"]
