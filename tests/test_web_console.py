from __future__ import annotations

import hashlib
import io
import json
import threading
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from primordial.config import AppConfig
from primordial.adapters.caido import CaidoIntegrationService
from primordial.core.domain.enums import (
    AgentRole,
    ArtifactKind,
    EvidenceType,
    EventType,
    InterestStatus,
    MethodologyPhase,
    NotificationChannel,
    NotificationStatus,
    PrimitiveRuntime,
    RiskTier,
    ProviderRoute,
    ScopeProfile,
    SideEffectLevel,
    TaskKind,
    TaskRunStatus,
    TaskStatus,
    VerificationStatus,
)
from primordial.core.domain.models import (
    AgentTrace,
    ArtifactRecord,
    EventRecord,
    EvidenceRecord,
    Interest,
    NotificationRecord,
    OperatorMessage,
    PrimitiveManifest,
    Task,
    TaskRun,
)
from primordial.core.providers.ollama import OllamaModelListResult, OllamaPreloadResult, OllamaResponse
from primordial.core.web.app import PrimordialWebApp, WebResponse
from primordial.core.web.server import _WebConsoleRequestHandler
from primordial.runtime import PrimordialRuntime
from tests.support import build_probe_fixture, write_scope_file


MANIFESTS_DIR = Path(__file__).resolve().parents[1] / "manifests"


class WebConsoleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.root = root
        config = AppConfig.from_env(project_root=root)
        config.manifests_dir = MANIFESTS_DIR
        config.rag.embeddings.provider = "deterministic_hash"
        config.ensure_directories()
        self.scope_path = write_scope_file(
            root,
            targets=[
                {
                    "handle": "pirate.htb",
                    "display_name": "Pirate Fixture",
                    "in_scope": True,
                    "assets": [{"asset": "http://pirate.htb/", "asset_type": "webapp"}],
                }
            ],
        )
        self.runtime = PrimordialRuntime(config)
        self.runtime.initialize()
        self.runtime.import_scope(self.scope_path)
        self.app = PrimordialWebApp(self.runtime)
        self.probe_patcher = patch(
            "primordial.modes.security.execution.PrimitiveExecutor._probe_url",
            autospec=True,
            side_effect=lambda _executor, **kwargs: build_probe_fixture(kwargs["url"]),
        )
        self.probe_patcher.start()

    def tearDown(self) -> None:
        self.probe_patcher.stop()
        self.runtime.shutdown()
        self.temp_dir.cleanup()

    def _write_rag_chunks(self, records: list[dict[str, object]]) -> Path:
        chunks_dir = self.root / "rag_chunks"
        chunks_dir.mkdir(parents=True, exist_ok=True)
        chunks_file = chunks_dir / "chunks.jsonl"
        chunks_file.write_text("\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8")
        return chunks_dir

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
        chunks_dir = self._write_rag_chunks(
            [
                {
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
            ]
        )

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

    def test_caido_presets_are_generic_and_targets_are_runtime_scope(self) -> None:
        create_response = self.app.dispatch(
            "POST",
            "/api/targets",
            json.dumps(
                {
                    "handle": "helix.htb",
                    "display_name": "helix.htb",
                    "profile": "hack_the_box",
                    "assets": ["helix.htb", "10.129.54.140"],
                    "active_ip": "10.129.54.140",
                    "in_scope": True,
                }
            ).encode("utf-8"),
        )
        response = self.app.dispatch("GET", "/api/control-plane")
        payload = json.loads(response.body)
        caido = payload["caido"]
        handles = {item["handle"] for item in caido["targetOptions"]}
        preset_labels = {item["label"] for item in caido["savedFilters"]}

        self.assertEqual(create_response.status, 200)
        self.assertEqual(response.status, 200)
        self.assertIn("pirate.htb", handles)
        self.assertIn("helix.htb", handles)
        self.assertIn("Error responses", preset_labels)
        self.assertIn("Auth paths", preset_labels)
        self.assertIn("Token hints", preset_labels)
        self.assertNotIn("pirate.htb scope", preset_labels)
        self.assertNotIn("helix.htb scope", preset_labels)

    def test_caido_import_creates_redacted_evidence_and_artifact(self) -> None:
        detail = {
            "ok": True,
            "request": {
                "id": "42",
                "method": "POST",
                "host": "pirate.htb",
                "port": 80,
                "path": "/login",
                "status": 200,
                "source": "INTERCEPT",
                "request_sha256": "reqhash",
                "response_sha256": "resphash",
                "request_snippet": "POST /login HTTP/1.1\nHost: pirate.htb\nAuthorization: [redacted]\n\npassword=[redacted]",
                "response_snippet": "HTTP/1.1 200 OK\nSet-Cookie: [redacted]\n\nok",
                "request_truncated": False,
                "response_truncated": False,
                "raw_bodies_stored": False,
            },
        }
        with patch.object(self.runtime.caido, "request_detail", return_value=detail):
            response = self.app.dispatch(
                "POST",
                "/api/integrations/caido/import",
                json.dumps(
                    {
                        "target": "pirate.htb",
                        "request_ids": ["42"],
                        "httpql": 'req.host.eq:"pirate.htb"',
                    }
                ).encode("utf-8"),
            )

        payload = json.loads(response.body)
        records = self.runtime.records_payload(limit=10)
        evidence = records["evidence"][0]
        artifact = records["artifacts"][0]
        artifact_body = Path(artifact["path"]).read_text(encoding="utf-8")
        serialized = json.dumps(payload) + json.dumps(records) + artifact_body

        self.assertEqual(response.status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(evidence["type"], "http_replay")
        self.assertEqual(artifact["kind"], "caido_capture")
        self.assertIn("Authorization: [redacted]", serialized)
        self.assertIn("password=[redacted]", serialized)
        self.assertNotIn("Bearer abc", serialized)
        self.assertNotIn("swordfish", serialized)
        self.assertNotIn("\"raw\":", serialized)
        self.assertFalse(evidence["metadata"]["raw_bodies_stored"])

        target = next(item for item in self.runtime.store.list_targets() if item.handle == "pirate.htb")
        assert target is not None
        self.runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=target.id,
                type=EvidenceType.HTTP_REPLAY,
                title="Recon",
                summary="Generic replay evidence that is not a Caido capture.",
                source_ref="manual://recon",
                verification_status=VerificationStatus.PARTIAL,
                metadata={"method": "http_replay", "host": "pirate.htb", "path": "Recon"},
            )
        )
        control_plane = json.loads(self.app.dispatch("GET", "/api/control-plane").body)

        self.assertEqual(control_plane["caido"]["requests"], [])
        self.assertEqual(len(control_plane["caido"]["importedCaptures"]), 1)
        self.assertEqual(control_plane["caido"]["importedCaptures"][0]["caidoRequestId"], "42")
        self.assertEqual(control_plane["caido"]["importedCaptures"][0]["path"], "/login")

    def test_caido_replay_send_gates_confirmation_scope_and_batches(self) -> None:
        valid_raw = "GET / HTTP/1.1\nHost: pirate.htb\nConnection: close\n\n"
        out_of_scope_raw = "GET / HTTP/1.1\nHost: evil.example\nConnection: close\n\n"
        batch_raw = (
            "GET /one HTTP/1.1\nHost: pirate.htb\nConnection: close\n\n"
            "GET /two HTTP/1.1\nHost: pirate.htb\nConnection: close\n\n"
        )

        missing = self.app.dispatch(
            "POST",
            "/api/integrations/caido/replay/send",
            json.dumps({"target": "pirate.htb", "raw_request": valid_raw, "session_id": "1"}).encode("utf-8"),
        )
        out_of_scope = self.app.dispatch(
            "POST",
            "/api/integrations/caido/replay/send",
            json.dumps(
                {
                    "target": "pirate.htb",
                    "raw_request": out_of_scope_raw,
                    "session_id": "1",
                    "confirmation": hashlib.sha256(out_of_scope_raw.strip("\n").encode("utf-8")).hexdigest(),
                }
            ).encode("utf-8"),
        )
        malformed = self.app.dispatch(
            "POST",
            "/api/integrations/caido/replay/send",
            json.dumps({"target": "pirate.htb", "raw_request": "not an http request", "confirmation": "x"}).encode("utf-8"),
        )
        batch = self.app.dispatch(
            "POST",
            "/api/integrations/caido/replay/send",
            json.dumps(
                {
                    "target": "pirate.htb",
                    "raw_request": batch_raw,
                    "session_id": "1",
                    "confirmation": hashlib.sha256(batch_raw.strip("\n").encode("utf-8")).hexdigest(),
                }
            ).encode("utf-8"),
        )

        parsed = self.runtime.caido.parse_raw_request(valid_raw)
        with patch.object(
            self.runtime.caido,
            "send_replay",
            return_value={
                "ok": True,
                "parsed": parsed.as_payload(),
                "task": {"id": "8", "replay_entry_id": "2"},
            },
        ) as send_replay:
            sent = self.app.dispatch(
                "POST",
                "/api/integrations/caido/replay/send",
                json.dumps(
                    {
                        "target": "pirate.htb",
                        "raw_request": valid_raw,
                        "session_id": "1",
                        "confirmation": parsed.raw_sha256,
                    }
                ).encode("utf-8"),
            )

        self.assertEqual(missing.status, 400)
        self.assertIn("confirmation", json.loads(missing.body)["error"])
        self.assertEqual(out_of_scope.status, 400)
        self.assertIn("not in target scope", json.loads(out_of_scope.body)["error"])
        self.assertEqual(malformed.status, 400)
        self.assertIn("request line", json.loads(malformed.body)["error"])
        self.assertEqual(batch.status, 400)
        self.assertIn("one HTTP request", json.loads(batch.body)["error"])
        self.assertEqual(sent.status, 200)
        send_replay.assert_called_once()
        audit = self.runtime.audit_payload(limit=5)
        self.assertEqual(audit["recent_events"][0]["type"], "caido_replay_sent")
        self.assertEqual(audit["recent_events"][0]["metadata"]["raw_sha256"], parsed.raw_sha256)
        self.assertFalse(audit["recent_events"][0]["metadata"]["raw_persisted"])

    def test_target_guidance_can_be_updated_from_web_console(self) -> None:
        update_response = self.app.dispatch(
            "POST",
            "/api/findings-context/guidance",
            json.dumps(
                {
                    "target": "pirate.htb",
                    "guidance": "# Pirate Guidance\n\n- Prefer careful AD enumeration.\n",
                }
            ).encode("utf-8"),
        )
        read_response = self.app.dispatch("GET", "/api/findings-context?target=pirate.htb&include_guidance=1")

        update = json.loads(update_response.body)
        read = json.loads(read_response.body)

        self.assertEqual(update_response.status, 200)
        self.assertTrue(update["ok"])
        self.assertEqual(update["action"], "update-target-guidance")
        self.assertIn("Prefer careful AD enumeration", read["workspace"]["guidance"])

    def test_tick_action_and_task_detail_work(self) -> None:
        tick_response = self.app.dispatch(
            "POST",
            "/api/actions/tick",
            json.dumps({"max_executions": 1}).encode("utf-8"),
        )
        tick_payload = json.loads(tick_response.body)

        self.assertEqual(tick_response.status, 200)
        self.assertTrue(tick_payload["ok"])
        self.assertIn("work_status", tick_payload)
        self.assertNotIn("dashboard", tick_payload)
        self.assertNotIn("control_plane", tick_payload)

        task_id = self.runtime.store.list_tasks(limit=1)[0].id
        detail_response = self.app.dispatch("GET", f"/api/tasks/{task_id}")
        detail_payload = json.loads(detail_response.body)

        self.assertEqual(detail_response.status, 200)
        self.assertEqual(detail_payload["task"]["id"], task_id)
        self.assertIn("runs", detail_payload)
        self.assertIn("checkpoints", detail_payload)

    def test_static_index_and_health_are_available(self) -> None:
        index_response = self.app.dispatch("GET", "/")
        health_response = self.app.dispatch("GET", "/api/health")

        self.assertEqual(index_response.status, 200)
        self.assertIn(b"Primordial Control Plane", index_response.body)

        health = json.loads(health_response.body)
        self.assertEqual(health_response.status, 200)
        self.assertEqual(health["status"], "ok")

    def test_control_plane_endpoint_returns_live_new_gui_shape(self) -> None:
        response = self.app.dispatch("GET", "/api/control-plane")
        payload = json.loads(response.body)

        self.assertEqual(response.status, 200)
        for key in (
            "runtime",
            "models",
            "tasks",
            "approvals",
            "events",
            "scope",
            "graph",
            "traces",
            "geo",
            "plan",
            "notes",
            "interests",
            "caido",
        ):
            self.assertIn(key, payload)
        self.assertEqual(payload["mode"], "real")
        self.assertEqual(payload["scope"][0]["handle"], "pirate.htb")
        self.assertNotIn("acme.bug", {item["handle"] for item in payload["scope"]})
        self.assertNotIn("driftnet.io", {item["handle"] for item in payload["scope"]})
        self.assertNotIn("tomcat:s3cret_2024", response.body.decode("utf-8"))
        self.assertIn("gpuMemory", payload["runtime"])
        self.assertIn("role_metrics", payload["modelPayload"])
        wrapper = payload["runtime"]["premiumWrapper"]
        self.assertEqual(wrapper["local_chat_wrapper"], "agent_chat_api")
        self.assertTrue(wrapper["local_wrapper_available"])
        self.assertEqual(wrapper["status"], "local wrapper")
        self.assertTrue(wrapper["remote_premium_policy_gate_bypassed_for_wrapper"])
        self.assertEqual(payload["plan"]["intent"]["id"], "htb_lab")
        self.assertTrue(payload["plan"]["intent"]["flags"]["credential_guessing"])
        self.assertTrue(payload["plan"]["intent"]["flags"]["credential_spraying"])
        self.assertTrue(payload["plan"]["intent"]["flags"]["hash_cracking"])
        self.assertTrue(payload["plan"]["intent"]["flags"]["reverse_shell"])

    def test_control_plane_marks_wrapper_backed_claude_gpt_tasks(self) -> None:
        target = self.runtime.store.list_targets()[0]
        task = Task(
            target_id=target.id,
            phase=MethodologyPhase.ANALYSIS,
            kind=TaskKind.REVIEW_PREMIUM_ESCALATION,
            title="Claude/GPT wrapper review",
            summary="Show local chat wrapper routing in the web GUI.",
            role=AgentRole.CLAUDE_REVIEWER,
            provider_route=ProviderRoute.REMOTE_PREMIUM,
            metadata={
                "local_chat_wrapper": "agent_chat_api",
                "remote_premium_local_wrapper": True,
            },
        )
        self.runtime.store.insert_task(task)

        response = self.app.dispatch("GET", "/api/control-plane")
        payload = json.loads(response.body)
        rows = [item for item in payload["tasks"] if item["id"] == task.id]

        self.assertEqual(response.status, 200)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["local_chat_wrapper"], "agent_chat_api")
        self.assertTrue(rows[0]["remote_premium_local_wrapper"])
        self.assertEqual(rows[0]["wrapper_label"], "agent_chat_api wrapper")
        self.assertIn("local chat wrapper", rows[0]["wrapper_detail"])

    def test_control_plane_handles_administration_phase_tasks(self) -> None:
        target = self.runtime.store.list_targets()[0]
        task = Task(
            target_id=target.id,
            phase=MethodologyPhase.ADMINISTRATION,
            kind=TaskKind.COMPACT_MEMORY,
            title="Administrative maintenance",
            summary="Persisted administrative task should not break the dashboard payload.",
            role=AgentRole.MEMORY_WORKER,
            provider_route=ProviderRoute.LOCAL_COMPACT,
            provider_model="fixture-compact",
        )
        self.runtime.store.insert_task(task)

        response = self.app.dispatch("GET", "/api/control-plane")
        payload = json.loads(response.body)
        task_ids = {item["id"] for item in payload["tasks"]}

        self.assertEqual(response.status, 200)
        self.assertIn(task.id, task_ids)

    def test_control_plane_handles_legacy_collection_phase_primitives(self) -> None:
        primitive = PrimitiveManifest(
            name="legacy-collection-phase",
            version="1",
            description="Legacy primitive row using collection as an allowed phase.",
            capability_tags=["legacy-collection"],
            allowed_phases=[MethodologyPhase.COLLECTION],
            runtime=PrimitiveRuntime.HOST,
            risk_tier=RiskTier.LOW,
            side_effect_level=SideEffectLevel.READ_ONLY,
        )
        self.runtime.store.insert_primitive(primitive)

        response = self.app.dispatch("GET", "/api/control-plane")
        payload = json.loads(response.body)

        self.assertEqual(response.status, 200)
        self.assertEqual(payload["runtime"]["health"], "OK")

    def test_control_plane_handles_legacy_integration_runtime_primitives(self) -> None:
        primitive = PrimitiveManifest(
            name="legacy-integration-runtime",
            version="1",
            description="Legacy primitive row using integration as a primitive runtime.",
            capability_tags=["legacy-integration"],
            allowed_phases=[MethodologyPhase.ADMINISTRATION],
            runtime=PrimitiveRuntime.INTEGRATION,
            risk_tier=RiskTier.LOW,
            side_effect_level=SideEffectLevel.NONE,
        )
        self.runtime.store.insert_primitive(primitive)

        response = self.app.dispatch("GET", "/api/control-plane")
        payload = json.loads(response.body)

        self.assertEqual(response.status, 200)
        self.assertEqual(payload["runtime"]["health"], "OK")

    def test_control_plane_live_metrics_force_refreshes_system_payload(self) -> None:
        metrics = {
            "cpu": {"available": True, "percent": 37.0, "memory": {"percent": 48.0}},
            "gpu": {
                "available": True,
                "percent": 64.0,
                "memory_percent": 25.0,
                "memory_used_mb": 2000.0,
                "memory_free_mb": 6000.0,
                "memory_total_mb": 8000.0,
            },
            "network": {"available": True, "rx_label": "1.0 KB/s", "tx_label": "2.0 KB/s"},
        }

        with patch.object(self.runtime, "system_metrics_payload", return_value=metrics) as mocked_metrics:
            response = self.app.dispatch("GET", "/api/control-plane?live_metrics=1")

        payload = json.loads(response.body)
        self.assertEqual(response.status, 200)
        self.assertEqual(payload["runtime"]["cpu"], 0.37)
        self.assertEqual(payload["runtime"]["gpu"], 0.64)
        self.assertEqual(payload["runtime"]["mem"], 0.48)
        self.assertEqual(payload["runtime"]["gpuMemory"]["free_label"], "6000 MB")
        mocked_metrics.assert_any_call(force_refresh=True)

    def test_system_metrics_endpoint_returns_live_runtime_metric_shape(self) -> None:
        metrics = {
            "cpu": {"available": True, "percent": 41.0, "memory": {"percent": 52.0}},
            "gpu": {
                "available": True,
                "percent": 73.0,
                "memory_percent": 50.0,
                "memory_used_mb": 4096.0,
                "memory_free_mb": 4096.0,
                "memory_total_mb": 8192.0,
            },
            "network": {"available": True, "rx_label": "4.0 KB/s", "tx_label": "8.0 KB/s"},
        }

        with patch.object(self.runtime, "system_metrics_payload", return_value=metrics) as mocked_metrics:
            response = self.app.dispatch("GET", "/api/system-metrics")

        payload = json.loads(response.body)
        self.assertEqual(response.status, 200)
        self.assertEqual(payload["runtime"]["cpu"], 0.41)
        self.assertEqual(payload["runtime"]["gpu"], 0.73)
        self.assertEqual(payload["runtime"]["mem"], 0.52)
        self.assertEqual(payload["runtime"]["netIn"], "4.0 KB/s")
        self.assertEqual(payload["runtime"]["gpuMemory"]["used_label"], "4096 / 8192 MB")
        mocked_metrics.assert_called_once_with(force_refresh=True)

    def test_self_test_is_deterministic_and_does_not_call_generation(self) -> None:
        with patch.object(self.runtime.ollama, "is_reachable", return_value=False), patch.object(
            self.runtime.ollama,
            "list_models",
            return_value=OllamaModelListResult(ok=True, models=["gemma4:e4b"]),
        ), patch.object(self.runtime.ollama, "generate") as generate:
            response = self.app.dispatch("GET", "/api/self-test")

        payload = json.loads(response.body)

        self.assertEqual(response.status, 200)
        self.assertIn(payload["status"], {"pass", "warn"})
        self.assertIn("checks", payload)
        self.assertIn("model_listing", {item["id"] for item in payload["checks"]})
        generate.assert_not_called()

    def test_control_plane_groups_repeated_traces_and_filters_target_views(self) -> None:
        target = self.runtime.store.get_target_by_handle("pirate.htb")
        self.assertIsNotNone(target)
        assert target is not None
        self.runtime.register_target(
            handle="alpha.htb",
            profile=ScopeProfile.HACK_THE_BOX,
            assets=["alpha.htb"],
            emit_event=False,
        )
        for _ in range(3):
            self.runtime.store.insert_trace(
                AgentTrace(
                    task_id=None,
                    role=AgentRole.ANALYSIS_WORKER,
                    status="completed",
                    summary="Repeated trace",
                    metadata={"target": "pirate.htb", "task_type": "analysis.repeat", "model": "fixture"},
                )
            )

        response = self.app.dispatch("GET", "/api/control-plane?target=pirate.htb")
        payload = json.loads(response.body)
        children = payload["traces"][0]["children"]

        self.assertEqual(response.status, 200)
        self.assertEqual({item["handle"] for item in payload["scope"]}, {"pirate.htb"})
        self.assertTrue(any(item["summary"] == "Repeated trace" and item["count"] == 3 for item in children))
        trace_group = next(item for item in children if item["summary"] == "Repeated trace")
        self.assertEqual(len(trace_group["member_ids"]), 3)
        inspect_response = self.app.dispatch("GET", f"/api/inspect/group/{trace_group['id']}")
        inspect_payload = json.loads(inspect_response.body)
        self.assertEqual(inspect_response.status, 200)
        self.assertEqual(inspect_payload["count"], 3)
        self.assertEqual(inspect_payload["duplicate_group"]["kind"], "trace")
        self.assertTrue(all(pin["kind"] != "target" or "pirate.htb" in pin["label"] for pin in payload["geo"]["pins"]))

    def test_control_plane_groups_completed_tasks_and_hints_missing_compact_model(self) -> None:
        target = self.runtime.store.get_target_by_handle("pirate.htb")
        self.assertIsNotNone(target)
        assert target is not None
        for index in range(2):
            task = Task(
                target_id=target.id,
                phase=MethodologyPhase.RECON,
                kind=TaskKind.RECON_SCAN,
                title=f"Completed recon {index}",
                summary="Repeated completed recon task.",
                role=AgentRole.RECON_WORKER,
                status=TaskStatus.SUCCEEDED,
                provider_route=ProviderRoute.LOCAL_FAST,
                provider_model="gemma4:e4b",
                metadata={"active_ip_generation": 3},
            )
            self.runtime.store.insert_task(task)
        invalid = Task(
            target_id=None,
            phase=MethodologyPhase.RECON,
            kind=TaskKind.RECON_SCAN,
            title="Blocked invalid target",
            summary="Stale invalid-target row.",
            role=AgentRole.RECON_WORKER,
            status=TaskStatus.BLOCKED,
            metadata={"invalid_target": True},
        )
        self.runtime.store.insert_task(invalid)
        compact = Task(
            target_id=target.id,
            phase=MethodologyPhase.MEMORY_MAINTENANCE,
            kind=TaskKind.COMPACT_MEMORY,
            title="Compact memory",
            summary="Queued compact task.",
            role=AgentRole.MEMORY_WORKER,
            status=TaskStatus.PENDING,
            provider_route=ProviderRoute.LOCAL_COMPACT,
            provider_model="phi4-reasoning",
        )
        self.runtime.store.insert_task(compact)

        response = self.app.dispatch("GET", "/api/control-plane")
        payload = json.loads(response.body)
        tasks = payload["tasks"]

        self.assertTrue(any(item.get("grouped_count") == 2 for item in tasks))
        self.assertFalse(any(item["id"] == invalid.id for item in tasks))
        compact_row = next(item for item in tasks if item["id"] == compact.id)
        self.assertIn("Missing local model hint", compact_row["hint"])

    def test_control_plane_groups_failed_duplicate_tasks(self) -> None:
        target = self.runtime.store.get_target_by_handle("pirate.htb")
        self.assertIsNotNone(target)
        assert target is not None
        for index in range(2):
            self.runtime.store.insert_task(
                Task(
                    target_id=target.id,
                    phase=MethodologyPhase.RECON,
                    kind=TaskKind.RECON_SCAN,
                    title="Run recon sweep",
                    summary="Repeated failed recon task.",
                    role=AgentRole.RECON_WORKER,
                    status=TaskStatus.FAILED,
                    provider_route=ProviderRoute.LOCAL_FAST,
                    provider_model="gemma4:e4b",
                    metadata={"active_ip_generation": 5, "error": f"boom {index}"},
                )
            )

        response = self.app.dispatch("GET", "/api/control-plane")
        payload = json.loads(response.body)
        grouped = next(item for item in payload["tasks"] if item.get("grouped_count") == 2 and item.get("status") == "failed")

        self.assertIn("failed 2 times", grouped["title"])
        self.assertEqual(len(grouped["raw"]["grouped_task_ids"]), 2)
        inspect_response = self.app.dispatch("GET", f"/api/inspect/group/{grouped['id']}")
        inspect_payload = json.loads(inspect_response.body)
        self.assertEqual(inspect_response.status, 200)
        self.assertEqual(inspect_payload["duplicate_group"]["kind"], "task")
        self.assertEqual(inspect_payload["count"], 2)

    def test_inspect_task_endpoint_returns_related_records_and_error_detail(self) -> None:
        target = self.runtime.store.get_target_by_handle("pirate.htb")
        self.assertIsNotNone(target)
        assert target is not None
        task = Task(
            target_id=target.id,
            phase=MethodologyPhase.RECON,
            kind=TaskKind.RECON_SCAN,
            title="Inspectable failed task",
            summary="Task with related runtime records.",
            role=AgentRole.RECON_WORKER,
            status=TaskStatus.FAILED,
            provider_route=ProviderRoute.LOCAL_FAST,
            provider_model="gemma4:e4b",
            metadata={"error": "fixture failure", "traceback": "Traceback fixture"},
        )
        self.runtime.store.insert_task(task)
        run = TaskRun(
            task_id=task.id,
            status=TaskRunStatus.FAILED,
            attempt_number=1,
            role=AgentRole.RECON_WORKER,
            provider_route=ProviderRoute.LOCAL_FAST,
            model_name="gemma4:e4b",
            error="fixture run failure",
            metadata={"traceback": "Run traceback fixture"},
        )
        self.runtime.store.insert_task_run(run)
        self.runtime.store.insert_trace(
            AgentTrace(
                task_id=task.id,
                role=AgentRole.RECON_WORKER,
                status="failed",
                summary="Trace failed",
                metadata={"error": "trace failure", "traceback": "Trace traceback fixture", "model": "gemma4:e4b"},
            )
        )
        self.runtime.store.insert_event(
            EventRecord(
                type=EventType.TASK_FAILED,
                task_id=task.id,
                target_id=target.id,
                summary="Task failed",
                metadata={"error": "event failure"},
            )
        )

        response = self.app.dispatch("GET", f"/api/inspect/task/{task.id}")
        payload = json.loads(response.body)

        self.assertEqual(response.status, 200)
        self.assertEqual(payload["record"]["id"], task.id)
        self.assertEqual(payload["related"]["task"]["id"], task.id)
        self.assertTrue(payload["related"]["runs"])
        self.assertTrue(payload["related"]["traces"])
        self.assertTrue(payload["error_detail"]["available"])
        self.assertTrue(payload["error_detail"]["stack_available"])

    def test_inspect_artifact_preview_is_runtime_root_limited_and_redacted(self) -> None:
        target = self.runtime.store.get_target_by_handle("pirate.htb")
        self.assertIsNotNone(target)
        assert target is not None
        artifact_path = self.runtime.config.artifacts_dir / "inspect-fixture.txt"
        artifact_path.write_text("token: super-secret-value\nnormal line\n", encoding="utf-8")
        artifact = ArtifactRecord(
            task_id=None,
            target_id=target.id,
            kind=ArtifactKind.TOOL_OUTPUT,
            path=str(artifact_path),
            sha256=hashlib.sha256(artifact_path.read_bytes()).hexdigest(),
            size_bytes=artifact_path.stat().st_size,
        )
        self.runtime.store.insert_artifact(artifact)

        response = self.app.dispatch("GET", f"/api/inspect/artifact/{artifact.id}")
        payload = json.loads(response.body)

        self.assertEqual(response.status, 200)
        self.assertTrue(payload["artifact_preview"]["available"])
        self.assertIn("[redacted]", payload["artifact_preview"]["text"])
        self.assertNotIn("super-secret-value", payload["artifact_preview"]["text"])

    def test_ui_command_endpoint_creates_proposal_only_approval(self) -> None:
        response = self.app.dispatch(
            "POST",
            "/api/ui/commands",
            json.dumps({"command": "geo-probe-pin", "target": "pirate.htb", "title": "Probe selected geo pin"}).encode("utf-8"),
        )
        payload = json.loads(response.body)
        proposal = payload["result"]["proposal"]

        self.assertEqual(response.status, 200)
        self.assertEqual(proposal["status"], "needs_approval")
        self.assertTrue(proposal["requires_approval"])
        self.assertTrue(proposal["metadata"]["proposal_only"])
        self.assertEqual(proposal["metadata"]["ui_command"], "geo-probe-pin")

        approve_response = self.app.dispatch(
            "POST",
            "/api/actions/approve",
            json.dumps({"task_id": proposal["id"]}).encode("utf-8"),
        )
        approve = json.loads(approve_response.body)
        stored = self.runtime.store.get_task(proposal["id"])

        self.assertEqual(approve_response.status, 200)
        self.assertEqual(approve["result"]["status"], "succeeded")
        self.assertIsNotNone(stored)
        assert stored is not None
        self.assertTrue(stored.metadata["proposal_resolved"])
        self.assertTrue(stored.metadata["proposal_approved"])

    def test_ops_approval_buttons_resolve_credentialed_access_tasks(self) -> None:
        target = self.runtime.store.get_target_by_handle("pirate.htb")
        self.assertIsNotNone(target)
        assert target is not None
        self.runtime.set_operator_intent("credential_validation")
        self.runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=target.id,
                type=EvidenceType.TOOL_OUTPUT,
                title="Windows remote access services",
                summary="Observed Microsoft Windows SMB and WinRM surfaces.",
                source_ref="fixture://windows-remote-access",
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.86,
                freshness=0.9,
                metadata={
                    "kind": "tcp_service_discovery",
                    "open_services": [
                        {"port": 445, "service": "microsoft-ds", "product": "Microsoft Windows Server 2019"},
                        {"port": 5985, "service": "winrm", "product": "Microsoft HTTPAPI httpd"},
                    ],
                },
            )
        )
        approve_task = Task(
            target_id=target.id,
            phase=MethodologyPhase.EXPLOITATION,
            kind=TaskKind.CREDENTIALED_ACCESS_CHECK,
            title="Verify credentialed SMB/WinRM access",
            summary="Use configured known credentials to verify access for pirate.htb.",
            role=AgentRole.EXPLOITATION_WORKER,
            risk_tier=RiskTier.HIGH,
            status=TaskStatus.NEEDS_APPROVAL,
            requires_approval=True,
        )
        deny_task = Task(
            target_id=target.id,
            phase=MethodologyPhase.EXPLOITATION,
            kind=TaskKind.CREDENTIALED_ACCESS_CHECK,
            title="Verify credentialed SMB/WinRM access",
            summary="Use configured known credentials to verify access for pirate.htb.",
            role=AgentRole.EXPLOITATION_WORKER,
            risk_tier=RiskTier.HIGH,
            status=TaskStatus.NEEDS_APPROVAL,
            requires_approval=True,
        )
        self.runtime.store.insert_task(approve_task)
        self.runtime.store.insert_task(deny_task)

        control_response = self.app.dispatch("GET", "/api/control-plane")
        control_payload = json.loads(control_response.body)
        approval_ids = {item["task"] for item in control_payload["approvals"]}

        self.assertEqual(control_response.status, 200)
        self.assertIn(approve_task.id, approval_ids)
        self.assertIn(deny_task.id, approval_ids)

        with patch.object(self.runtime, "run_tick") as run_tick:
            approve_response = self.app.dispatch(
                "POST",
                "/api/actions/approve",
                json.dumps({"task_id": approve_task.id}).encode("utf-8"),
            )
        deny_response = self.app.dispatch(
            "POST",
            "/api/actions/deny",
            json.dumps({"task_id": deny_task.id}).encode("utf-8"),
        )
        approved = self.runtime.store.get_task(approve_task.id)
        denied = self.runtime.store.get_task(deny_task.id)

        self.assertEqual(approve_response.status, 200)
        self.assertEqual(deny_response.status, 200)
        self.assertIsNotNone(approved)
        self.assertIsNotNone(denied)
        assert approved is not None
        assert denied is not None
        self.assertEqual(approved.status, TaskStatus.PENDING)
        self.assertFalse(approved.requires_approval)
        self.assertEqual(denied.status, TaskStatus.CANCELLED)
        run_tick.assert_called_once_with(max_executions=1)

    def test_approval_inquiry_answers_from_task_and_evidence(self) -> None:
        target = self.runtime.store.get_target_by_handle("pirate.htb")
        self.assertIsNotNone(target)
        assert target is not None
        evidence = EvidenceRecord(
            target_id=target.id,
            type=EvidenceType.TOOL_OUTPUT,
            title="HTTP header evidence",
            summary="HTTP service responded with a bounded banner capture.",
            source_ref="fixture://http-headers",
            verification_status=VerificationStatus.VERIFIED,
            confidence=0.88,
            freshness=0.9,
            metadata={"kind": "http_probe"},
        )
        self.runtime.store.insert_evidence(evidence)
        task = Task(
            target_id=target.id,
            phase=MethodologyPhase.RECON,
            kind=TaskKind.RECON_SCAN,
            title="HTTP Header Analysis and Parameter Discovery",
            summary="Review HTTP headers before proposing any follow-up.",
            role=AgentRole.RECON_WORKER,
            risk_tier=RiskTier.LOW,
            status=TaskStatus.NEEDS_APPROVAL,
            requires_approval=True,
            evidence_refs=[evidence.id],
            metadata={"primitive_hint": "http-probe"},
        )
        self.runtime.store.insert_task(task)

        exact_response = self.app.dispatch(
            "POST",
            "/api/approvals/inquiry",
            json.dumps({"task_id": task.id, "message": "show me the exact request"}).encode("utf-8"),
        )
        evidence_response = self.app.dispatch(
            "POST",
            "/api/approvals/inquiry",
            json.dumps({"task_id": task.id, "message": "what evidence backs this?"}).encode("utf-8"),
        )

        exact = json.loads(exact_response.body)["result"]["chat"]["answer"]["body"]
        backed = json.loads(evidence_response.body)["result"]["chat"]["answer"]["body"]
        stored = self.runtime.store.get_task(task.id)

        self.assertEqual(exact_response.status, 200)
        self.assertEqual(evidence_response.status, 200)
        self.assertIn("**Approval Request**", exact)
        self.assertIn(task.id, exact)
        self.assertIn("`http-probe`", exact)
        self.assertNotIn("Approval note recorded locally", exact)
        self.assertIn("**Evidence Check**", backed)
        self.assertIn(evidence.id, backed)
        self.assertEqual(stored.status, TaskStatus.NEEDS_APPROVAL)

    def test_operator_next_steps_do_not_use_searchsploit_without_versioned_evidence(self) -> None:
        target = self.runtime.store.get_target_by_handle("pirate.htb")
        self.assertIsNotNone(target)
        assert target is not None
        self.runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=target.id,
                type=EvidenceType.TOOL_OUTPUT,
                title="TCP service discovery",
                summary="TCP connect checks completed; no service versions were identified.",
                source_ref="fixture://tcp-discovery",
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.7,
                freshness=0.9,
                metadata={"kind": "tcp_service_discovery", "open_services": []},
            )
        )

        answer = self.runtime.ask_operator_ai("next 3 scoped recon steps", target=target.handle)["answer"]["body"]

        self.assertNotIn("Run evidence-backed Searchsploit research", answer)
        self.assertIn("Collect current service/version evidence before Searchsploit research", answer)

    def test_generated_web_bundle_has_no_fixture_switch_or_payload(self) -> None:
        generated = Path("primordial/core/web/frontend/src/generated-gui.jsx").read_text(encoding="utf-8")
        static_assets = Path("primordial/core/web/static/assets")
        bundle_text = "\n".join(path.read_text(encoding="utf-8") for path in static_assets.glob("*.js"))
        forbidden = [
            "PD_" + "DE" + "MO_DATA",
            "de" + "mo=1",
            ">DE" + "MO<",
            "window.PD_" + "DE" + "MO_DATA",
            "dom_pirate",
            "14:02:11",
            "fake live sparklines",
            "https://cdn.jsdelivr.net/npm/world-atlas",
            "target.local",
            "example.htb",
            "mock-pirate",
        ]

        for text in (generated, bundle_text):
            for token in forbidden:
                self.assertNotIn(token, text)
            for token in [
                "Target scope editor",
                "Target / domain",
                "Current IP",
                "Scope profile",
                "ADVANCED ASSETS",
                "Operator Intent still gates actions",
                "/api/runtime-control",
                "/api/credentials",
                "/api/integrations/caido",
                "http://127.0.0.1:8650/graphql",
                "AUTH FAILED",
                "HEALTH CHECK",
                "Health OK",
                "refreshCredentials",
                "refreshCaido",
                "auth-blocked",
                "USE TARGET SCOPE",
                "NO LIVE CAIDO TRAFFIC FOR CURRENT FILTER",
                "IMPORTED CAPTURES",
                "SEED TARGET GET",
                "SAVE CREDENTIALS",
                "Stored credentials",
                "Claude/GPT",
                "agent_chat_api wrapper",
                "remote_premium_local_wrapper",
                "Answer Citations",
                "READABLE",
                "RAW",
                "Evaluation Probes",
                "CVE/Vuln Sync",
                "Vulnerability Intel",
                "/api/rag/status",
                "/api/rag/search",
                "/api/rag/synthesize",
                "/api/rag/vuln/status",
                "/api/rag/vuln/sync",
                "/api/rag/vuln/search",
            ]:
                self.assertIn(token, text)
            self.assertNotIn("pirate.htb scope", text)
            self.assertNotIn("http://127.0.0.1:8080/graphql", text)
            self.assertNotIn("live_metrics=1", text)
            self.assertNotIn("FULL_REFRESH_MS", text)
        self.assertIn("aria-label={`Edit ${activeCredentialGroup.n} ${label}`}", generated)
        self.assertIn("runtimeDraftDirty", generated)
        self.assertIn("aria-label", bundle_text)
        self.assertNotIn("'integrations', 'credentials'", generated)
        self.assertNotIn("dangerouslySetInnerHTML", generated)

    def test_target_registration_endpoint_updates_scope(self) -> None:
        response = self.app.dispatch(
            "POST",
            "/api/targets",
            json.dumps(
                {
                    "handle": "pirate.htb",
                    "display_name": "Pirate HTB",
                    "profile": "hack_the_box",
                    "assets": ["pirate.htb", "10.129.47.117"],
                    "active_ip": "10.129.47.117",
                    "in_scope": True,
                    "metadata": {"target_kind": "htb_lab"},
                }
            ).encode("utf-8"),
        )
        payload = json.loads(response.body)

        self.assertEqual(response.status, 200)
        self.assertEqual(payload["result"]["target"]["handle"], "pirate.htb")
        self.assertEqual(payload["result"]["target"]["metadata"]["active_ip"], "10.129.47.117")
        self.assertEqual(payload["result"]["target"]["metadata"]["target_kind"], "htb_lab")
        self.assertIn("scope", payload)
        self.assertIn("scopePayload", payload)
        self.assertIn("scopeProfiles", payload)
        self.assertNotIn("control_plane", payload)
        scope = json.loads(self.app.dispatch("GET", "/api/scope").body)
        self.assertTrue(any(item["target"]["handle"] == "pirate.htb" for item in scope["targets"]))

    def test_target_registration_auto_adds_active_ip_asset(self) -> None:
        response = self.app.dispatch(
            "POST",
            "/api/targets",
            json.dumps(
                {
                    "handle": "helix.htb",
                    "display_name": "helix.htb",
                    "profile": "hack_the_box",
                    "assets": ["helix.htb"],
                    "active_ip": "10.129.54.140",
                    "in_scope": True,
                }
            ).encode("utf-8"),
        )
        payload = json.loads(response.body)
        target = self.runtime.store.get_target_by_handle("helix.htb", ScopeProfile.HACK_THE_BOX)

        self.assertEqual(response.status, 200)
        self.assertEqual(payload["result"]["target"]["handle"], "helix.htb")
        self.assertEqual(payload["result"]["target"]["metadata"]["active_ip"], "10.129.54.140")
        self.assertIsNotNone(target)
        assert target is not None
        assets = {item.asset for item in self.runtime.store.list_scope_assets(target.id)}
        self.assertIn("helix.htb", assets)
        self.assertIn("10.129.54.140", assets)

    def test_target_registration_can_replace_scope_assets_when_active_ip_changes(self) -> None:
        first = self.app.dispatch(
            "POST",
            "/api/targets",
            json.dumps(
                {
                    "handle": "helix.htb",
                    "display_name": "helix.htb",
                    "profile": "hack_the_box",
                    "assets": ["helix.htb", "10.129.54.140"],
                    "active_ip": "10.129.54.140",
                    "in_scope": True,
                    "replace_scope_assets": True,
                }
            ).encode("utf-8"),
        )
        second = self.app.dispatch(
            "POST",
            "/api/targets",
            json.dumps(
                {
                    "handle": "helix.htb",
                    "display_name": "helix.htb",
                    "profile": "hack_the_box",
                    "assets": ["helix.htb"],
                    "active_ip": "10.129.99.99",
                    "in_scope": True,
                    "replace_scope_assets": True,
                }
            ).encode("utf-8"),
        )
        target = self.runtime.store.get_target_by_handle("helix.htb", ScopeProfile.HACK_THE_BOX)

        self.assertEqual(first.status, 200)
        self.assertEqual(second.status, 200)
        self.assertIsNotNone(target)
        assert target is not None
        assets = {item.asset for item in self.runtime.store.list_scope_assets(target.id)}
        self.assertEqual(assets, {"helix.htb", "10.129.99.99"})
        self.assertEqual(target.metadata["active_ip"], "10.129.99.99")
        self.assertEqual(target.metadata["active_ip_generation"], 2)
        notes = self.runtime.store.list_notes(target_id=target.id, limit=10)
        self.assertTrue(any(note.metadata.get("previous_ip") == "10.129.54.140" for note in notes))

    def test_target_registration_rejects_invalid_active_ip(self) -> None:
        response = self.app.dispatch(
            "POST",
            "/api/targets",
            json.dumps(
                {
                    "handle": "pirate.htb",
                    "profile": "hack_the_box",
                    "assets": ["pirate.htb"],
                    "active_ip": "not-an-ip",
                }
            ).encode("utf-8"),
        )
        payload = json.loads(response.body)

        self.assertEqual(response.status, 400)
        self.assertIn("invalid IP address", payload["error"])

    def test_scope_profile_presets_can_be_managed_and_resolved(self) -> None:
        saved = self.runtime.upsert_scope_profile(
            profile_id="htb_windows_ad",
            label="HTB Windows AD",
            base_profile="hack_the_box",
            description="Windows AD lab preset.",
        )

        ids = {item["id"] for item in saved["profiles"]}
        self.assertIn("hack_the_box", ids)
        self.assertIn("hackerone", ids)
        self.assertIn("htb_windows_ad", ids)
        self.assertEqual(saved["saved"], "htb_windows_ad")
        self.assertEqual(self.runtime.resolve_scope_profile("htb_windows_ad"), ScopeProfile.HACK_THE_BOX)

        imported = self.runtime.import_scope_payload(
            {
                "profile": "htb_windows_ad",
                "targets": [{"handle": "custom.htb", "assets": ["custom.htb"]}],
            },
            source_name="custom-profile-test",
        )
        self.assertEqual(imported["profile"], ScopeProfile.HACK_THE_BOX.value)

        response = self.app.dispatch(
            "POST",
            "/api/targets",
            json.dumps(
                {
                    "handle": "preset.htb",
                    "profile": "htb_windows_ad",
                    "assets": ["preset.htb"],
                    "in_scope": True,
                }
            ).encode("utf-8"),
        )
        payload = json.loads(response.body)
        self.assertEqual(response.status, 200)
        self.assertEqual(payload["result"]["target"]["profile"], ScopeProfile.HACK_THE_BOX.value)

        deleted = self.runtime.delete_scope_profile("htb_windows_ad")
        self.assertTrue(deleted["removed"])
        self.assertNotIn("htb_windows_ad", {item["id"] for item in deleted["profiles"]})
        with self.assertRaises(ValueError):
            self.runtime.delete_scope_profile("hack_the_box")

    def test_scope_import_endpoint_adds_multiple_targets(self) -> None:
        response = self.app.dispatch(
            "POST",
            "/api/scope/import",
            json.dumps(
                {
                    "profile": "hack_the_box",
                    "source": "web-test.json",
                    "scope": {
                        "targets": [
                            {"handle": "alpha.htb", "assets": ["alpha.htb", "10.10.10.10"]},
                            {"handle": "beta.htb", "assets": [{"asset": "https://beta.htb", "asset_type": "webapp"}]},
                        ]
                    },
                }
            ).encode("utf-8"),
        )
        payload = json.loads(response.body)

        self.assertEqual(response.status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["action"], "import-scope")
        self.assertEqual(payload["result"]["targets_imported"], 2)
        self.assertEqual(payload["result"]["assets_imported"], 3)
        scope = json.loads(self.app.dispatch("GET", "/api/scope").body)
        handles = {item["target"]["handle"] for item in scope["targets"]}
        self.assertIn("alpha.htb", handles)
        self.assertIn("beta.htb", handles)

    def test_target_removal_endpoint_updates_scope(self) -> None:
        response = self.app.dispatch("DELETE", "/api/targets/pirate.htb?profile=hack_the_box")
        payload = json.loads(response.body)

        self.assertEqual(response.status, 200)
        self.assertTrue(payload["result"]["removed"])
        scope = json.loads(self.app.dispatch("GET", "/api/scope").body)
        self.assertEqual(scope["targets"], [])

    def test_target_removal_blocks_linked_runtime_records(self) -> None:
        target = self.runtime.store.get_target_by_handle("pirate.htb", ScopeProfile.HACK_THE_BOX)
        self.assertIsNotNone(target)
        self.runtime.store.insert_evidence(
            EvidenceRecord(
                id="evidence_delete_guard",
                target_id=target.id,
                type=EvidenceType.SCANNER_OUTPUT,
                title="Preserved runtime evidence",
                summary="Runtime evidence must not be deleted by target cleanup.",
                source_ref="test",
                verification_status=VerificationStatus.PARTIAL,
            )
        )

        response = self.app.dispatch("DELETE", "/api/targets/pirate.htb?profile=hack_the_box")
        payload = json.loads(response.body)

        self.assertEqual(response.status, 409)
        self.assertFalse(payload["ok"])
        self.assertTrue(payload["result"]["blocked"])
        self.assertEqual(payload["result"]["runtime_record_counts"]["evidence"], 1)
        self.assertIsNotNone(self.runtime.store.get_target_by_handle("pirate.htb", ScopeProfile.HACK_THE_BOX))
        self.assertTrue(self.runtime.store.target_has_evidence(target.id))

    def test_database_trigger_blocks_direct_runtime_deletes(self) -> None:
        target = self.runtime.store.get_target_by_handle("pirate.htb", ScopeProfile.HACK_THE_BOX)
        self.assertIsNotNone(target)

        with self.assertRaises(Exception):
            with self.runtime.store.connect() as connection:
                connection.execute("DELETE FROM targets WHERE id = %s", (target.id,))
                connection.commit()

        self.assertIsNotNone(self.runtime.store.get_target_by_handle("pirate.htb", ScopeProfile.HACK_THE_BOX))

    def test_credentials_and_records_endpoints_are_practical(self) -> None:
        notion_response = self.app.dispatch(
            "POST",
            "/api/credentials/notion",
            json.dumps(
                {
                    "api_key": "secret_notion_token",
                    "parent_page_id": "parent123",
                    "version": "2022-06-28",
                }
            ).encode("utf-8"),
        )
        discord_response = self.app.dispatch(
            "POST",
            "/api/credentials/discord",
            json.dumps({"webhook_url": "https://discord.com/api/webhooks/123/token"}).encode("utf-8"),
        )
        caido_response = self.app.dispatch(
            "POST",
            "/api/credentials/caido",
            json.dumps(
                {
                    "graphql_url": "http://127.0.0.1:8650/graphql",
                    "api_token": "caido-secret-token",
                }
            ).encode("utf-8"),
        )
        credentials_response = self.app.dispatch("GET", "/api/credentials")
        records_response = self.app.dispatch("GET", "/api/records?limit=5")

        self.assertEqual(notion_response.status, 200)
        self.assertEqual(discord_response.status, 200)
        self.assertEqual(caido_response.status, 200)
        self.assertEqual(credentials_response.status, 200)
        self.assertEqual(records_response.status, 200)

        credentials = json.loads(credentials_response.body)
        serialized = json.dumps(credentials)
        self.assertNotIn("secret_notion_token", serialized)
        self.assertNotIn("discord.com/api/webhooks/123/token", serialized)
        self.assertNotIn("caido-secret-token", serialized)
        self.assertTrue(credentials["services"]["notion"]["api_key"]["configured"])
        self.assertTrue(credentials["services"]["discord"]["webhook_url"]["configured"])
        self.assertTrue(credentials["services"]["caido"]["api_token"]["configured"])

        records = json.loads(records_response.body)
        self.assertIn("evidence", records)
        self.assertIn("primitives", records)

    def test_discord_credential_save_rejects_non_webhook_urls(self) -> None:
        channel_response = self.app.dispatch(
            "POST",
            "/api/credentials/discord",
            json.dumps({"webhook_url": "https://discord.com/channels/1/2"}).encode("utf-8"),
        )
        malformed_response = self.app.dispatch(
            "POST",
            "/api/credentials/discord",
            json.dumps({"webhook_url": "http://discord.com/api/webhooks/123/token"}).encode("utf-8"),
        )

        self.assertEqual(channel_response.status, 400)
        self.assertEqual(malformed_response.status, 400)
        self.assertIn("/api/webhooks", json.loads(channel_response.body)["error"])
        self.assertIn("HTTPS", json.loads(malformed_response.body)["error"])

    def test_discord_405_marks_webhook_configuration_invalid(self) -> None:
        self.runtime.set_discord_credentials(webhook_url="https://discord.com/api/webhooks/123/token")
        first = NotificationRecord(channel=NotificationChannel.DISCORD, event_type="approval_needed", summary="one")
        second = NotificationRecord(channel=NotificationChannel.DISCORD, event_type="finding_candidate", summary="two")
        self.runtime.store.insert_notification(first)
        self.runtime.store.insert_notification(second)

        def method_not_allowed(req, timeout):
            raise __import__("urllib.error").error.HTTPError(
                req.full_url,
                405,
                "Method Not Allowed",
                {},
                io.BytesIO(b"method not allowed"),
            )

        with patch("primordial.adapters.discord.request.urlopen", side_effect=method_not_allowed):
            delivered = self.runtime.discord.deliver_pending(limit=10)

        self.assertEqual(delivered, 0)
        notifications = {item.id: item for item in self.runtime.store.list_notifications(limit=10)}
        self.assertEqual(notifications[first.id].status, NotificationStatus.FAILED)
        self.assertEqual(notifications[second.id].status, NotificationStatus.FAILED)
        events = self.runtime.store.list_events(limit=10)
        self.assertTrue(any("invalid webhook configuration" in event.summary for event in events))

    def test_discord_transient_failure_keeps_notification_pending_until_retry_limit(self) -> None:
        self.runtime.set_discord_credentials(webhook_url="https://discord.com/api/webhooks/123/token")
        notification = NotificationRecord(
            channel=NotificationChannel.DISCORD,
            event_type="approval_needed",
            summary="retry me",
        )
        self.runtime.store.insert_notification(notification)

        with patch("primordial.adapters.discord.request.urlopen", side_effect=OSError("temporary network failure")):
            delivered = self.runtime.discord.deliver_pending(limit=10)

        self.assertEqual(delivered, 0)
        refreshed = {item.id: item for item in self.runtime.store.list_notifications(limit=10)}[notification.id]
        self.assertEqual(refreshed.status, NotificationStatus.PENDING)
        self.assertEqual(refreshed.metadata["delivery_attempts"], 1)
        self.assertTrue(refreshed.metadata["retryable_delivery_error"])
        deliveries = self.runtime.store.list_discord_deliveries(limit=10)
        self.assertEqual(deliveries[0].status, NotificationStatus.PENDING)

    def test_connector_api_endpoints_have_route_level_contracts(self) -> None:
        raw_request = "GET / HTTP/1.1\nHost: pirate.htb\nConnection: close\n\n"
        raw_sha256 = self.runtime.caido.parse_raw_request(raw_request).raw_sha256

        notion_response = self.app.dispatch(
            "POST",
            "/api/credentials/notion",
            json.dumps(
                {
                    "api_key": "secret_notion_token",
                    "parent_page_id": "parent123",
                    "version": "2022-06-28",
                }
            ).encode("utf-8"),
        )
        discord_response = self.app.dispatch(
            "POST",
            "/api/credentials/discord",
            json.dumps({"webhook_url": "https://discord.com/api/webhooks/123/token"}).encode("utf-8"),
        )
        known_response = self.app.dispatch(
            "POST",
            "/api/credentials/known",
            json.dumps({"username": "operator", "password": "known-secret", "domain": "LAB"}).encode("utf-8"),
        )
        lab_response = self.app.dispatch(
            "POST",
            "/api/credentials/lab",
            json.dumps({"username": "legacy", "password": "legacy-secret", "domain": "LEGACY"}).encode("utf-8"),
        )
        caido_response = self.app.dispatch(
            "POST",
            "/api/credentials/caido",
            json.dumps({"api_token": "caido-secret-token"}).encode("utf-8"),
        )
        credentials_response = self.app.dispatch("GET", "/api/credentials")
        credentials = json.loads(credentials_response.body)
        serialized_credentials = json.dumps(credentials)

        self.assertEqual(notion_response.status, 200)
        self.assertEqual(discord_response.status, 200)
        self.assertEqual(known_response.status, 200)
        self.assertEqual(lab_response.status, 200)
        self.assertEqual(caido_response.status, 200)
        self.assertEqual(credentials_response.status, 200)
        self.assertTrue(credentials["services"]["notion"]["api_key"]["configured"])
        self.assertTrue(credentials["services"]["discord"]["webhook_url"]["configured"])
        self.assertTrue(credentials["services"]["known"]["username"]["configured"])
        self.assertTrue(credentials["services"]["lab"]["username"]["configured"])
        self.assertTrue(credentials["services"]["caido"]["graphql_url"]["configured"])
        self.assertEqual(credentials["services"]["known"]["username"]["hint"], "legacy")
        self.assertEqual(credentials["services"]["lab"]["username"]["hint"], "legacy")
        self.assertEqual(self.runtime.credentials.get("caido", "graphql_url"), CaidoIntegrationService.DEFAULT_GRAPHQL_URL)
        for secret in [
            "secret_notion_token",
            "discord.com/api/webhooks/123/token",
            "known-secret",
            "legacy-secret",
            "caido-secret-token",
        ]:
            self.assertNotIn(secret, serialized_credentials)

        with (
            patch.object(
                self.runtime.caido,
                "search_requests",
                return_value={"ok": True, "httpql": 'req.host.eq:"pirate.htb"', "requests": []},
            ) as search,
            patch.object(
                self.runtime.caido,
                "request_detail",
                return_value={"ok": True, "request": {"id": "42", "host": "pirate.htb"}},
            ) as detail,
            patch.object(
                self.runtime.caido,
                "create_replay_draft",
                return_value={
                    "ok": True,
                    "parsed": {"host": "pirate.htb", "raw_sha256": raw_sha256},
                    "session": {"id": "session-1"},
                },
            ) as draft,
            patch.object(self.runtime.caido, "send_replay", return_value={"ok": True, "task": {"id": "task-1"}}) as send,
        ):
            search_response = self.app.dispatch(
                "POST",
                "/api/integrations/caido/search",
                json.dumps({"target": "pirate.htb", "httpql": 'req.host.eq:"pirate.htb"', "limit": 25}).encode(
                    "utf-8"
                ),
            )
            detail_response = self.app.dispatch("GET", "/api/integrations/caido/requests/42")
            draft_response = self.app.dispatch(
                "POST",
                "/api/integrations/caido/replay/draft",
                json.dumps({"target": "pirate.htb", "raw_request": raw_request}).encode("utf-8"),
            )
            send_response = self.app.dispatch(
                "POST",
                "/api/integrations/caido/replay/send",
                json.dumps(
                    {
                        "target": "pirate.htb",
                        "raw_request": raw_request,
                        "session_id": "session-1",
                        "confirmation": raw_sha256,
                    }
                ).encode("utf-8"),
            )

        search_payload = json.loads(search_response.body)
        detail_payload = json.loads(detail_response.body)
        draft_payload = json.loads(draft_response.body)
        send_payload = json.loads(send_response.body)

        self.assertEqual(search_response.status, 200)
        self.assertEqual(detail_response.status, 200)
        self.assertEqual(draft_response.status, 200)
        self.assertEqual(send_response.status, 200)
        self.assertTrue(search_payload["ok"])
        self.assertTrue(detail_payload["ok"])
        self.assertTrue(draft_payload["ok"])
        self.assertTrue(send_payload["ok"])
        self.assertEqual(send_payload["action"], "caido-replay-send")
        search.assert_called_once_with('req.host.eq:"pirate.htb"', limit=25, offset=0)
        detail.assert_called_once_with("42")
        draft.assert_called_once_with(raw_request)
        send.assert_called_once_with(raw_request, session_id="session-1")

        bad_search = self.app.dispatch(
            "POST",
            "/api/integrations/caido/search",
            json.dumps({"target": "missing.htb"}).encode("utf-8"),
        )
        bad_import = self.app.dispatch(
            "POST",
            "/api/integrations/caido/import",
            json.dumps({"target": "pirate.htb", "request_ids": "42"}).encode("utf-8"),
        )
        bad_draft = self.app.dispatch(
            "POST",
            "/api/integrations/caido/replay/draft",
            json.dumps({"raw_request": raw_request}).encode("utf-8"),
        )
        invalid_clear = self.app.dispatch("DELETE", "/api/credentials/web")

        self.assertEqual(bad_search.status, 400)
        self.assertEqual(bad_import.status, 400)
        self.assertEqual(bad_draft.status, 400)
        self.assertEqual(invalid_clear.status, 400)

        with (
            patch.object(self.runtime.notion, "process_pending", return_value=2) as notion_pending,
            patch.object(self.runtime.discord, "deliver_pending", return_value=3) as discord_pending,
        ):
            process_response = self.app.dispatch("POST", "/api/actions/process-queues")
        process_payload = json.loads(process_response.body)

        self.assertEqual(process_response.status, 200)
        self.assertEqual(process_payload["action"], "process-queues")
        self.assertEqual(process_payload["result"], {"notion_completed": 2, "discord_delivered": 3})
        notion_pending.assert_called_once_with()
        discord_pending.assert_called_once_with()

    def test_operator_chat_uses_local_model_and_persists_messages(self) -> None:
        with patch.object(
            self.runtime.ollama,
            "generate",
            return_value=OllamaResponse(model="gemma4:e4b", text="Primordial is waiting on recon tasks."),
        ) as generate:
            response = self.app.dispatch(
                "POST",
                "/api/chat",
                json.dumps({"message": "Draft a concise operator note.", "target": "pirate.htb"}).encode("utf-8"),
            )

        payload = json.loads(response.body)
        chat_response = self.app.dispatch("GET", "/api/chat?limit=5&target=pirate.htb")
        chat = json.loads(chat_response.body)

        self.assertEqual(response.status, 200)
        self.assertTrue(payload["result"]["chat"]["ok"])
        self.assertEqual(payload["result"]["chat"]["model"], "deepseek-r1:8b")
        self.assertEqual(len(chat["messages"]), 2)
        self.assertEqual(chat["messages"][-1]["role"], "assistant")
        logs = sorted(self.runtime.config.chat_logs_dir.glob("*/*.json"))
        self.assertEqual(len(logs), 2)
        serialized_logs = "\n".join(path.read_text(encoding="utf-8") for path in logs)
        self.assertIn("Draft a concise operator note.", serialized_logs)
        self.assertIn("Primordial is waiting on recon tasks.", serialized_logs)
        generate.assert_called_once()

    def test_operator_chat_view_surfaces_wrapper_model_label(self) -> None:
        self.runtime.store.insert_operator_message(
            OperatorMessage(role="operator", body="test", target_id=None)
        )
        self.runtime.store.insert_operator_message(
            OperatorMessage(
                role="assistant",
                body="wrapper response",
                target_id=None,
                model="agent_chat_api:claude:provider-default",
            )
        )

        response = self.app.dispatch("GET", "/api/control-plane")
        payload = json.loads(response.body)
        rows = payload["inquiryChat"]

        self.assertEqual(response.status, 200)
        self.assertEqual(rows[-1]["text"], "wrapper response")
        self.assertEqual(rows[-1]["model"], "agent_chat_api:claude:provider-default")

    def test_long_operator_chat_does_not_block_fast_runtime_endpoints(self) -> None:
        started = threading.Event()
        release = threading.Event()
        responses = []

        def slow_chat(message, target=None):
            started.set()
            release.wait(timeout=2)
            return {"ok": True, "model": "fixture", "answer": {"body": f"done: {message}"}, "target": target}

        with patch.object(self.runtime, "ask_operator_ai", side_effect=slow_chat):
            thread = threading.Thread(
                target=lambda: responses.append(
                    self.app.dispatch(
                        "POST",
                        "/api/chat",
                        json.dumps({"message": "hold this request", "target": "pirate.htb"}).encode("utf-8"),
                    )
                )
            )
            thread.start()
            self.assertTrue(started.wait(timeout=1))

            started_at = time.monotonic()
            for path in ("/api/work-status", "/api/execution-mode", "/api/runtime-settings"):
                response = self.app.dispatch("GET", path)
                self.assertEqual(response.status, 200)
            elapsed = time.monotonic() - started_at

            release.set()
            thread.join(timeout=2)

        self.assertLess(elapsed, 0.5)
        self.assertEqual(responses[0].status, 200)

    def test_full_control_plane_render_does_not_block_lightweight_endpoints(self) -> None:
        started = threading.Event()
        release = threading.Event()
        responses = []

        def slow_control_plane(**kwargs):
            started.set()
            release.wait(timeout=2)
            return {"mode": "real", "runtime": {}}

        with patch.object(self.app, "_control_plane_payload", side_effect=slow_control_plane):
            thread = threading.Thread(
                target=lambda: responses.append(self.app.dispatch("GET", "/api/control-plane"))
            )
            thread.start()
            self.assertTrue(started.wait(timeout=1))

            started_at = time.monotonic()
            for path in (
                "/api/work-status",
                "/api/execution-mode",
                "/api/runtime-settings",
                "/api/operator-intent",
                "/api/credentials",
                "/api/integrations/caido?check_health=1",
            ):
                response = self.app.dispatch("GET", path)
                self.assertEqual(response.status, 200)
            elapsed = time.monotonic() - started_at

            release.set()
            thread.join(timeout=2)

        self.assertLess(elapsed, 0.5)
        self.assertEqual(responses[0].status, 200)

    def test_continuous_tick_does_not_block_population_endpoints(self) -> None:
        started = threading.Event()
        release = threading.Event()

        class _Report:
            summary = "slow tick"
            completed_runs = []

        def slow_tick(max_executions: int = 1):
            started.set()
            release.wait(timeout=2)
            return _Report()

        self.runtime.update_execution_mode("continuous", interval_seconds=7)
        with patch.object(self.runtime, "run_tick", side_effect=slow_tick):
            thread = threading.Thread(target=self.app.continuous_tick_once)
            thread.start()
            self.assertTrue(started.wait(timeout=1))

            started_at = time.monotonic()
            for path in ("/api/control-plane", "/api/scope", "/api/models", "/api/storage-status"):
                response = self.app.dispatch("GET", path)
                self.assertEqual(response.status, 200)
            elapsed = time.monotonic() - started_at

            skipped = self.app.continuous_tick_once()
            release.set()
            thread.join(timeout=2)

        self.assertLess(elapsed, 0.5)
        self.assertFalse(skipped["ran"])
        self.assertTrue(skipped["busy"])

    def test_aborted_browser_response_writes_are_ignored(self) -> None:
        handler = object.__new__(_WebConsoleRequestHandler)
        response = WebResponse(
            status=200,
            body=b"{}",
            content_type="application/json; charset=utf-8",
            headers={"Cache-Control": "no-store"},
        )
        calls = []

        def broken_send_response(status):
            calls.append(status)
            raise BrokenPipeError("browser went away")

        handler.send_response = broken_send_response
        handler.send_header = lambda *args: None
        handler.end_headers = lambda: None
        handler.wfile = io.BytesIO()

        handler._write_response(response)
        self.assertEqual(calls, [200])

    def test_operator_status_chat_uses_deterministic_state_guard(self) -> None:
        with patch.object(
            self.runtime.ollama,
            "generate",
            return_value=OllamaResponse(
                model="deepseek-r1:8b",
                text="- No flag evidence exists yet.\n- Run bounded TCP service discovery next.",
            ),
        ) as generate:
            response = self.app.dispatch(
                "POST",
                "/api/chat",
                json.dumps({"message": "current status and flags", "target": "pirate.htb"}).encode("utf-8"),
            )

        payload = json.loads(response.body)
        answer = payload["result"]["chat"]["answer"]["body"]

        self.assertEqual(response.status, 200)
        self.assertEqual(payload["result"]["chat"]["model"], "deepseek-r1:8b")
        self.assertEqual(payload["result"]["chat"]["route_model"], "deepseek-r1:8b")
        self.assertIn("**Facts**", answer)
        self.assertIn("**AI Review**", answer)
        self.assertIn("No stored evidence contains", answer)
        generate.assert_called_once()

    def test_operator_ip_question_and_correction_update_target_state(self) -> None:
        target = self.runtime.store.get_target_by_handle("pirate.htb")
        self.assertIsNotNone(target)
        assert target is not None
        self.runtime.register_target(
            handle="pirate.htb",
            profile=ScopeProfile.HACK_THE_BOX,
            assets=[{"asset": "10.129.47.117", "asset_type": "ip"}],
            emit_event=False,
        )
        self.runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=target.id,
                type=EvidenceType.TOOL_OUTPUT,
                title="TCP service discovery",
                summary="Observed services on 10.129.47.117.",
                source_ref="fixture://old-service",
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.8,
                freshness=0.9,
                metadata={
                    "kind": "tcp_service_discovery",
                    "open_services": [{"host": "10.129.47.117", "port": 445, "service": "smb"}],
                },
            )
        )

        with patch.object(self.runtime.ollama, "generate") as generate:
            question_response = self.app.dispatch(
                "POST",
                "/api/chat",
                json.dumps({"message": "What IP are you using for the target?", "target": "pirate.htb"}).encode("utf-8"),
            )
            update_response = self.app.dispatch(
                "POST",
                "/api/chat",
                json.dumps({"message": "You should be using 10.129.244.95", "target": "pirate.htb"}).encode("utf-8"),
            )
            followup_response = self.app.dispatch(
                "POST",
                "/api/chat",
                json.dumps({"message": "What IP are you using for the target?", "target": "pirate.htb"}).encode("utf-8"),
            )

        question_answer = json.loads(question_response.body)["result"]["chat"]["answer"]["body"]
        update_answer = json.loads(update_response.body)["result"]["chat"]["answer"]["body"]
        followup_answer = json.loads(followup_response.body)["result"]["chat"]["answer"]["body"]
        refreshed = self.runtime.store.get_target_by_handle("pirate.htb")
        self.assertIsNotNone(refreshed)
        assert refreshed is not None
        ip_assets = [asset.asset for asset in self.runtime.store.list_scope_assets(refreshed.id) if asset.asset_type == "ip"]

        self.assertIn("10.129.47.117", question_answer)
        self.assertIn("Target IP Updated", update_answer)
        self.assertEqual(refreshed.metadata["active_ip"], "10.129.244.95")
        self.assertIn("10.129.244.95", ip_assets)
        self.assertIn("10.129.244.95", followup_answer)
        self.assertIn("historical", followup_answer.lower())
        generate.assert_not_called()

    def test_operator_summary_uses_deterministic_renderer(self) -> None:
        target = self.runtime.register_target(
            handle="example.test",
            profile=ScopeProfile.HACKERONE,
            assets=["example.test"],
            emit_event=False,
        )
        self.runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=target.id,
                type=EvidenceType.TOOL_OUTPUT,
                title="Recon: http://example.test/",
                summary="HTTP probe returned 200 for http://example.test/.",
                source_ref="fixture://example-summary",
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.85,
                freshness=0.9,
                metadata={"kind": "recon_scan", "effective_url": "http://example.test/", "status_code": 200},
            )
        )
        with patch.object(self.runtime.ollama, "generate") as generate:
            response = self.app.dispatch(
                "POST",
                "/api/chat",
                json.dumps({"message": "summarize example.test"}).encode("utf-8"),
            )

        payload = json.loads(response.body)

        self.assertEqual(response.status, 200)
        self.assertEqual(payload["result"]["chat"]["model"], "deterministic-state")
        self.assertIn("**Facts**", payload["result"]["chat"]["answer"]["body"])
        generate.assert_not_called()

    def test_operator_inquiry_infers_target_and_answers_ports_auth_and_escalation_from_state(self) -> None:
        target = self.runtime.register_target(
            handle="example.test",
            profile=ScopeProfile.HACKERONE,
            assets=["example.test", "203.0.113.37"],
            emit_event=False,
        )
        self.runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=target.id,
                type=EvidenceType.TOOL_OUTPUT,
                title="TCP service discovery: example.test",
                summary="TCP service discovery observed SSH and HTTP.",
                source_ref="fixture://example-services",
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.9,
                freshness=0.9,
                metadata={
                    "kind": "tcp_service_discovery",
                    "open_services": [
                        {"host": "203.0.113.37", "port": 22, "service": "ssh"},
                        {"host": "203.0.113.37", "port": 80, "service": "http"},
                    ],
                },
            )
        )
        self.runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=target.id,
                type=EvidenceType.TOOL_OUTPUT,
                title="Recon: http://example.test/",
                summary="HTTP probe returned 200 for http://example.test/ with content-type text/html.",
                source_ref="fixture://example-http",
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.85,
                freshness=0.9,
                metadata={
                    "kind": "recon_scan",
                    "effective_url": "http://example.test/",
                    "status_code": 200,
                    "auth_surfaces": [],
                    "forms": [],
                    "paths": ["/"],
                },
            )
        )

        with patch.object(self.runtime.ollama, "generate") as generate:
            response = self.app.dispatch(
                "POST",
                "/api/chat",
                json.dumps(
                    {
                        "message": (
                            "Are there only 2 open ports on example.test? Is there any login portals "
                            "on the site? (port 80) can we escalate this to gpt?"
                        )
                    }
                ).encode("utf-8"),
            )

        payload = json.loads(response.body)
        answer = payload["result"]["chat"]["answer"]["body"]
        review_tasks = [
            task
            for task in self.runtime.store.list_tasks(target_id=target.id, limit=20)
            if task.kind == TaskKind.REVIEW_PREMIUM_ESCALATION
        ]

        self.assertEqual(response.status, 200)
        self.assertEqual(payload["result"]["chat"]["model"], "deterministic-state")
        self.assertIn("2 unique open TCP port", answer)
        self.assertIn("`22/ssh`", answer)
        self.assertIn("`80/http`", answer)
        self.assertIn("not proof that no other ports exist", answer)
        self.assertIn("No stored current evidence identifies a login portal on port 80", answer)
        self.assertIn("**Premium Review**", answer)
        self.assertEqual(len(review_tasks), 1)
        generate.assert_not_called()

    def test_operator_generic_model_greeting_is_replaced_by_state_answer(self) -> None:
        target = self.runtime.register_target(
            handle="example.test",
            profile=ScopeProfile.HACKERONE,
            assets=["example.test"],
            emit_event=False,
        )
        self.runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=target.id,
                type=EvidenceType.TOOL_OUTPUT,
                title="Recon: http://example.test/",
                summary="HTTP probe returned 200 for http://example.test/.",
                source_ref="fixture://example-greeting",
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.85,
                freshness=0.9,
                metadata={"kind": "recon_scan", "effective_url": "http://example.test/", "status_code": 200},
            )
        )
        with patch.object(
            self.runtime.ollama,
            "generate",
            return_value=OllamaResponse(model="deepseek-r1:8b", text="Hello! I'm here to help. How can I assist you today?"),
        ) as generate:
            response = self.app.dispatch(
                "POST",
                "/api/chat",
                json.dumps({"message": "Draft a concise operator note for example.test."}).encode("utf-8"),
            )

        payload = json.loads(response.body)
        chat = payload["result"]["chat"]

        self.assertEqual(response.status, 200)
        self.assertEqual(chat["model"], "deterministic-state")
        self.assertIn("**Facts**", chat["answer"]["body"])
        self.assertTrue(chat["answer"]["metadata"]["guardrail_replaced_model_output"])
        generate.assert_called_once()

    def test_operator_status_uses_state_derived_potential_paths_and_actions(self) -> None:
        target = self.runtime.store.get_target_by_handle("pirate.htb")
        self.assertIsNotNone(target)
        assert target is not None
        self.runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=target.id,
                type=EvidenceType.TOOL_OUTPUT,
                title="Web content discovery: pirate.htb",
                summary="Bounded web content discovery checked 2 base URL(s) and found no interesting paths.",
                source_ref="fixture://content",
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.7,
                freshness=0.9,
                metadata={"kind": "web_content_discovery"},
            )
        )
        self.runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=target.id,
                type=EvidenceType.TOOL_OUTPUT,
                title="Windows service discovery: pirate.htb",
                summary="Observed Microsoft Windows SMB service evidence.",
                source_ref="fixture://windows-service",
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.78,
                freshness=0.9,
                metadata={
                    "kind": "tcp_service_discovery",
                    "open_services": [{"port": 445, "service": "microsoft-ds", "product": "Microsoft Windows Server"}],
                },
            )
        )
        exploit_evidence = EvidenceRecord(
            target_id=target.id,
            type=EvidenceType.MODEL_REVIEW,
            title="Exploit research: pirate.htb",
            summary="Searchsploit research found 1 non-DoS candidate: Microsoft Active Directory LDAP Server - Username Enumeration.",
            source_ref="fixture://exploit-research",
            verification_status=VerificationStatus.PARTIAL,
            confidence=0.68,
            freshness=0.9,
            metadata={"kind": "exploit_research", "match_count": 1, "executes_pocs": False},
        )
        self.runtime.store.insert_evidence(exploit_evidence)
        self.runtime.store.insert_interest(
            Interest(
                target_id=target.id,
                title="PoC research candidates for gated synthesis",
                summary="Searchsploit returned non-DoS public exploit references.",
                evidence_refs=[exploit_evidence.id],
                status=InterestStatus.OPEN,
                confidence=0.7,
                metadata={"class": "exploit_research", "match_count": 1},
            )
        )

        response = self.app.dispatch(
            "POST",
            "/api/chat",
            json.dumps({"message": "status and next step", "target": "pirate.htb"}).encode("utf-8"),
        )
        answer = json.loads(response.body)["result"]["chat"]["answer"]["body"]

        self.assertIn("**Potential Paths**", answer)
        self.assertIn("retained 1 non-DoS public exploit reference", answer)
        self.assertIn("Run gated public PoC applicability validation", answer)
        self.assertIn("Known username/password are not configured", answer)
        self.assertNotIn("Gated exploit-synthesis/adaptation primitive is missing", answer)
        self.assertNotIn("Add a bounded web content discovery primitive", answer)
        self.assertNotIn("No verified findings are stored for this target.", answer)

    def test_work_status_explains_idle_blockers(self) -> None:
        target = self.runtime.store.get_target_by_handle("pirate.htb")
        self.assertIsNotNone(target)
        assert target is not None
        self.runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=target.id,
                type=EvidenceType.MODEL_REVIEW,
                title="Exploit research: pirate.htb",
                summary="Searchsploit research found 1 non-DoS candidate.",
                source_ref="fixture://exploit-research",
                verification_status=VerificationStatus.PARTIAL,
                confidence=0.68,
                freshness=0.9,
                metadata={"kind": "exploit_research", "match_count": 1, "executes_pocs": False},
            )
        )

        payload = self.runtime.work_status_payload()

        self.assertIn("blockers", payload)
        self.assertTrue(payload["blockers"])
        self.assertIn("PoC candidates", payload["summary"])

    def test_operator_status_gates_lpe_until_shell_or_credentials_exist(self) -> None:
        target = self.runtime.store.get_target_by_handle("pirate.htb")
        self.assertIsNotNone(target)
        assert target is not None
        self.runtime.store.insert_interest(
            Interest(
                target_id=target.id,
                title="Unquoted service path candidate",
                summary="Searchsploit identified an unquoted service path style local privilege escalation lead.",
                confidence=0.65,
                metadata={"class": "exploit_research"},
            )
        )

        blocked_response = self.app.dispatch(
            "POST",
            "/api/chat",
            json.dumps({"message": "status and next step", "target": "pirate.htb"}).encode("utf-8"),
        )
        blocked_answer = json.loads(blocked_response.body)["result"]["chat"]["answer"]["body"]
        self.assertIn("Defer local privilege-escalation candidate", blocked_answer)
        self.assertIn("requires user shell", blocked_answer)

        self.runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=target.id,
                type=EvidenceType.TOOL_OUTPUT,
                title="Credentialed WinRM session",
                summary="A credentialed shell is available for follow-up verification.",
                source_ref="fixture://shell",
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.8,
                freshness=0.9,
                metadata={"kind": "credentialed_access"},
            )
        )
        ready_response = self.app.dispatch(
            "POST",
            "/api/chat",
            json.dumps({"message": "status and next step", "target": "pirate.htb"}).encode("utf-8"),
        )
        ready_answer = json.loads(ready_response.body)["result"]["chat"]["answer"]["body"]
        self.assertIn("Verify local privilege-escalation candidate", ready_answer)

    def test_model_warm_action_reports_route_results(self) -> None:
        with patch.object(
            self.runtime.ollama,
            "preload",
            side_effect=lambda *, model, keep_alive, num_gpu=None: OllamaPreloadResult(
                model=model,
                ok=True,
                elapsed_seconds=0.01,
            ),
        ) as preload:
            response = self.app.dispatch(
                "POST",
                "/api/actions/warm-models",
                json.dumps({"keep_alive": "2h"}).encode("utf-8"),
            )

        payload = json.loads(response.body)

        self.assertEqual(response.status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["result"]["keep_alive"], "2h")
        self.assertEqual(len(payload["result"]["results"]), 4)
        cold_routes = {item["route"]: item for item in payload["result"]["results"]}
        self.assertEqual(cold_routes["local_compact"]["num_gpu"], 0)
        self.assertEqual(cold_routes["local_code_cold"]["processor_hint"], "cpu")
        self.assertEqual(preload.call_count, 4)

    def test_model_clear_and_stop_work_actions_are_available(self) -> None:
        self.runtime.start_session(title="Active GUI session")
        with patch.object(
            self.runtime.ollama,
            "unload",
            side_effect=lambda *, model, num_gpu=None: OllamaPreloadResult(
                model=model,
                ok=True,
                elapsed_seconds=0.01,
            ),
        ) as unload:
            clear_response = self.app.dispatch("POST", "/api/actions/clear-models")
        stop_response = self.app.dispatch("POST", "/api/actions/stop-work")

        clear_payload = json.loads(clear_response.body)
        stop_payload = json.loads(stop_response.body)

        self.assertEqual(clear_response.status, 200)
        self.assertTrue(clear_payload["ok"])
        self.assertEqual(clear_payload["action"], "clear-models")
        self.assertEqual(len(clear_payload["result"]["results"]), 4)
        self.assertEqual(unload.call_count, 4)
        self.assertEqual(stop_response.status, 200)
        self.assertTrue(stop_payload["ok"])
        self.assertEqual(stop_payload["action"], "stop-work")
        self.assertEqual(stop_payload["result"]["paused_sessions"], 1)

    def test_execution_mode_endpoint_persists_and_surfaces_on_dashboard(self) -> None:
        update_response = self.app.dispatch(
            "POST",
            "/api/execution-mode",
            json.dumps({"mode": "continuous", "interval_seconds": 7}).encode("utf-8"),
        )
        mode_response = self.app.dispatch("GET", "/api/execution-mode")
        dashboard_response = self.app.dispatch("GET", "/api/dashboard")

        update = json.loads(update_response.body)
        mode = json.loads(mode_response.body)
        dashboard = json.loads(dashboard_response.body)

        self.assertEqual(update_response.status, 200)
        self.assertTrue(update["ok"])
        self.assertEqual(update["result"]["execution_mode"]["mode"], "continuous")
        self.assertEqual(mode["mode"], "continuous")
        self.assertEqual(mode["interval_seconds"], 7)
        self.assertEqual(dashboard["execution_mode"]["mode"], "continuous")

    def test_runtime_control_endpoint_persists_mode_and_intent_without_full_payload(self) -> None:
        response = self.app.dispatch(
            "POST",
            "/api/runtime-control",
            json.dumps(
                {
                    "mode": "continuous",
                    "interval_seconds": 9,
                    "intent_id": "recon_only",
                }
            ).encode("utf-8"),
        )
        payload = json.loads(response.body)
        mode_response = json.loads(self.app.dispatch("GET", "/api/execution-mode").body)
        intent_response = json.loads(self.app.dispatch("GET", "/api/operator-intent").body)

        self.assertEqual(response.status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["action"], "runtime-control")
        self.assertEqual(payload["execution_mode"]["mode"], "continuous")
        self.assertEqual(payload["execution_mode"]["interval_seconds"], 9)
        self.assertEqual(payload["operator_intent"]["active"]["id"], "recon_only")
        self.assertIn("work_status", payload)
        self.assertNotIn("control_plane", payload)
        self.assertNotIn("runtime", payload)
        self.assertNotIn("result", payload)
        self.assertEqual(mode_response["mode"], "continuous")
        self.assertEqual(intent_response["active"]["id"], "recon_only")
        self.assertIsNotNone(self.runtime.store.get_active_session())

    def test_runtime_settings_endpoint_persists_and_surfaces_on_dashboard(self) -> None:
        update_response = self.app.dispatch(
            "POST",
            "/api/runtime-settings",
            json.dumps(
                {
                    "gpu_ai_timeout_seconds": 150,
                    "cpu_ai_timeout_seconds": 420,
                    "stale_run_timeout_seconds": 5400,
                    "min_free_cpu_ram_mb": 3072,
                    "min_free_gpu_ram_mb": 512,
                }
            ).encode("utf-8"),
        )
        settings_response = self.app.dispatch("GET", "/api/runtime-settings")
        dashboard_response = self.app.dispatch("GET", "/api/dashboard")

        update = json.loads(update_response.body)
        settings = json.loads(settings_response.body)
        dashboard = json.loads(dashboard_response.body)

        self.assertEqual(update_response.status, 200)
        self.assertTrue(update["ok"])
        self.assertEqual(update["result"]["runtime_tuning"]["cpu_ai_timeout_seconds"], 420)
        self.assertEqual(update["result"]["runtime_tuning"]["min_free_cpu_ram_mb"], 3072)
        self.assertEqual(settings["gpu_ai_timeout_seconds"], 150)
        self.assertEqual(settings["stale_run_timeout_seconds"], 5400)
        self.assertEqual(settings["min_free_gpu_ram_mb"], 512)
        self.assertEqual(dashboard["runtime_tuning"]["cpu_ai_timeout_seconds"], 420)

    def test_model_role_endpoint_lists_and_persists_selected_models(self) -> None:
        with patch.object(
            self.runtime.ollama,
            "list_models",
            return_value=OllamaModelListResult(
                ok=True,
                models=["gemma4:e4b", "deepseek-r1:8b", "qwen3-coder-next:q4_K_M", "phi4-reasoning"],
            ),
        ):
            status_response = self.app.dispatch("GET", "/api/models")
            update_response = self.app.dispatch(
                "POST",
                "/api/models",
                json.dumps(
                    {
                        "roles": {"local_fast": "deepseek-r1:8b"},
                        "processors": {"local_fast": "cpu", "local_code": "gpu"},
                    }
                ).encode("utf-8"),
            )

        status = json.loads(status_response.body)
        update = json.loads(update_response.body)

        self.assertEqual(status_response.status, 200)
        self.assertEqual(update_response.status, 200)
        self.assertEqual(status["roles"][0]["label"], "Orchestrator")
        self.assertEqual(update["result"]["models"]["roles"][0]["selected_model"], "deepseek-r1:8b")
        self.assertEqual(update["result"]["models"]["roles"][0]["processor"], "cpu")
        self.assertEqual(update["result"]["models"]["roles"][0]["num_gpu"], 0)
        self.assertEqual(update["result"]["models"]["roles"][2]["processor"], "gpu")
        self.assertIsNone(update["result"]["models"]["roles"][2]["num_gpu"])
        self.assertEqual(self.runtime.config.topology.local_fast, "deepseek-r1:8b")


if __name__ == "__main__":
    unittest.main()
