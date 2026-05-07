from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from primordial.config import AppConfig
from primordial.core.domain.enums import EvidenceType, InterestStatus, ScopeProfile, VerificationStatus
from primordial.core.domain.models import EvidenceRecord, Interest
from primordial.core.providers.ollama import OllamaModelListResult, OllamaPreloadResult, OllamaResponse
from primordial.core.web.app import PrimordialWebApp
from primordial.runtime import PrimordialRuntime
from tests.support import build_probe_fixture, write_scope_file


MANIFESTS_DIR = Path(__file__).resolve().parents[1] / "manifests"


class WebConsoleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        config = AppConfig.from_env(project_root=root)
        config.manifests_dir = MANIFESTS_DIR
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
        self.assertIn("dashboard", tick_payload)

        task_id = tick_payload["dashboard"]["tasks"][0]["id"]
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
        self.assertTrue(
            any(item["target"]["handle"] == "pirate.htb" for item in payload["scope"]["targets"])
        )

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
        handles = {item["target"]["handle"] for item in payload["scope"]["targets"]}
        self.assertIn("alpha.htb", handles)
        self.assertIn("beta.htb", handles)

    def test_target_removal_endpoint_updates_scope(self) -> None:
        response = self.app.dispatch("DELETE", "/api/targets/pirate.htb?profile=hack_the_box")
        payload = json.loads(response.body)

        self.assertEqual(response.status, 200)
        self.assertTrue(payload["result"]["removed"])
        self.assertEqual(payload["scope"]["targets"], [])

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
            json.dumps({"webhook_url": "https://discord.com/api/webhooks/token"}).encode("utf-8"),
        )
        caido_response = self.app.dispatch(
            "POST",
            "/api/credentials/caido",
            json.dumps(
                {
                    "graphql_url": "http://127.0.0.1:8080/graphql",
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
        self.assertNotIn("discord.com/api/webhooks/token", serialized)
        self.assertNotIn("caido-secret-token", serialized)
        self.assertTrue(credentials["services"]["notion"]["api_key"]["configured"])
        self.assertTrue(credentials["services"]["discord"]["webhook_url"]["configured"])
        self.assertTrue(credentials["services"]["caido"]["api_token"]["configured"])

        records = json.loads(records_response.body)
        self.assertIn("evidence", records)
        self.assertIn("primitives", records)

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

    def test_operator_summary_uses_local_model_not_deterministic_renderer(self) -> None:
        with patch.object(
            self.runtime.ollama,
            "generate",
            return_value=OllamaResponse(model="deepseek-r1:8b", text="Target context summarized from the bounded snapshot."),
        ) as generate:
            response = self.app.dispatch(
                "POST",
                "/api/chat",
                json.dumps({"message": "summarize target context", "target": "pirate.htb"}).encode("utf-8"),
            )

        payload = json.loads(response.body)

        self.assertEqual(response.status, 200)
        self.assertEqual(payload["result"]["chat"]["model"], "deepseek-r1:8b")
        self.assertIn("Target context summarized", payload["result"]["chat"]["answer"]["body"])
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
        self.assertIn("Lab username/password are not configured", answer)
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
