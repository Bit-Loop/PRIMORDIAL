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
    EvidenceType,
    InterestStatus,
    MethodologyPhase,
    NotificationChannel,
    NotificationStatus,
    RiskTier,
    ProviderRoute,
    ScopeProfile,
    TaskKind,
    TaskStatus,
    VerificationStatus,
)
from primordial.core.domain.models import AgentTrace, EvidenceRecord, Interest, NotificationRecord, Task
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
                "http://127.0.0.1:8650/graphql",
                "AUTH FAILED",
                "auth-blocked",
                "USE TARGET SCOPE",
                "SAVE CREDENTIALS",
                "Stored credentials",
                "aria-label={`Edit ${activeCredentialGroup.n} ${label}`}",
            ]:
                self.assertIn(token, text)
            self.assertNotIn("pirate.htb scope", text)
            self.assertNotIn("http://127.0.0.1:8080/graphql", text)
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
