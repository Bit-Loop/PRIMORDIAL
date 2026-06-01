from __future__ import annotations

from tests.test_web_console_common import *


class WebConsoleTestsPart11(WebConsoleTestsBase):
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

__all__ = ["WebConsoleTestsPart11"]
