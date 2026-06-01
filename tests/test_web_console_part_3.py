from __future__ import annotations

from tests.test_web_console_common import *


class WebConsoleTestsPart3(WebConsoleTestsBase):
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
        self.assertEqual(payload["plan"]["intent"]["id"], "recon_only")
        self.assertFalse(payload["plan"]["intent"]["flags"]["credential_guessing"])
        self.assertFalse(payload["plan"]["intent"]["flags"]["credential_spraying"])
        self.assertFalse(payload["plan"]["intent"]["flags"]["hash_cracking"])
        self.assertFalse(payload["plan"]["intent"]["flags"]["reverse_shell"])

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

__all__ = ["WebConsoleTestsPart3"]
