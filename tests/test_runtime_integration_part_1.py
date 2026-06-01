from __future__ import annotations

from tests.test_runtime_integration_common import *


class RuntimeIntegrationTestsPart1(RuntimeIntegrationTestsBase):
    def test_wrapper_only_mode_skips_ollama_model_listing_and_reports_prompts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.manifests_dir = MANIFESTS_DIR
            config.use_only_wrapper_mode = True
            config.ensure_directories()

            with patch("primordial.core.providers.ollama.OllamaClient.list_models") as list_models:
                runtime = PrimordialRuntime(config)
                runtime.initialize()
                runtime.store.set_setting(runtime.MODEL_WRAPPER_MODE_SETTING, {"use_only_wrapper": False})
                payload = runtime.models_payload()
            try:
                list_models.assert_not_called()
                self.assertTrue(payload["wrapper_mode"]["use_only_wrapper"])
                self.assertTrue(payload["ollama"]["disabled_by_wrapper_mode"])
                self.assertIn("local_deep", payload["wrapper_mode"]["personality_prompts"])
            finally:
                runtime.shutdown()

    def test_wrapper_only_worker_ai_uses_role_personality_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.manifests_dir = MANIFESTS_DIR
            config.use_only_wrapper_mode = True
            config.ensure_directories()
            runtime = PrimordialRuntime(config)
            runtime.initialize()

            class FakeAgentChat:
                def __init__(self) -> None:
                    self.calls: list[dict[str, object]] = []

                def chat(self, **kwargs: object) -> AgentChatResponse:
                    self.calls.append(kwargs)
                    return AgentChatResponse(
                        provider="claude",
                        model="claude-sonnet-4",
                        text='{"summary":"ok"}',
                        exit_code=0,
                        elapsed_seconds=0.1,
                        request_id="req-wrapper",
                    )

            fake = FakeAgentChat()
            runtime.agent_chat = fake  # type: ignore[assignment]
            task = Task(
                target_id=None,
                phase=MethodologyPhase.RECON,
                kind=TaskKind.RECON_SCAN,
                title="Probe",
                summary="Probe safely.",
                role=AgentRole.RECON_WORKER,
                provider_route=None,
            )

            with patch.object(runtime.ollama, "is_reachable") as is_reachable:
                response = runtime._worker_ai_generate(task, "Base system", "Prompt body")

            try:
                is_reachable.assert_not_called()
                self.assertIsNotNone(response)
                assert response is not None
                self.assertEqual(response["adapter"], "agent_chat_api")
                self.assertEqual(response["processor"], "wrapper")
                system_prompt = str(fake.calls[0]["system_prompt"])
                self.assertIn("use-only-wrapper mode", system_prompt)
                self.assertIn("Role personality (local_fast)", system_prompt)
                self.assertIn("terse runtime dispatcher", system_prompt)
                self.assertIn("Caller contract: Base system", system_prompt)
            finally:
                runtime.shutdown()

    def test_wrapper_mode_persists_gpt_preset_and_passes_effort(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.manifests_dir = MANIFESTS_DIR
            config.use_only_wrapper_mode = True
            config.ensure_directories()
            runtime = PrimordialRuntime(config)
            runtime.initialize()

            class FakeAgentChat:
                def __init__(self) -> None:
                    self.calls: list[dict[str, object]] = []

                def chat(self, **kwargs: object) -> AgentChatResponse:
                    self.calls.append(kwargs)
                    return AgentChatResponse(
                        provider="codex",
                        model="gpt-5.5",
                        text="wrapper-ok",
                        exit_code=0,
                        elapsed_seconds=0.1,
                        request_id="req-gpt",
                    )

            fake = FakeAgentChat()
            runtime.agent_chat = fake  # type: ignore[assignment]
            try:
                with patch.object(runtime, "_ensure_agent_chat_api_available", return_value={"ok": True}):
                    payload = runtime.update_model_roles(
                        {},
                        wrapper_mode={"use_only_wrapper": True, "preset": "codex_gpt55_high"},
                    )
                    response = runtime._wrapper_ai_generate(role="operator_chat", system="s", prompt="p")

                wrapper = payload["wrapper_mode"]
                self.assertEqual(wrapper["preset"], "codex_gpt55_high")
                self.assertEqual(wrapper["provider"], "codex")
                self.assertEqual(wrapper["model"], "gpt-5.5")
                self.assertEqual(wrapper["effort"], "high")
                self.assertEqual(wrapper["display_label"], "GPT 5.5 High")
                self.assertEqual(fake.calls[0]["provider"], "codex")
                self.assertEqual(fake.calls[0]["model"], "gpt-5.5")
                self.assertEqual(fake.calls[0]["effort"], "high")
                self.assertEqual(response["model"], "agent_chat_api:codex:gpt-5.5:high")
            finally:
                runtime.shutdown()

    def test_wrapper_only_generation_autostarts_local_agent_chat_api_when_unreachable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.manifests_dir = MANIFESTS_DIR
            config.use_only_wrapper_mode = True
            config.ensure_directories()
            runtime = PrimordialRuntime(config)
            runtime.initialize()

            with (
                patch.object(runtime.agent_chat, "health", side_effect=[RuntimeError("down"), {"ok": True}]) as health,
                patch.object(runtime, "_start_local_agent_chat_api", return_value={"started": True, "pid": 1234}) as start,
                patch.object(
                    runtime.agent_chat,
                    "chat",
                    return_value=AgentChatResponse(
                        provider="claude",
                        model="claude-sonnet-4",
                        text="wrapper-ok",
                        exit_code=0,
                        elapsed_seconds=0.2,
                    ),
                ) as chat,
            ):
                response = runtime._wrapper_ai_generate(role="operator_chat", system="s", prompt="p")

            try:
                self.assertEqual(health.call_count, 2)
                start.assert_called_once()
                chat.assert_called_once()
                self.assertEqual(response["text"], "wrapper-ok")
                self.assertEqual(response["adapter"], "agent_chat_api")
            finally:
                runtime.shutdown()

    def test_topology_model_validation_accepts_implicit_latest_tag(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.manifests_dir = MANIFESTS_DIR
            config.ensure_directories()

            with patch(
                "primordial.core.providers.ollama.OllamaClient.list_models",
                return_value=OllamaModelListResult(
                    ok=True,
                    models=["gemma4:e4b", "deepseek-r1:8b", "qwen3-coder-next:q4_K_M", "phi4-reasoning:latest"],
                ),
            ):
                runtime = PrimordialRuntime(config)
                runtime.initialize()
            try:
                events = runtime.store.list_events(limit=20)
                self.assertFalse(any(event.summary.startswith("Topology models missing") for event in events))
            finally:
                runtime.shutdown()

    def test_execution_mode_defaults_to_longer_cpu_friendly_interval(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.manifests_dir = MANIFESTS_DIR
            config.ensure_directories()
            runtime = PrimordialRuntime(config)
            runtime.initialize()

            payload = runtime.execution_mode_payload()

            self.assertEqual(payload["mode"], "tick")
            self.assertEqual(
                payload["interval_seconds"],
                PrimordialRuntime.DEFAULT_EXECUTION_INTERVAL_SECONDS,
            )
            runtime.shutdown()

    def test_runtime_tuning_defaults_persist_and_apply_to_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.manifests_dir = MANIFESTS_DIR
            config.ensure_directories()
            runtime = PrimordialRuntime(config)
            runtime.initialize()

            defaults = runtime.runtime_tuning_payload()
            self.assertEqual(
                defaults["cpu_ai_timeout_seconds"],
                PrimordialRuntime.DEFAULT_WORKER_AI_TIMEOUT_SECONDS_CPU,
            )
            self.assertEqual(
                defaults["gpu_ai_timeout_seconds"],
                PrimordialRuntime.DEFAULT_WORKER_AI_TIMEOUT_SECONDS_GPU,
            )
            self.assertEqual(
                defaults["stale_run_timeout_seconds"],
                PrimordialRuntime.DEFAULT_STALE_RUN_TIMEOUT_SECONDS,
            )
            self.assertEqual(
                defaults["min_free_cpu_ram_mb"],
                PrimordialRuntime.DEFAULT_MIN_FREE_CPU_RAM_MB,
            )
            self.assertEqual(
                defaults["min_free_gpu_ram_mb"],
                PrimordialRuntime.DEFAULT_MIN_FREE_GPU_RAM_MB,
            )

            updated = runtime.update_runtime_tuning(
                cpu_ai_timeout_seconds=420,
                gpu_ai_timeout_seconds=150,
                stale_run_timeout_seconds=5400,
                min_free_cpu_ram_mb=3072,
                min_free_gpu_ram_mb=512,
            )
            self.assertEqual(updated["cpu_ai_timeout_seconds"], 420)
            self.assertEqual(updated["gpu_ai_timeout_seconds"], 150)
            self.assertEqual(updated["stale_run_timeout_seconds"], 5400)
            self.assertEqual(updated["min_free_cpu_ram_mb"], 3072)
            self.assertEqual(updated["min_free_gpu_ram_mb"], 512)
            self.assertEqual(runtime.workflow.stale_run_max_age_seconds, 5400)
            runtime.shutdown()

            runtime_reloaded = PrimordialRuntime(config)
            runtime_reloaded.initialize()
            persisted = runtime_reloaded.runtime_tuning_payload()
            self.assertEqual(persisted["cpu_ai_timeout_seconds"], 420)
            self.assertEqual(persisted["gpu_ai_timeout_seconds"], 150)
            self.assertEqual(persisted["stale_run_timeout_seconds"], 5400)
            self.assertEqual(persisted["min_free_cpu_ram_mb"], 3072)
            self.assertEqual(persisted["min_free_gpu_ram_mb"], 512)
            self.assertEqual(runtime_reloaded.workflow.stale_run_max_age_seconds, 5400)
            runtime_reloaded.shutdown()

__all__ = ["RuntimeIntegrationTestsPart1"]
