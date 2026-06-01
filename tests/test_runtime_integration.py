from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from primordial.config import AppConfig
from primordial.core.domain.enums import (
    AgentRole,
    EvidenceType,
    MethodologyPhase,
    NotificationChannel,
    RiskTier,
    ScopeProfile,
    TaskKind,
    TaskRunStatus,
    TaskStatus,
    VerificationStatus,
)
from primordial.core.domain.models import EvidenceRecord, Task
from primordial.core.domain.models import TaskRun
from primordial.core.providers.agent_chat import AgentChatResponse
from primordial.core.providers.ollama import OllamaModelListResult
from primordial.runtime import PrimordialRuntime
from tests.support import build_probe_fixture, fixture_ip, fixture_secret, write_scope_file


MANIFESTS_DIR = Path(__file__).resolve().parents[1] / "manifests"
PIRATE_IP = fixture_ip(10, 129, 47, 117)


class RuntimeIntegrationTests(unittest.TestCase):
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

    def test_dashboard_payload_surfaces_runtime_tuning_and_system_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.manifests_dir = MANIFESTS_DIR
            config.ensure_directories()
            runtime = PrimordialRuntime(config)
            runtime.initialize()

            with patch.object(
                runtime,
                "_read_cpu_metrics",
                return_value={
                    "available": True,
                    "percent": 12.5,
                    "load_1": 1.23,
                    "cpu_count": 8,
                    "memory_available_mb": 12345.0,
                    "memory_total_mb": 32768.0,
                },
            ), patch.object(
                runtime,
                "_read_gpu_metrics",
                return_value={
                    "available": True,
                    "percent": 34.0,
                    "memory_used_mb": 2048.0,
                    "memory_free_mb": 6144.0,
                    "memory_total_mb": 8192.0,
                },
            ):
                payload = runtime.dashboard_payload()

            self.assertIn("runtime_tuning", payload)
            self.assertIn("system_metrics", payload)
            self.assertEqual(payload["system_metrics"]["cpu"]["percent"], 12.5)
            self.assertEqual(payload["system_metrics"]["gpu"]["percent"], 34.0)
            self.assertEqual(payload["system_metrics"]["cpu"]["memory_available_mb"], 12345.0)
            self.assertEqual(payload["system_metrics"]["gpu"]["memory_free_mb"], 6144.0)
            runtime.shutdown()

    def test_work_status_repairs_stale_active_run_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.manifests_dir = MANIFESTS_DIR
            config.ensure_directories()
            scope_path = write_scope_file(
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
            runtime = PrimordialRuntime(config)
            runtime.initialize()
            runtime.import_scope(scope_path, ScopeProfile.HACK_THE_BOX)
            runtime.set_operator_intent("htb_lab")
            target = runtime.store.list_targets()[0]
            task = Task(
                target_id=target.id,
                phase=MethodologyPhase.ANALYSIS,
                kind=TaskKind.ANALYZE_EVIDENCE,
                title="Analyze accumulated evidence",
                summary="Synthetic stale execution fixture",
                role=AgentRole.ANALYSIS_WORKER,
                risk_tier=RiskTier.LOW,
                status=TaskStatus.CANCELLED,
            )
            runtime.store.insert_task(task)
            run = TaskRun(
                task_id=task.id,
                attempt_number=1,
                role=task.role,
                provider_route=task.provider_route or runtime.router.select_route(task).route,
                model_name=task.provider_model or runtime.router.select_route(task).model_name,
                status=TaskRunStatus.RUNNING,
                trace_summary="task claimed for brokered execution",
            )
            runtime.store.insert_task_run(run)

            payload = runtime.work_status_payload()
            repaired_run = next(item for item in runtime.store.list_task_runs(limit=20) if item.id == run.id)

            self.assertFalse(any(item["task_id"] == task.id for item in payload["active"]))
            self.assertEqual(repaired_run.status, TaskRunStatus.CANCELLED)
            self.assertIsNotNone(repaired_run.finished_at)
            self.assertIn("recovered stale execution state", repaired_run.error or "")
            runtime.shutdown()

    def test_real_recon_creates_evidence_and_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.manifests_dir = MANIFESTS_DIR
            config.ensure_directories()
            scope_path = write_scope_file(
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
            runtime = PrimordialRuntime(config)
            runtime.initialize()
            runtime.import_scope(scope_path, ScopeProfile.HACK_THE_BOX)

            with patch(
                "primordial.modes.security.execution.PrimitiveExecutor._probe_url",
                autospec=True,
                side_effect=lambda _executor, **kwargs: build_probe_fixture(kwargs["url"]),
            ):
                report = runtime.run_tick(max_executions=1)

            self.assertEqual(len(report.completed_runs), 1)
            self.assertGreaterEqual(len(runtime.store.list_evidence(limit=100)), 1)
            findings = runtime.store.list_findings(limit=100)
            self.assertGreaterEqual(len(findings), 1)
            self.assertEqual(findings[0].metadata.get("source"), TaskKind.RECON_SCAN.value)
            artifacts = runtime.store.list_artifacts(limit=100)
            self.assertGreaterEqual(len(artifacts), 1)
            self.assertTrue(Path(artifacts[0].path).exists())
            runtime.shutdown()

    def test_approve_all_safe_rechecks_policy_before_unblocking_tasks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.manifests_dir = MANIFESTS_DIR
            config.ensure_directories()
            scope_path = write_scope_file(
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
            runtime = PrimordialRuntime(config)
            runtime.initialize()
            runtime.import_scope(scope_path, ScopeProfile.HACK_THE_BOX)
            target = runtime.store.list_targets()[0]
            task = Task(
                target_id=target.id,
                phase=MethodologyPhase.ANALYSIS,
                kind=TaskKind.ANALYZE_EVIDENCE,
                title="Analyze accumulated evidence",
                summary="Safe analysis task from an older approval state",
                role=AgentRole.ANALYSIS_WORKER,
                risk_tier=RiskTier.MODERATE,
                status=TaskStatus.NEEDS_APPROVAL,
                requires_approval=True,
            )
            runtime.store.insert_task(task)

            outcome = runtime.approve_all_safe_tasks()
            approved = runtime.store.get_task(task.id)

            self.assertEqual(outcome["approved_count"], 1)
            self.assertEqual(outcome["skipped_count"], 0)
            self.assertIsNotNone(approved)
            self.assertEqual(approved.status, TaskStatus.PENDING)
            self.assertFalse(approved.requires_approval)
            runtime.shutdown()

    def test_remove_target_cascades_records_and_runtime_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.manifests_dir = MANIFESTS_DIR
            config.ensure_directories()
            scope_path = write_scope_file(
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
            runtime = PrimordialRuntime(config)
            runtime.initialize()
            runtime.import_scope(scope_path, ScopeProfile.HACK_THE_BOX)
            with patch(
                "primordial.modes.security.execution.PrimitiveExecutor._probe_url",
                autospec=True,
                side_effect=lambda _executor, **kwargs: build_probe_fixture(kwargs["url"]),
            ):
                runtime.run_tick(max_executions=1)
            artifact_path = Path(runtime.store.list_artifacts(limit=10)[0].path)

            outcome = runtime.remove_target("pirate.htb", ScopeProfile.HACK_THE_BOX)

            self.assertTrue(outcome["removed"])
            self.assertEqual(runtime.store.list_targets(), [])
            self.assertEqual(runtime.store.list_tasks(limit=10), [])
            self.assertEqual(runtime.store.list_evidence(limit=10), [])
            self.assertFalse(artifact_path.exists())
            runtime.shutdown()

    def test_runtime_keeps_security_mode_lazy_until_needed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.manifests_dir = MANIFESTS_DIR
            config.ensure_directories()
            scope_path = write_scope_file(
                root,
                targets=[
                    {
                        "handle": "pirate.htb",
                        "display_name": "Pirate Fixture",
                        "in_scope": True,
                        "assets": [{"asset": "http://127.0.0.1:1/", "asset_type": "webapp"}],
                    }
                ],
            )
            runtime = PrimordialRuntime(config)
            runtime.initialize()
            runtime.import_scope(scope_path)

            self.assertTrue(config.crash_journal_path.exists())
            self.assertNotIn("security", runtime.modules.active_modules())
            self.assertNotIn("notion", runtime.modules.active_modules())

            runtime.workflow.tick(max_executions=1)

            self.assertIn("security", runtime.modules.active_modules())
            self.assertNotIn("notion", runtime.modules.active_modules())

            runtime.process_external_queues()

            self.assertIn("notion", runtime.modules.active_modules())
            self.assertIn("discord", runtime.modules.active_modules())

            runtime.shutdown()

            self.assertFalse(config.crash_journal_path.exists())

    def test_service_discovery_creates_evidence_without_shelling_out(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.manifests_dir = MANIFESTS_DIR
            config.ensure_directories()
            scope_path = write_scope_file(
                root,
                targets=[
                    {
                        "handle": "pirate.htb",
                        "display_name": "Pirate Fixture",
                        "in_scope": True,
                        "assets": [
                            {"asset": "pirate.htb", "asset_type": "hostname"},
                            {"asset": PIRATE_IP, "asset_type": "ip"},
                        ],
                    }
                ],
            )
            runtime = PrimordialRuntime(config)
            runtime.initialize()
            runtime.import_scope(scope_path, ScopeProfile.HACK_THE_BOX)

            fake_scan = {
                "open_services": [
                    {
                        "host": PIRATE_IP,
                        "port": 22,
                        "service": "ssh",
                        "banner": "SSH-2.0-OpenSSH",
                        "source_asset": PIRATE_IP,
                    }
                ],
                "closed_count": 37,
                "errors": [],
            }
            with patch(
                "primordial.modes.security.execution.PrimitiveExecutor._probe_url",
                autospec=True,
                side_effect=lambda _executor, **kwargs: build_probe_fixture(kwargs["url"]),
            ), patch(
                "primordial.modes.security.execution.PrimitiveExecutor._scan_tcp_services",
                autospec=True,
                return_value=fake_scan,
            ):
                runtime.run_tick(max_executions=2)

            service_evidence = [
                item
                for item in runtime.store.list_evidence(limit=100)
                if item.metadata.get("kind") == "tcp_service_discovery"
            ]
            self.assertEqual(len(service_evidence), 1)
            self.assertEqual(service_evidence[0].metadata["open_services"][0]["service"], "ssh")
            self.assertTrue(runtime.store.list_interests(target_id=runtime.store.list_targets()[0].id, limit=10))
            runtime.shutdown()

    def test_ad_enumeration_normalizes_host_tool_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.manifests_dir = MANIFESTS_DIR
            config.ensure_directories()
            scope_path = write_scope_file(
                root,
                targets=[
                    {
                        "handle": "pirate.htb",
                        "display_name": "Pirate Fixture",
                        "in_scope": True,
                        "assets": [
                            {"asset": "pirate.htb", "asset_type": "hostname"},
                            {"asset": PIRATE_IP, "asset_type": "ip"},
                        ],
                    }
                ],
            )
            runtime = PrimordialRuntime(config)
            runtime.initialize()
            runtime.import_scope(scope_path, ScopeProfile.HACK_THE_BOX)

            fake_scan = {
                "open_services": [
                    {"host": PIRATE_IP, "port": 389, "service": "ldap", "banner": "", "source_asset": PIRATE_IP},
                    {"host": PIRATE_IP, "port": 445, "service": "smb", "banner": "", "source_asset": PIRATE_IP},
                ],
                "closed_count": 36,
                "errors": [],
            }

            def fake_command(_executor, *, tool: str, argv: list[str], timeout_seconds: int) -> dict[str, object]:
                outputs = {
                    "ldapsearch": "dn:\nnamingContexts: DC=pirate,DC=htb\ndefaultNamingContext: DC=pirate,DC=htb\n",
                    "smbclient": "Disk|SYSVOL|Logon server share\nDisk|NETLOGON|Logon server share\nIPC|IPC$|IPC Service\n",
                    "rpcclient": "user:[guest] rid:[0x1f5]\ngroup:[Domain Users] rid:[0x201]\n",
                    "netexec": "",
                }
                return {
                    "tool": tool,
                    "argv": argv,
                    "executed": True,
                    "returncode": 0,
                    "stdout": outputs.get(tool, ""),
                    "stderr": "",
                    "timeout": False,
                }

            with patch(
                "primordial.modes.security.execution.PrimitiveExecutor._probe_url",
                autospec=True,
                side_effect=lambda _executor, **kwargs: build_probe_fixture(kwargs["url"]),
            ), patch(
                "primordial.modes.security.execution.PrimitiveExecutor._scan_tcp_services",
                autospec=True,
                return_value=fake_scan,
            ):
                runtime.run_tick(max_executions=2)

            with patch(
                "primordial.modes.security.execution.PrimitiveExecutor._run_host_command",
                autospec=True,
                side_effect=fake_command,
            ), patch(
                "primordial.modes.security.execution.PrimitiveExecutor._run_dns_enumeration_commands",
                autospec=True,
                return_value=[],
            ), patch(
                "primordial.modes.security.execution.PrimitiveExecutor._run_web_content_discovery",
                autospec=True,
                return_value=[],
            ), patch(
                "primordial.modes.security.execution.PrimitiveExecutor._content_discovery_words",
                autospec=True,
                return_value=["admin"],
            ):
                runtime.run_tick(max_executions=3)

            ad_evidence = [
                item
                for item in runtime.store.list_evidence(limit=100)
                if item.metadata.get("kind") == "ad_enumeration"
            ]
            self.assertEqual(len(ad_evidence), 1)
            self.assertEqual(ad_evidence[0].metadata["ldap_rootdse"]["defaultNamingContext"], ["DC=pirate,DC=htb"])
            self.assertEqual(ad_evidence[0].metadata["smb_shares"][0]["name"], "IPC$")
            self.assertEqual(ad_evidence[0].metadata["rpc_users"][0]["name"], "guest")
            runtime.shutdown()

    def test_exploit_research_keeps_pocs_as_gated_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.manifests_dir = MANIFESTS_DIR
            config.ensure_directories()
            scope_path = write_scope_file(
                root,
                targets=[
                    {
                        "handle": "pirate.htb",
                        "display_name": "Pirate Fixture",
                        "in_scope": True,
                        "assets": [{"asset": PIRATE_IP, "asset_type": "ip"}],
                    }
                ],
            )
            runtime = PrimordialRuntime(config)
            runtime.initialize()
            runtime.import_scope(scope_path, ScopeProfile.HACK_THE_BOX)
            runtime.set_operator_intent("htb_lab")
            target = runtime.store.list_targets()[0]
            runtime.store.insert_evidence(
                EvidenceRecord(
                    target_id=target.id,
                    type=EvidenceType.TOOL_OUTPUT,
                    title="TCP service discovery",
                    summary="Observed IIS and SMB services.",
                    source_ref="fixture://service",
                    verification_status=VerificationStatus.VERIFIED,
                    confidence=0.8,
                    freshness=0.9,
                    metadata={
                        "kind": "tcp_service_discovery",
                        "open_services": [
                            {"service": "http", "port": 80, "banner": "Microsoft-IIS/10.0"},
                            {"service": "smb", "port": 445, "banner": ""},
                        ],
                    },
                )
            )
            task = Task(
                target_id=target.id,
                phase=MethodologyPhase.ANALYSIS,
                kind=TaskKind.EXPLOIT_RESEARCH,
                title="Research relevant public PoCs",
                summary="Search local exploit references.",
                role=AgentRole.CODE_WORKER,
            )
            fake_research = {
                "matches": [
                    {
                        "query": "Microsoft IIS",
                        "section": "RESULTS_EXPLOIT",
                        "edb_id": "12345",
                        "title": "Microsoft IIS Example Remote Exploit",
                        "path": "/usr/share/exploitdb/exploits/windows/remote/12345.py",
                        "platform": "Windows",
                        "score": 8,
                    }
                ],
                "suppressed_matches": [
                    {
                        "query": "Microsoft IIS",
                        "edb_id": "99999",
                        "title": "Microsoft IIS Denial of Service",
                        "path": "/usr/share/exploitdb/exploits/windows/dos/99999.py",
                        "score": -5,
                    }
                ],
                "examined_examples": [{"edb_id": "12345", "title": "Example", "excerpt": "print('poc')"}],
                "command_results": [],
            }
            with patch(
                "primordial.modes.security.execution.PrimitiveExecutor._run_searchsploit_research",
                autospec=True,
                return_value=fake_research,
            ):
                result = runtime.executor.execute(task, None)

            self.assertTrue(result.success)
            self.assertEqual(result.evidence[0].metadata["kind"], "exploit_research")
            self.assertFalse(result.evidence[0].metadata["executes_pocs"])
            self.assertIn("No PoC was executed", result.notes[0].body)
            self.assertEqual(result.interests[0].metadata["class"], "exploit_research")
            self.assertEqual(result.notifications[0].channel, NotificationChannel.DISCORD)
            self.assertEqual(result.notifications[0].event_type, "poc_research_candidate")
            self.assertEqual(result.notifications[0].urgency, "high")
            self.assertIn("PoC research candidates found for pirate.htb", result.notifications[0].summary)
            self.assertFalse(result.notifications[0].metadata["executes_pocs"])
            runtime.shutdown()

    def test_poc_applicability_validation_is_read_only_and_prerequisite_aware(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.manifests_dir = MANIFESTS_DIR
            config.ensure_directories()
            scope_path = write_scope_file(
                root,
                targets=[
                    {
                        "handle": "pirate.htb",
                        "display_name": "Pirate Fixture",
                        "in_scope": True,
                        "assets": [{"asset": PIRATE_IP, "asset_type": "ip"}],
                    }
                ],
            )
            runtime = PrimordialRuntime(config)
            runtime.initialize()
            runtime.import_scope(scope_path, ScopeProfile.HACK_THE_BOX)
            runtime.set_operator_intent("htb_lab")
            target = runtime.store.list_targets()[0]
            runtime.store.insert_evidence(
                EvidenceRecord(
                    target_id=target.id,
                    type=EvidenceType.TOOL_OUTPUT,
                    title="TCP service discovery",
                    summary="Observed IIS and AD services.",
                    source_ref="fixture://service",
                    verification_status=VerificationStatus.VERIFIED,
                    confidence=0.8,
                    freshness=0.9,
                    metadata={
                        "kind": "tcp_service_discovery",
                        "open_services": [
                            {"service": "http", "port": 80, "banner": "Microsoft-IIS/10.0"},
                            {"service": "ldap", "port": 389, "banner": ""},
                            {"service": "kerberos", "port": 88, "banner": ""},
                        ],
                    },
                )
            )
            research = EvidenceRecord(
                target_id=target.id,
                type=EvidenceType.MODEL_REVIEW,
                title="Exploit research: pirate.htb",
                summary=(
                    "Searchsploit research found 2 non-DoS candidate(s): "
                    "Microsoft Active Directory LDAP Server - Username Enumeration, "
                    "Microsoft Exchange Active Directory Topology - Unquoted Service Path."
                ),
                source_ref="fixture://exploit-research",
                verification_status=VerificationStatus.PARTIAL,
                confidence=0.68,
                freshness=0.9,
                metadata={"kind": "exploit_research", "match_count": 2, "executes_pocs": False},
            )
            runtime.store.insert_evidence(research)
            task = Task(
                target_id=target.id,
                phase=MethodologyPhase.ANALYSIS,
                kind=TaskKind.POC_APPLICABILITY_VALIDATION,
                title="Validate public PoC applicability",
                summary="Classify retained public PoCs.",
                role=AgentRole.CODE_WORKER,
            )

            result = runtime.executor.execute(task, None)

            self.assertTrue(result.success)
            self.assertEqual(result.evidence[0].metadata["kind"], "poc_applicability_validation")
            self.assertFalse(result.evidence[0].metadata["executes_pocs"])
            self.assertFalse(result.evidence[0].metadata["writes_exploit_code"])
            self.assertIn("No PoC was executed", result.notes[0].body)
            self.assertIn("requires user shell", result.notes[0].body)
            runtime.shutdown()

    def test_searchsploit_queries_are_versioned_and_do_not_use_raw_headers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.manifests_dir = MANIFESTS_DIR
            config.ensure_directories()
            scope_path = write_scope_file(
                root,
                targets=[
                    {
                        "handle": "pirate.htb",
                        "display_name": "Pirate Fixture",
                        "in_scope": True,
                        "assets": [{"asset": PIRATE_IP, "asset_type": "ip"}],
                    }
                ],
            )
            runtime = PrimordialRuntime(config)
            runtime.initialize()
            runtime.set_operator_intent("htb_lab")
            runtime.import_scope(scope_path, ScopeProfile.HACK_THE_BOX)
            target = runtime.store.list_targets()[0]
            runtime.store.insert_evidence(
                EvidenceRecord(
                    target_id=target.id,
                    type=EvidenceType.HTTP_REPLAY,
                    title="HTTP probe",
                    summary="IIS default page",
                    source_ref="fixture://http",
                    verification_status=VerificationStatus.VERIFIED,
                    confidence=0.8,
                    freshness=0.9,
                    metadata={"headers": {"server": "Microsoft-IIS/10.0"}, "title": "IIS Windows Server"},
                )
            )
            runtime.store.insert_evidence(
                EvidenceRecord(
                    target_id=target.id,
                    type=EvidenceType.TOOL_OUTPUT,
                    title="TCP service discovery",
                    summary="Observed IIS headers and AD services.",
                    source_ref="fixture://service",
                    verification_status=VerificationStatus.VERIFIED,
                    confidence=0.8,
                    freshness=0.9,
                    metadata={
                        "kind": "tcp_service_discovery",
                        "open_services": [
                            {
                                "service": "http",
                                "port": 80,
                                "banner": (
                                    "HTTP/1.1 200 OK Content-Length: 703 Content-Type: text/html "
                                    "Last-Modified: Sun, Server: Microsoft-IIS/10.0"
                                ),
                            },
                            {"service": "ldap", "port": 389, "banner": ""},
                        ],
                    },
                )
            )

            queries = runtime.executor._build_searchsploit_queries(target.id)

            self.assertIn("Microsoft IIS 10.0", queries)
            self.assertIn("IIS 10.0", queries)
            self.assertIn("Active Directory LDAP", queries)
            self.assertNotIn("Microsoft IIS", queries)
            self.assertFalse(any(query.lower().startswith("http") for query in queries))
            self.assertFalse(any("content-length" in query.lower() for query in queries))
            runtime.shutdown()

    def test_searchsploit_refines_precise_queries_when_no_rows_return(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.manifests_dir = MANIFESTS_DIR
            config.ensure_directories()
            runtime = PrimordialRuntime(config)
            runtime.initialize()
            runtime.set_operator_intent("exploit_research_allowed")

            def fake_command(_executor, *, tool: str, argv: list[str], timeout_seconds: int) -> dict[str, object]:
                query = argv[-1]
                stdout = '{"RESULTS_EXPLOIT": [], "RESULTS_PAPER": []}'
                if query == "IIS 10.0":
                    stdout = (
                        '{"RESULTS_EXPLOIT": ['
                        '{"Title": "IIS 10.0 Remote Code Execution", "EDB-ID": "123", '
                        '"Path": "/usr/share/exploitdb/exploits/windows/remote/123.py", '
                        '"Type": "remote", "Platform": "windows"}'
                        '], "RESULTS_PAPER": []}'
                    )
                return {
                    "tool": tool,
                    "argv": argv,
                    "executed": True,
                    "returncode": 0,
                    "stdout": stdout,
                    "stderr": "",
                    "timeout": False,
                }

            with patch(
                "primordial.modes.security.execution.PrimitiveExecutor._run_host_command",
                autospec=True,
                side_effect=fake_command,
            ):
                research = runtime.executor._run_searchsploit_research(["Microsoft IIS 10.0"])

            self.assertEqual(len(research["matches"]), 1)
            self.assertEqual(research["matches"][0]["query"], "IIS 10.0")
            refined = [item for item in research["command_results"] if item.get("refined_from")]
            self.assertTrue(refined)
            self.assertEqual(refined[-1]["refined_from"], "Microsoft IIS 10.0")
            runtime.shutdown()

    def test_kerberos_user_discovery_normalizes_ldap_principals(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.manifests_dir = MANIFESTS_DIR
            config.ensure_directories()
            scope_path = write_scope_file(
                root,
                targets=[
                    {
                        "handle": "pirate.htb",
                        "display_name": "Pirate Fixture",
                        "in_scope": True,
                        "assets": [{"asset": PIRATE_IP, "asset_type": "ip"}],
                    }
                ],
            )
            runtime = PrimordialRuntime(config)
            runtime.initialize()
            runtime.import_scope(scope_path, ScopeProfile.HACK_THE_BOX)
            target = runtime.store.list_targets()[0]
            runtime.store.insert_evidence(
                EvidenceRecord(
                    target_id=target.id,
                    type=EvidenceType.TOOL_OUTPUT,
                    title="AD enumeration",
                    summary="RootDSE observed.",
                    source_ref="fixture://ad",
                    verification_status=VerificationStatus.VERIFIED,
                    confidence=0.8,
                    freshness=0.9,
                    metadata={
                        "kind": "ad_enumeration",
                        "ldap_rootdse": {"defaultNamingContext": ["DC=pirate,DC=htb"]},
                    },
                )
            )
            task = Task(
                target_id=target.id,
                phase=MethodologyPhase.RECON,
                kind=TaskKind.KERBEROS_USER_DISCOVERY,
                title="Run Kerberos user discovery",
                summary="Discover users.",
                role=AgentRole.RECON_WORKER,
            )

            def fake_command(_executor, *, tool: str, argv: list[str], timeout_seconds: int) -> dict[str, object]:
                stdout = ""
                if tool == "ldapsearch":
                    stdout = (
                        "dn: CN=Anne Bonny,CN=Users,DC=pirate,DC=htb\n"
                        "sAMAccountName: anne\n"
                        "userPrincipalName: anne@pirate.htb\n"
                        "servicePrincipalName: HTTP/pirate.htb\n\n"
                        "dn: CN=PIRATE$,CN=Computers,DC=pirate,DC=htb\n"
                        "sAMAccountName: PIRATE$\n\n"
                    )
                return {
                    "tool": tool,
                    "argv": argv,
                    "executed": True,
                    "returncode": 0,
                    "stdout": stdout,
                    "stderr": "",
                    "timeout": False,
                }

            with patch(
                "primordial.modes.security.execution.PrimitiveExecutor._run_host_command",
                autospec=True,
                side_effect=fake_command,
            ):
                result = runtime.executor.execute(task, None)

            self.assertTrue(result.success)
            self.assertEqual(result.evidence[0].metadata["kind"], "kerberos_user_discovery")
            self.assertEqual(result.evidence[0].metadata["users"][0]["username"], "anne")
            self.assertEqual(result.evidence[0].metadata["spn_candidates"][0]["spn"], "HTTP/pirate.htb")
            runtime.shutdown()

    def test_credentialed_access_uses_redacted_secret_commands(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.manifests_dir = MANIFESTS_DIR
            config.ensure_directories()
            scope_path = write_scope_file(
                root,
                targets=[
                    {
                        "handle": "pirate.htb",
                        "display_name": "Pirate Fixture",
                        "in_scope": True,
                        "assets": [{"asset": PIRATE_IP, "asset_type": "ip"}],
                    }
                ],
            )
            runtime = PrimordialRuntime(config)
            runtime.initialize()
            runtime.import_scope(scope_path, ScopeProfile.HACK_THE_BOX)
            runtime.set_operator_intent("htb_lab")
            runtime.set_lab_credentials(username=fixture_secret("anne"), password=fixture_secret("super-secret"), domain="PIRATE")
            target = runtime.store.list_targets()[0]
            task = Task(
                target_id=target.id,
                phase=MethodologyPhase.EXPLOITATION,
                kind=TaskKind.CREDENTIALED_ACCESS_CHECK,
                title="Verify credentialed access",
                summary="Check SMB/WinRM.",
                role=AgentRole.EXPLOITATION_WORKER,
            )

            def fake_secret_command(
                _executor,
                *,
                tool: str,
                argv: list[str],
                redacted_argv: list[str],
                timeout_seconds: int,
            ) -> dict[str, object]:
                self.assertNotIn("super-secret", " ".join(redacted_argv))
                if argv[-1].startswith("get "):
                    quoted = argv[-1].split('"')
                    if len(quoted) >= 4 and quoted[1].endswith("user.txt"):
                        Path(quoted[3]).write_text("HTB{user-fixture}\n", encoding="utf-8")
                return {
                    "tool": tool,
                    "argv": redacted_argv,
                    "executed": True,
                    "returncode": 0,
                    "stdout": "Disk|C$|Default share\nuser.txt",
                    "stderr": "",
                    "timeout": False,
                }

            with patch(
                "primordial.modes.security.execution.PrimitiveExecutor._run_secret_host_command",
                autospec=True,
                side_effect=fake_secret_command,
            ):
                result = runtime.executor.execute(task, None)

            serialized = json.dumps(result.evidence[0].as_payload())
            self.assertTrue(result.success)
            self.assertEqual(result.evidence[0].metadata["kind"], "credentialed_access_check")
            self.assertNotIn("super-secret", serialized)
            self.assertTrue(result.evidence[0].metadata["auth_results"][0]["valid"])
            self.assertEqual(result.evidence[0].metadata["flag_hits"][0]["value"], "HTB{user-fixture}")
            runtime.shutdown()


if __name__ == "__main__":
    unittest.main()
