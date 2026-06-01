from __future__ import annotations

from tests.test_runtime_integration_common import *


class RuntimeIntegrationTestsPart2(RuntimeIntegrationTestsBase):
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

__all__ = ["RuntimeIntegrationTestsPart2"]
