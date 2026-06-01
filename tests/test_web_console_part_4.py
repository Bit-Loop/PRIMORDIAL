from __future__ import annotations

from tests.test_web_console_common import *


class WebConsoleTestsPart4(WebConsoleTestsBase):
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

__all__ = ["WebConsoleTestsPart4"]
