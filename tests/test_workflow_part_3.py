from __future__ import annotations

from tests.test_workflow_common import *


class WorkflowTestsPart3(WorkflowTestsBase):
    def test_planner_persists_methodology_state_for_target(self) -> None:
        report = self.runtime.run_tick(max_executions=0)

        stored_target = self.runtime.store.get_target(self.target.id)
        methodology_state = stored_target.metadata.get("methodology_state", {})

        self.assertTrue(report.created_tasks)
        self.assertIsInstance(methodology_state, dict)
        self.assertEqual(methodology_state.get("phase"), "recon")
        self.assertEqual(methodology_state.get("subphase"), "bootstrap")
        self.assertTrue(methodology_state.get("candidate_actions"))
        self.assertEqual(methodology_state.get("planner_version"), 2)

    def test_broker_execution_exception_is_finalized_instead_of_leaking_running_state(self) -> None:
        task = Task(
            target_id=self.target.id,
            phase=MethodologyPhase.RECON,
            kind=TaskKind.RECON_SCAN,
            title="Crashy recon",
            summary="Broker execution should be finalized on exception",
            role=AgentRole.RECON_WORKER,
            risk_tier=RiskTier.LOW,
            status=TaskStatus.PENDING,
        )
        self.runtime.store.insert_task(task)
        report = OrchestrationReport()

        with patch.object(self.runtime.worker_broker, "execute", side_effect=RuntimeError("boom")):
            self.runtime.workflow._execute_ready_tasks(report, max_executions=1)

        refreshed_task = self.runtime.store.get_task(task.id)
        latest_run = next(run for run in self.runtime.store.list_task_runs(limit=20) if run.task_id == task.id)

        self.assertIn(refreshed_task.status, {TaskStatus.PENDING, TaskStatus.FAILED})
        self.assertNotEqual(refreshed_task.status, TaskStatus.RUNNING)
        self.assertEqual(latest_run.status, TaskRunStatus.FAILED)
        self.assertIsNotNone(latest_run.finished_at)
        self.assertIn("boom", latest_run.error or "")

    def test_broker_timeout_exception_sets_timed_out_run_status(self) -> None:
        task = Task(
            target_id=self.target.id,
            phase=MethodologyPhase.RECON,
            kind=TaskKind.RECON_SCAN,
            title="Timeout recon",
            summary="Broker timeout should be classified distinctly",
            role=AgentRole.RECON_WORKER,
            risk_tier=RiskTier.LOW,
            status=TaskStatus.PENDING,
        )
        self.runtime.store.insert_task(task)
        report = OrchestrationReport()

        with patch.object(self.runtime.worker_broker, "execute", side_effect=TimeoutError("worker timed out")):
            self.runtime.workflow._execute_ready_tasks(report, max_executions=1)

        refreshed_task = self.runtime.store.get_task(task.id)
        latest_run = next(run for run in self.runtime.store.list_task_runs(limit=20) if run.task_id == task.id)

        self.assertIn(refreshed_task.status, {TaskStatus.PENDING, TaskStatus.FAILED})
        self.assertEqual(latest_run.status, TaskRunStatus.TIMED_OUT)
        self.assertTrue(latest_run.metadata["timed_out"])

    def test_scope_reduction_blocks_active_tasks_for_target(self) -> None:
        pending = Task(
            target_id=self.target.id,
            phase=MethodologyPhase.RECON,
            kind=TaskKind.RECON_SCAN,
            title="Pending recon",
            summary="Should be blocked when scope is reduced.",
            role=AgentRole.RECON_WORKER,
            risk_tier=RiskTier.LOW,
            status=TaskStatus.PENDING,
        )
        approval = Task(
            target_id=self.target.id,
            phase=MethodologyPhase.EXPLOITATION,
            kind=TaskKind.VERIFY_HYPOTHESIS,
            title="Approved verification",
            summary="Should also be blocked when scope is reduced.",
            role=AgentRole.EXPLOITATION_WORKER,
            risk_tier=RiskTier.HIGH,
            status=TaskStatus.NEEDS_APPROVAL,
            requires_approval=True,
        )
        self.runtime.store.insert_task(pending)
        self.runtime.store.insert_task(approval)

        self.runtime.update_target_fields(
            handle=self.target.handle,
            profile=self.target.profile,
            display_name=self.target.display_name,
            assets=[self.target.handle],
            in_scope=False,
        )

        self.assertEqual(self.runtime.store.get_task(pending.id).status, TaskStatus.BLOCKED)
        self.assertEqual(self.runtime.store.get_task(approval.id).status, TaskStatus.BLOCKED)
        self.assertTrue(self.runtime.store.get_task(pending.id).metadata["scope_invalidated"])

    def test_out_of_scope_target_is_rechecked_after_task_claim(self) -> None:
        task = Task(
            target_id=self.target.id,
            phase=MethodologyPhase.RECON,
            kind=TaskKind.RECON_SCAN,
            title="Racey recon",
            summary="Target scope flips after planning.",
            role=AgentRole.RECON_WORKER,
            risk_tier=RiskTier.LOW,
            status=TaskStatus.PENDING,
        )
        self.runtime.store.insert_task(task)
        with self.runtime.store.connect() as connection:
            connection.execute(
                "UPDATE targets SET in_scope = false, updated_at = %s WHERE id = %s",
                (utc_now().isoformat(), self.target.id),
            )
            connection.commit()
        report = OrchestrationReport()

        self.runtime.workflow._execute_ready_tasks(report, max_executions=1)

        refreshed = self.runtime.store.get_task(task.id)
        self.assertEqual(refreshed.status, TaskStatus.BLOCKED)
        self.assertIn("out of scope", refreshed.metadata["invalid_target_reason"])

    def test_resource_reserve_guard_defers_task_before_dispatch(self) -> None:
        task = Task(
            target_id=self.target.id,
            phase=MethodologyPhase.RECON,
            kind=TaskKind.RECON_SCAN,
            title="Memory guarded recon",
            summary="Should wait until RAM and VRAM reserves are available",
            role=AgentRole.RECON_WORKER,
            risk_tier=RiskTier.LOW,
            status=TaskStatus.PENDING,
        )
        self.runtime.store.insert_task(task)
        self.runtime.workflow.resource_status_loader = lambda: {
            "cpu": {"available": True, "memory_available_mb": 1024.0},
            "gpu": {"available": True, "memory_free_mb": 128.0},
        }
        self.runtime.workflow.resource_reserve_loader = lambda: {
            "min_free_cpu_ram_mb": 2048,
            "min_free_gpu_ram_mb": 368,
        }
        report = OrchestrationReport()

        self.runtime.workflow._execute_ready_tasks(report, max_executions=1)

        refreshed_task = self.runtime.store.get_task(task.id)
        self.assertEqual(refreshed_task.status, TaskStatus.WAITING)
        self.assertEqual(refreshed_task.metadata["wait_metadata"]["resource_reserve_guard"], True)
        self.assertFalse([run for run in self.runtime.store.list_task_runs(limit=20) if run.task_id == task.id])
        event = next(
            item
            for item in self.runtime.store.list_events(limit=20)
            if item.task_id == task.id and item.type == EventType.TASK_DEFERRED
        )
        self.assertEqual(event.metadata["resource_reserve_guard"], True)
        self.assertIn("CPU RAM available", event.summary)
        self.assertIn("GPU VRAM free", event.summary)

    def test_ssh_http_linux_evidence_blocks_credentialed_windows_prompt_and_stale_approval(self) -> None:
        self.runtime.set_operator_intent("credential_validation")
        self.runtime.set_known_credentials(username=fixture_secret("anne"), password=fixture_secret("secret"), domain="PIRATE")
        self.runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=self.target.id,
                type=EvidenceType.TOOL_OUTPUT,
                title="TCP service discovery",
                summary="Observed OpenSSH and nginx on Ubuntu.",
                source_ref="fixture://helix-linux-services",
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.86,
                freshness=0.9,
                metadata={
                    "kind": "tcp_service_discovery",
                    "open_services": [
                        {"port": 22, "service": "ssh", "product": "OpenSSH", "version": "8.9p1 Ubuntu"},
                        {"port": 80, "service": "http", "product": "nginx", "banner": "Ubuntu"},
                    ],
                },
            )
        )
        stale_approval = Task(
            target_id=self.target.id,
            phase=MethodologyPhase.EXPLOITATION,
            kind=TaskKind.CREDENTIALED_ACCESS_CHECK,
            title="Verify credentialed SMB/WinRM access",
            summary="Stale Windows credential prompt.",
            role=AgentRole.EXPLOITATION_WORKER,
            risk_tier=RiskTier.HIGH,
            status=TaskStatus.NEEDS_APPROVAL,
            requires_approval=True,
        )
        self.runtime.store.insert_task(stale_approval)

        report = self.runtime.run_tick(max_executions=0)
        refreshed = self.runtime.store.get_task(stale_approval.id)

        self.assertFalse(any(task.kind == TaskKind.CREDENTIALED_ACCESS_CHECK for task in report.created_tasks))
        self.assertIsNotNone(refreshed)
        assert refreshed is not None
        self.assertEqual(refreshed.status, TaskStatus.BLOCKED)
        self.assertIn("Linux/Unix", refreshed.metadata["invalidation_reason"])

    def test_linux_samba_on_445_does_not_plan_windows_credentialed_access(self) -> None:
        self.runtime.set_operator_intent("credential_validation")
        self.runtime.set_known_credentials(username=fixture_secret("anne"), password=fixture_secret("secret"), domain="")
        self.runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=self.target.id,
                type=EvidenceType.TOOL_OUTPUT,
                title="TCP service discovery",
                summary="Observed Samba file sharing on Linux.",
                source_ref="fixture://linux-samba",
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.84,
                freshness=0.9,
                metadata={
                    "kind": "tcp_service_discovery",
                    "open_services": [
                        {"port": 445, "service": "netbios-ssn", "product": "Samba smbd", "banner": "Samba 4.15 Ubuntu"},
                    ],
                },
            )
        )

        report = self.runtime.run_tick(max_executions=0)
        state = self.runtime.workflow.preview_target_state(self.target)

        self.assertFalse(any(task.kind == TaskKind.CREDENTIALED_ACCESS_CHECK for task in report.created_tasks))
        self.assertFalse(
            any(
                action["kind"] == TaskKind.CREDENTIALED_ACCESS_CHECK.value
                for action in state.as_payload()["candidate_actions"]
            )
        )

__all__ = ["WorkflowTestsPart3"]
