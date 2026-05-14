from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from primordial.config import AppConfig
from primordial.runtime import PrimordialRuntime
from primordial.core.domain.enums import (
    AgentRole,
    EvidenceType,
    EventType,
    InterestStatus,
    MethodologyPhase,
    ProviderRoute,
    RiskTier,
    ScopeProfile,
    TaskKind,
    TaskRunStatus,
    TaskStatus,
    VerificationStatus,
)
from primordial.core.domain.models import EvidenceRecord, Interest, Target, Task, utc_now
from primordial.core.domain.models import OrchestrationReport
from primordial.core.web.app import PrimordialWebApp
from tests.support import build_probe_fixture, write_scope_file


MANIFESTS_DIR = Path(__file__).resolve().parents[1] / "manifests"


class WorkflowTests(unittest.TestCase):
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
        self.target = self.runtime.store.list_targets()[0]
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

    def test_first_tick_creates_recon_task_or_run_artifacts(self) -> None:
        report = self.runtime.run_tick(max_executions=1)

        task_kinds = [task.kind.value for task in report.created_tasks]
        self.assertIn("recon_scan", task_kinds)
        self.assertIn("service_discovery", task_kinds)
        self.assertTrue(
            self.runtime.store.list_tasks(limit=10) or self.runtime.store.list_evidence(limit=10)
        )

    def test_empty_target_handles_are_not_planned_or_shown_in_control_plane_scope(self) -> None:
        blank = Target(handle="", display_name="", profile=ScopeProfile.HACK_THE_BOX)
        self.runtime.store.insert_target(blank)

        report = self.runtime.run_tick(max_executions=0)
        response = PrimordialWebApp(self.runtime).dispatch("GET", "/api/control-plane")
        control_plane = json.loads(response.body)

        self.assertFalse(any(task.target_id == blank.id for task in report.created_tasks))
        self.assertTrue(any(event.metadata.get("invalid_target") for event in report.events))
        self.assertEqual(response.status, 200)
        self.assertIn("pirate.htb", {item["handle"] for item in control_plane["scope"]})
        self.assertNotIn("", {item["handle"] for item in control_plane["scope"]})

    def test_existing_pending_task_for_empty_target_is_blocked_before_execution(self) -> None:
        blank = Target(handle="", display_name="", profile=ScopeProfile.HACK_THE_BOX)
        self.runtime.store.insert_target(blank)
        task = Task(
            target_id=blank.id,
            phase=MethodologyPhase.RECON,
            kind=TaskKind.RECON_SCAN,
            title="Run recon sweep",
            summary="Invalid target fixture",
            role=AgentRole.RECON_WORKER,
            priority=999,
        )
        self.runtime.store.insert_task(task)

        report = self.runtime.run_tick(max_executions=1)
        refreshed = self.runtime.store.get_task(task.id)

        self.assertEqual(refreshed.status, TaskStatus.BLOCKED)
        self.assertTrue(refreshed.metadata["invalid_target"])
        self.assertTrue(any(event.task_id == task.id and event.metadata.get("invalid_target") for event in report.events))

    def test_runtime_rejects_empty_target_handle(self) -> None:
        with self.assertRaises(ValueError):
            self.runtime.update_target_fields(
                handle="",
                profile=ScopeProfile.HACK_THE_BOX,
                assets=["10.129.244.220"],
            )

    def test_evidence_drives_analysis_and_exploitation_planning(self) -> None:
        self.runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=self.target.id,
                type=EvidenceType.TOOL_OUTPUT,
                title="Recon result",
                summary="Collected login endpoints and redirect behavior",
                source_ref="fixture://evidence/1",
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.7,
                freshness=0.9,
            )
        )
        self.runtime.store.insert_interest(
            Interest(
                target_id=self.target.id,
                title="Suspicious auth flow",
                summary="Candidate workflow issue",
                evidence_refs=[],
                status=InterestStatus.VERIFIED,
                confidence=0.75,
            )
        )

        report = self.runtime.run_tick(max_executions=0)
        kinds = {task.kind.value for task in report.created_tasks}

        self.assertIn("analyze_evidence", kinds)
        self.assertIn("verify_hypothesis", kinds)

    def test_resume_tracker_promotes_due_waiting_tasks(self) -> None:
        task = Task(
            target_id=self.target.id,
            phase=MethodologyPhase.RECON,
            kind=TaskKind.RECON_SCAN,
            title="Deferred recon",
            summary="Resume after temporary throttling",
            role=AgentRole.RECON_WORKER,
            risk_tier=RiskTier.LOW,
            status=TaskStatus.WAITING,
            metadata={"resume_after": utc_now().isoformat()},
        )
        self.runtime.store.insert_task(task)

        resumed = self.runtime.resume_tracker.resume_due_tasks()

        self.assertEqual(resumed, 1)
        self.assertEqual(self.runtime.store.get_task(task.id).status, TaskStatus.PENDING)

    def test_task_approval_records_operator_approval_metadata(self) -> None:
        task = Task(
            target_id=self.target.id,
            phase=MethodologyPhase.EXPLOITATION,
            kind=TaskKind.VERIFY_HYPOTHESIS,
            title="Approve gated verification",
            summary="Read-only verification planning needs explicit operator approval.",
            role=AgentRole.EXPLOITATION_WORKER,
            risk_tier=RiskTier.HIGH,
            status=TaskStatus.NEEDS_APPROVAL,
            requires_approval=True,
        )
        self.runtime.store.insert_task(task)

        approved = self.runtime.workflow.approve_task(task.id, approved=True)

        self.assertIsNotNone(approved)
        self.assertEqual(approved.status, TaskStatus.PENDING)
        self.assertTrue(approved.metadata["operator_approved"])
        self.assertIn("operator_approved_at", approved.metadata)

    def test_primitive_hint_narrows_validation_and_execution_primitives(self) -> None:
        task = Task(
            target_id=self.target.id,
            phase=MethodologyPhase.EXPLOITATION,
            kind=TaskKind.VERIFY_HYPOTHESIS,
            title="Verify finding candidates",
            summary="Use the explicit primitive hint instead of broad auth-analysis tags.",
            role=AgentRole.EXPLOITATION_WORKER,
            risk_tier=RiskTier.HIGH,
            required_capabilities=["auth-analysis", "finding-verification"],
            metadata={"primitive_hint": "finding-verification"},
        )

        validation_primitives = self.runtime.workflow._stored_primitives_for_task(task)
        execution_primitives = self.runtime.security.primitive_executor.resolve_primitives(task)

        self.assertEqual([primitive.name for primitive in validation_primitives], ["finding-verification"])
        self.assertEqual([primitive.name for primitive in execution_primitives], ["finding-verification"])

    def test_validation_blocks_tasks_without_primitive_coverage(self) -> None:
        task = Task(
            target_id=self.target.id,
            phase=MethodologyPhase.ANALYSIS,
            kind=TaskKind.ANALYZE_EVIDENCE,
            title="Broken task",
            summary="Should fail validation",
            role=AgentRole.ANALYSIS_WORKER,
            required_capabilities=["nonexistent-capability"],
            risk_tier=RiskTier.LOW,
        )
        report = OrchestrationReport()

        self.runtime.workflow._register_task(task, self.target, report)

        blocked = self.runtime.store.get_task(task.id)
        self.assertIsNotNone(blocked)
        self.assertEqual(blocked.status, TaskStatus.BLOCKED)
        self.assertIn("validation_errors", blocked.metadata)

    def test_analysis_replans_when_target_state_changes(self) -> None:
        self.runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=self.target.id,
                type=EvidenceType.TOOL_OUTPUT,
                title="Initial recon result",
                summary="First evidence batch",
                source_ref="fixture://evidence/initial",
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.7,
                freshness=0.9,
            )
        )
        first = self.runtime.run_tick(max_executions=0)
        analysis_tasks = [task for task in first.created_tasks if task.kind == TaskKind.ANALYZE_EVIDENCE]
        self.assertEqual(len(analysis_tasks), 1)
        analysis_tasks[0].status = TaskStatus.SUCCEEDED
        self.runtime.store.insert_task(analysis_tasks[0])

        unchanged = self.runtime.run_tick(max_executions=0)
        self.assertFalse(any(task.kind == TaskKind.ANALYZE_EVIDENCE for task in unchanged.created_tasks))

        self.runtime.store.insert_interest(
            Interest(
                target_id=self.target.id,
                title="Auth-adjacent surface review backlog",
                summary="Generated analysis interest should not invalidate the satisfied analysis signature.",
                evidence_refs=[],
                status=InterestStatus.OPEN,
                confidence=0.76,
                metadata={"rank": 1, "phase": MethodologyPhase.ANALYSIS.value},
            )
        )
        unchanged_after_interest = self.runtime.run_tick(max_executions=0)
        self.assertFalse(any(task.kind == TaskKind.ANALYZE_EVIDENCE for task in unchanged_after_interest.created_tasks))

        self.runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=self.target.id,
                type=EvidenceType.TOOL_OUTPUT,
                title="New recon result",
                summary="Second evidence batch should force a fresh reasoning pass",
                source_ref="fixture://evidence/new",
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.75,
                freshness=0.95,
            )
        )
        changed = self.runtime.run_tick(max_executions=0)
        self.assertTrue(any(task.kind == TaskKind.ANALYZE_EVIDENCE for task in changed.created_tasks))

    def test_operator_active_ip_change_invalidates_old_recon_generation(self) -> None:
        self.runtime.register_target(
            handle="pirate.htb",
            profile=ScopeProfile.HACK_THE_BOX,
            assets=[{"asset": "10.129.47.117", "asset_type": "ip"}],
            emit_event=False,
        )
        self.runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=self.target.id,
                type=EvidenceType.TOOL_OUTPUT,
                title="Old TCP service discovery",
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

        self.runtime.ask_operator_ai("You should be using 10.129.244.95", target="pirate.htb")
        report = self.runtime.run_tick(max_executions=0)

        self.assertTrue(any(task.kind == TaskKind.SERVICE_DISCOVERY for task in report.created_tasks))
        service_task = next(task for task in report.created_tasks if task.kind == TaskKind.SERVICE_DISCOVERY)
        self.assertEqual(service_task.metadata["active_ip"], "10.129.244.95")
        self.assertEqual(str(service_task.metadata["active_ip_generation"]), "1")

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
        self.runtime.set_known_credentials(username="anne", password="secret", domain="PIRATE")
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
        self.runtime.set_known_credentials(username="anne", password="secret", domain="")
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

    def test_windows_credentialed_access_requires_intent_and_windows_surface_evidence(self) -> None:
        self.runtime.set_known_credentials(username="anne", password="secret", domain="PIRATE")
        service_evidence = EvidenceRecord(
            target_id=self.target.id,
            type=EvidenceType.TOOL_OUTPUT,
            title="TCP service discovery",
            summary="Observed Microsoft Windows SMB and WinRM.",
            source_ref="fixture://windows-services",
            verification_status=VerificationStatus.VERIFIED,
            confidence=0.88,
            freshness=0.9,
            metadata={
                "kind": "tcp_service_discovery",
                "open_services": [
                    {"port": 445, "service": "microsoft-ds", "product": "Microsoft Windows Server 2019"},
                    {"port": 5985, "service": "winrm", "product": "Microsoft HTTPAPI httpd"},
                ],
            },
        )
        self.runtime.store.insert_evidence(service_evidence)

        blocked_report = self.runtime.run_tick(max_executions=0)
        self.assertFalse(any(task.kind == TaskKind.CREDENTIALED_ACCESS_CHECK for task in blocked_report.created_tasks))

        self.runtime.set_operator_intent("credential_validation")
        allowed_report = self.runtime.run_tick(max_executions=0)
        credential_tasks = [task for task in allowed_report.created_tasks if task.kind == TaskKind.CREDENTIALED_ACCESS_CHECK]

        self.assertEqual(len(credential_tasks), 1)
        self.assertEqual(credential_tasks[0].status, TaskStatus.NEEDS_APPROVAL)
        self.assertIn(service_evidence.id, credential_tasks[0].evidence_refs)
        self.assertEqual(credential_tasks[0].metadata["credentialed_access_surface"]["os_family"], "windows")
        self.assertIn("winrm", credential_tasks[0].metadata["protocols"])

    def test_stuck_planner_auto_approves_agent_chat_premium_review_packet(self) -> None:
        evidence = EvidenceRecord(
            target_id=self.target.id,
            type=EvidenceType.OPERATOR_NOTE,
            title="Manual evidence note",
            summary="Operator supplied live evidence, but no primitive-backed next action is obvious.",
            source_ref="fixture://manual-note",
            verification_status=VerificationStatus.PARTIAL,
            confidence=0.6,
            freshness=0.8,
            metadata={"kind": "tcp_service_discovery", "open_services": []},
        )
        self.runtime.store.insert_evidence(evidence)
        signature = self.runtime.workflow._target_analysis_signature(self.target)
        analysis = Task(
            target_id=self.target.id,
            phase=MethodologyPhase.ANALYSIS,
            kind=TaskKind.ANALYZE_EVIDENCE,
            title="Analyze accumulated evidence",
            summary="Already analyzed.",
            role=AgentRole.ANALYSIS_WORKER,
            status=TaskStatus.SUCCEEDED,
            metadata={"analysis_signature": signature},
        )
        self.runtime.store.insert_task(analysis)

        report = self.runtime.run_tick(max_executions=0)
        review_tasks = [task for task in report.created_tasks if task.kind == TaskKind.REVIEW_PREMIUM_ESCALATION]

        self.assertEqual(len(review_tasks), 1)
        self.assertEqual(review_tasks[0].provider_route, ProviderRoute.REMOTE_PREMIUM)
        self.assertEqual(review_tasks[0].status, TaskStatus.PENDING)
        self.assertTrue(review_tasks[0].metadata["remote_premium_operator_approved"])
        self.assertTrue(review_tasks[0].metadata["operator_approved"])
        self.assertEqual(review_tasks[0].metadata["auto_approval_source"], "agent_chat_api_wrapper")
        packet = review_tasks[0].metadata["escalation_package"]["metadata"]["packet"]
        self.assertEqual(packet["operator_intent"], "recon_only")
        self.assertEqual(packet["required_output"]["recommended_next_actions"], "array<object>")
        self.assertTrue(
            any(
                event.task_id == review_tasks[0].id and event.metadata.get("auto_approved")
                for event in self.runtime.store.list_events(limit=10)
            )
        )

    def test_agent_chat_premium_auto_approval_does_not_apply_to_credential_tasks(self) -> None:
        task = Task(
            target_id=self.target.id,
            phase=MethodologyPhase.EXPLOITATION,
            kind=TaskKind.CREDENTIALED_ACCESS_CHECK,
            title="Credential check should not auto-approve",
            summary="Remote premium route is not allowed to approve credential validation.",
            role=AgentRole.CLAUDE_REVIEWER,
            status=TaskStatus.PENDING,
            provider_route=ProviderRoute.REMOTE_PREMIUM,
            metadata={"remote_premium_policy_approval_required": True},
        )
        report = OrchestrationReport()

        self.runtime.workflow._register_task(task, self.target, report)
        stored = self.runtime.store.get_task(task.id)

        self.assertIsNotNone(stored)
        assert stored is not None
        self.assertEqual(stored.status, TaskStatus.BLOCKED)
        self.assertFalse(stored.metadata.get("remote_premium_operator_approved", False))

    def test_remote_review_actions_are_admitted_only_with_evidence_scope_and_policy(self) -> None:
        service_evidence = EvidenceRecord(
            target_id=self.target.id,
            type=EvidenceType.TOOL_OUTPUT,
            title="HTTP service evidence",
            summary="HTTP service responds and supports bounded content discovery.",
            source_ref="fixture://http-service",
            verification_status=VerificationStatus.VERIFIED,
            confidence=0.8,
            freshness=0.9,
            metadata={
                "kind": "tcp_service_discovery",
                "open_services": [{"port": 80, "service": "http", "product": "nginx"}],
            },
        )
        self.runtime.store.insert_evidence(service_evidence)
        review_evidence = EvidenceRecord(
            target_id=self.target.id,
            type=EvidenceType.MODEL_REVIEW,
            title="Premium planner review",
            summary="Remote premium review returned structured planner recommendations.",
            source_ref="fixture://premium-review",
            verification_status=VerificationStatus.PARTIAL,
            confidence=0.7,
            freshness=0.9,
            metadata={
                "kind": "premium_review_result",
                "review": {
                    "recommended_next_actions": [
                        {
                            "title": "Run bounded web content discovery from remote review",
                            "primitive_hint": "content-discovery",
                            "evidence_refs": [service_evidence.id],
                            "confidence": 0.7,
                        },
                        {"title": "Missing refs", "primitive_hint": "dns-enumeration"},
                        {
                            "title": "Scope drift",
                            "primitive_hint": "content-discovery",
                            "target": "other.htb",
                            "evidence_refs": [service_evidence.id],
                        },
                        {
                            "title": "Approve credential use",
                            "primitive_hint": "credentialed-access-check",
                            "evidence_refs": [service_evidence.id],
                            "credential_use_approved": True,
                        },
                    ],
                    "missing_evidence": [],
                    "invalid_existing_tasks": [],
                    "primitive_gaps": [],
                    "confidence": 0.72,
                    "rationale_with_evidence_refs": [],
                },
            },
        )
        self.runtime.store.insert_evidence(review_evidence)

        state = self.runtime.workflow.preview_target_state(self.target)
        admission = state.metadata["remote_review_admission"]

        self.assertTrue(any(item["title"].startswith("Run bounded web content") for item in admission["accepted"]))
        reasons = " ".join(item["reason"] for item in admission["rejected"])
        self.assertIn("no evidence refs", reasons)
        self.assertIn("different scope", reasons)
        self.assertIn("attempted to approve", reasons)


if __name__ == "__main__":
    unittest.main()
