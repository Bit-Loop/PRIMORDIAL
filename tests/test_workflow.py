from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from primordial.config import AppConfig
from primordial.runtime import PrimordialRuntime
from primordial.core.domain.enums import (
    AgentRole,
    EvidenceType,
    InterestStatus,
    MethodologyPhase,
    RiskTier,
    ScopeProfile,
    TaskKind,
    TaskStatus,
    VerificationStatus,
)
from primordial.core.domain.models import EvidenceRecord, Interest, Task, utc_now
from primordial.core.domain.models import OrchestrationReport
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


if __name__ == "__main__":
    unittest.main()
