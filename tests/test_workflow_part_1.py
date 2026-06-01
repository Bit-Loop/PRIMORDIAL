from __future__ import annotations

from tests.test_workflow_common import *


class WorkflowTestsPart1(WorkflowTestsBase):
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
                assets=[INVALID_IP],
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

    def test_primitive_hint_aliases_narrow_validation_and_execution_primitives(self) -> None:
        task = Task(
            target_id=self.target.id,
            phase=MethodologyPhase.RECON,
            kind=TaskKind.WEB_CONTENT_DISCOVERY,
            title="Discover web paths",
            summary="Use the canonical content discovery primitive for planner aliases.",
            role=AgentRole.RECON_WORKER,
            risk_tier=RiskTier.MODERATE,
            required_capabilities=["content-discovery", "path-enumeration"],
            metadata={"primitive_hint": "web_content_discovery"},
        )

        validation_primitives = self.runtime.workflow._stored_primitives_for_task(task)
        execution_primitives = self.runtime.security.primitive_executor.resolve_primitives(task)

        self.assertEqual([primitive.name for primitive in validation_primitives], ["content-discovery"])
        self.assertEqual([primitive.name for primitive in execution_primitives], ["content-discovery"])

    def test_primitive_capability_hint_resolves_matching_manifest(self) -> None:
        task = Task(
            target_id=self.target.id,
            phase=MethodologyPhase.RECON,
            kind=TaskKind.SERVICE_DISCOVERY,
            title="Fingerprint services",
            summary="Use capability hints to select the backing manifest.",
            role=AgentRole.RECON_WORKER,
            risk_tier=RiskTier.LOW,
            required_capabilities=[],
            metadata={"primitive_hint": "service-identification"},
        )

        validation_primitives = self.runtime.workflow._stored_primitives_for_task(task)
        execution_primitives = self.runtime.security.primitive_executor.resolve_primitives(task)

        self.assertEqual([primitive.name for primitive in validation_primitives], ["tcp-service-discovery"])
        self.assertEqual([primitive.name for primitive in execution_primitives], ["tcp-service-discovery"])

    def test_ai_proposal_admission_canonicalizes_primitive_aliases(self) -> None:
        task = Task(
            target_id=self.target.id,
            phase=MethodologyPhase.ANALYSIS,
            kind=TaskKind.ANALYZE_EVIDENCE,
            title="Analyze stalled planner evidence",
            summary="Structured AI proposal with common primitive aliases.",
            role=AgentRole.ANALYSIS_WORKER,
            risk_tier=RiskTier.LOW,
            metadata={
                "ai_proposal": {
                    "candidate_actions": [
                        {"title": "Run content discovery", "primitive_hint": "web_content_discovery"},
                        {"title": "Capture HTTP headers", "primitive_hint": "http_header_analysis"},
                        {"title": "Fingerprint services", "primitive_hint": "service_version_fingerprinting"},
                        {"title": "Run web vulnerability scan", "primitive_hint": "web_vulnerability_scan"},
                    ],
                }
            },
        )

        admission = self.runtime.workflow._evaluate_ai_proposal_admission([task])
        accepted = {item["title"]: item for item in admission["accepted"]}
        rejected = {item["title"]: item for item in admission["rejected"]}

        self.assertEqual(accepted["Run content discovery"]["primitive_hint"], "content-discovery")
        self.assertEqual(accepted["Run content discovery"]["raw_primitive_hint"], "web_content_discovery")
        self.assertEqual(accepted["Capture HTTP headers"]["primitive_hint"], "http-probe")
        self.assertEqual(accepted["Fingerprint services"]["primitive_hint"], "tcp-service-discovery")
        self.assertEqual(rejected["Run web vulnerability scan"]["primitive_hint"], "web-vulnerability-scan")
        self.assertEqual(rejected["Run web vulnerability scan"]["reason"], "missing primitive mapping")

__all__ = ["WorkflowTestsPart1"]
