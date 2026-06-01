from __future__ import annotations

from tests.test_workflow_common import *


class WorkflowTestsPart2(WorkflowTestsBase):
    def test_admitted_safe_ai_proposals_materialize_into_tasks(self) -> None:
        evidence = EvidenceRecord(
            target_id=self.target.id,
            type=EvidenceType.OPERATOR_NOTE,
            title="Current evidence note",
            summary="Manual current-generation evidence for planner proposal materialization.",
            source_ref="fixture://operator-note",
            verification_status=VerificationStatus.PARTIAL,
            confidence=0.6,
            freshness=0.8,
            metadata={"kind": "operator_note"},
        )
        self.runtime.store.insert_evidence(evidence)
        signature = self.runtime.workflow._target_analysis_signature(self.target)
        analysis = Task(
            target_id=self.target.id,
            phase=MethodologyPhase.ANALYSIS,
            kind=TaskKind.ANALYZE_EVIDENCE,
            title="Analyze accumulated evidence",
            summary="Already analyzed with admitted primitive proposals.",
            role=AgentRole.ANALYSIS_WORKER,
            risk_tier=RiskTier.LOW,
            status=TaskStatus.SUCCEEDED,
            metadata={
                "analysis_signature": signature,
                "ai_proposal": {
                    "candidate_actions": [
                        {"title": "Capture HTTP headers", "primitive_hint": "http_header_analysis"},
                        {"title": "Run web vulnerability scan", "primitive_hint": "web_vulnerability_scan"},
                    ],
                },
            },
        )
        self.runtime.store.insert_task(analysis)

        report = self.runtime.run_tick(max_executions=0)
        materialized = [
            task for task in report.created_tasks if task.metadata.get("ai_proposal_materialized")
        ]

        self.assertEqual(len(materialized), 1)
        self.assertEqual(materialized[0].kind, TaskKind.RECON_SCAN)
        self.assertEqual(materialized[0].metadata["primitive_hint"], "http-probe")
        self.assertEqual(materialized[0].metadata["raw_primitive_hint"], "http_header_analysis")
        self.assertFalse(
            any(task.metadata.get("primitive_hint") == "web-vulnerability-scan" for task in report.created_tasks)
        )

    def test_analysis_signature_ignores_task_churn(self) -> None:
        evidence = EvidenceRecord(
            target_id=self.target.id,
            type=EvidenceType.OPERATOR_NOTE,
            title="Stable evidence",
            summary="Evidence set should drive analysis freshness.",
            source_ref="fixture://stable-evidence",
            verification_status=VerificationStatus.PARTIAL,
            confidence=0.6,
            freshness=0.8,
        )
        self.runtime.store.insert_evidence(evidence)
        before = self.runtime.workflow._target_analysis_signature(self.target)
        task = Task(
            target_id=self.target.id,
            phase=MethodologyPhase.RECON,
            kind=TaskKind.SERVICE_DISCOVERY,
            title="Failed service task",
            summary="Task churn fixture.",
            role=AgentRole.RECON_WORKER,
            risk_tier=RiskTier.LOW,
            status=TaskStatus.FAILED,
        )
        self.runtime.store.insert_task(task)

        after = self.runtime.workflow._target_analysis_signature(self.target)

        self.assertEqual(before, after)

    def test_verify_hypothesis_writes_bounded_verification_result(self) -> None:
        evidence = EvidenceRecord(
            target_id=self.target.id,
            type=EvidenceType.TOOL_OUTPUT,
            title="Verified service evidence",
            summary="Deterministic fixture evidence.",
            source_ref="fixture://verified-service",
            verification_status=VerificationStatus.VERIFIED,
            confidence=0.86,
            freshness=0.9,
        )
        self.runtime.store.insert_evidence(evidence)
        interest = Interest(
            target_id=self.target.id,
            title="Evidence-backed hypothesis",
            summary="The hypothesis is backed by verified current evidence.",
            evidence_refs=[evidence.id],
            status=InterestStatus.VERIFIED,
            confidence=0.88,
        )
        self.runtime.store.insert_interest(interest)
        task = Task(
            target_id=self.target.id,
            phase=MethodologyPhase.EXPLOITATION,
            kind=TaskKind.VERIFY_HYPOTHESIS,
            title="Verify prioritized hypothesis",
            summary="Run deterministic bounded verification.",
            role=AgentRole.EXPLOITATION_WORKER,
            risk_tier=RiskTier.HIGH,
            required_capabilities=["finding-verification"],
            metadata={"primitive_hint": "finding-verification"},
        )

        result = self.runtime.executor.execute(task, None)

        self.assertTrue(result.success)
        self.assertEqual(result.evidence[0].verification_status, VerificationStatus.VERIFIED)
        self.assertIn(evidence.id, result.evidence[0].metadata["source_evidence_refs"])
        self.assertEqual(result.findings[0].verification_status, VerificationStatus.VERIFIED)
        self.assertFalse(result.findings[0].metadata["executes_pocs"])

    def test_chain_candidates_respects_max_chaining_fanout(self) -> None:
        self.runtime.config.autonomy.max_chaining_fanout = 2
        for index in range(4):
            self.runtime.store.insert_interest(
                Interest(
                    target_id=self.target.id,
                    title=f"Verified interest {index}",
                    summary="Chain review fixture.",
                    status=InterestStatus.VERIFIED,
                    confidence=0.9 - (index * 0.01),
                )
            )
        task = Task(
            target_id=self.target.id,
            phase=MethodologyPhase.CHAINING,
            kind=TaskKind.CHAIN_CANDIDATES,
            title="Review exploit-chain candidates",
            summary="Review bounded chain inputs.",
            role=AgentRole.CHAINING_WORKER,
            risk_tier=RiskTier.HIGH,
        )

        with patch.object(self.runtime.executor, "_run_ai_review", return_value=None):
            result = self.runtime.executor.execute(task, None)

        self.assertTrue(result.success)
        self.assertEqual(result.notes[0].metadata["verified_interest_count"], 4)
        self.assertEqual(result.notes[0].metadata["reviewed_interest_count"], 2)
        self.assertTrue(result.notes[0].metadata["truncated"])

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
            assets=[{"asset": ACTIVE_IP, "asset_type": "ip"}],
            emit_event=False,
        )
        self.runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=self.target.id,
                type=EvidenceType.TOOL_OUTPUT,
                title="Old TCP service discovery",
                summary="Observed services on " + ACTIVE_IP + ".",
                source_ref="fixture://old-service",
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.8,
                freshness=0.9,
                metadata={
                    "kind": "tcp_service_discovery",
                    "open_services": [{"host": ACTIVE_IP, "port": 445, "service": "smb"}],
                },
            )
        )

        self.runtime.ask_operator_ai("You should be using " + CORRECTED_IP, target="pirate.htb")
        report = self.runtime.run_tick(max_executions=0)

        self.assertTrue(any(task.kind == TaskKind.SERVICE_DISCOVERY for task in report.created_tasks))
        service_task = next(task for task in report.created_tasks if task.kind == TaskKind.SERVICE_DISCOVERY)
        self.assertEqual(service_task.metadata["active_ip"], CORRECTED_IP)
        self.assertEqual(str(service_task.metadata["active_ip_generation"]), "1")

__all__ = ["WorkflowTestsPart2"]
