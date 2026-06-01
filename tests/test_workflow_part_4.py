from __future__ import annotations

from tests.test_workflow_common import *


class WorkflowTestsPart4(WorkflowTestsBase):
    def test_windows_credentialed_access_requires_intent_and_windows_surface_evidence(self) -> None:
        self.runtime.set_operator_intent("recon_only")
        self.runtime.set_known_credentials(username=fixture_secret("anne"), password=fixture_secret("secret"), domain="PIRATE")
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

    def test_stuck_planner_routes_claude_gpt_through_local_chat_wrapper_without_remote_gate(self) -> None:
        self.runtime.set_operator_intent("recon_only")
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
        self.assertEqual(review_tasks[0].metadata["local_chat_wrapper"], "agent_chat_api")
        self.assertTrue(review_tasks[0].metadata["remote_premium_local_wrapper"])
        self.assertNotIn("remote_premium_policy_approval_required", review_tasks[0].metadata)
        self.assertNotIn("operator_approved", review_tasks[0].metadata)
        packet = review_tasks[0].metadata["escalation_package"]["metadata"]["packet"]
        self.assertEqual(packet["operator_intent"], "recon_only")
        self.assertEqual(packet["required_output"]["recommended_next_actions"], "array<object>")

    def test_failed_planner_escalation_is_visible_in_methodology_state(self) -> None:
        self.runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=self.target.id,
                type=EvidenceType.OPERATOR_NOTE,
                title="Manual evidence note",
                summary="Evidence exists but the planner escalation failed.",
                source_ref="fixture://manual-note",
                verification_status=VerificationStatus.PARTIAL,
                confidence=0.6,
                freshness=0.8,
            )
        )
        failed = Task(
            target_id=self.target.id,
            phase=MethodologyPhase.ANALYSIS,
            kind=TaskKind.REVIEW_PREMIUM_ESCALATION,
            title="Escalate uncertain planner state to Claude/GPT",
            summary="Ask wrapper for next bounded task.",
            role=AgentRole.ANALYSIS_WORKER,
            status=TaskStatus.FAILED,
            metadata={"last_error": "agent chat API is unreachable"},
        )
        self.runtime.store.insert_task(failed)

        state = self.runtime.workflow.preview_target_state(self.target)

        self.assertTrue(
            any("Planner uncertainty escalation failed: agent chat API is unreachable" == blocker for blocker in state.blockers)
        )
        self.assertEqual(
            state.metadata["planner_escalation_status"]["latest_failed"]["task_id"],
            failed.id,
        )

    def test_notion_auth_failure_blocks_retry_until_credentials_change(self) -> None:
        self.runtime.set_notion_credentials(api_key="bad-token", parent_page_id="notion-page", version="2022-06-28")
        job = ExternalSyncJob(
            kind=ExternalSyncKind.NOTION,
            target_id=self.target.id,
            summary="Sync target to Notion",
            payload={"target_id": self.target.id},
            status=ExternalSyncStatus.PENDING,
        )
        self.runtime.store.insert_external_sync_job(job)
        http_error = error.HTTPError(
            "https://api.notion.com/v1/pages",
            401,
            "Unauthorized",
            {},
            io.BytesIO(b'{"message":"invalid token"}'),
        )

        with patch("primordial.adapters.notion.request.urlopen", side_effect=http_error) as mocked_urlopen:
            completed = self.runtime.notion.process_pending(limit=1)

        self.assertEqual(completed, 0)
        self.assertEqual(mocked_urlopen.call_count, 1)
        status = self.runtime.credentials_payload()
        self.assertTrue(status["services"]["notion"]["service_status"]["auth_blocked"])
        refreshed = next(item for item in self.runtime.store.list_external_sync_jobs(limit=20) if item.id == job.id)
        self.assertEqual(refreshed.status, ExternalSyncStatus.FAILED)
        self.assertTrue(refreshed.metadata["auth_blocked"])

        retry_job = ExternalSyncJob(
            kind=ExternalSyncKind.NOTION,
            target_id=self.target.id,
            summary="Retry target to Notion",
            payload={"target_id": self.target.id},
            status=ExternalSyncStatus.PENDING,
        )
        self.runtime.store.insert_external_sync_job(retry_job)
        with patch("primordial.adapters.notion.request.urlopen") as mocked_retry:
            self.assertEqual(self.runtime.notion.process_pending(limit=1), 0)

        mocked_retry.assert_not_called()
        suppressed = next(item for item in self.runtime.store.list_external_sync_jobs(limit=20) if item.id == retry_job.id)
        self.assertEqual(suppressed.status, ExternalSyncStatus.FAILED)
        self.assertTrue(suppressed.metadata["auth_blocked"])

        self.runtime.set_notion_credentials(api_key="bad-token", parent_page_id="notion-page", version="2022-06-28")
        self.assertNotIn("service_status", self.runtime.credentials_payload()["services"]["notion"])

    def test_execution_escalation_package_uses_local_chat_wrapper_when_remote_flag_is_disabled(self) -> None:
        evidence = self._manual_escalation_evidence()
        self.runtime.store.insert_evidence(evidence)
        task = self._analysis_task()
        run = self._analysis_run(task)
        self.runtime.store.insert_task(task)
        self.runtime.store.insert_task_run(run)
        result = self._escalation_result(task, evidence)
        report = OrchestrationReport()

        self.runtime.workflow._persist_execution_result(task, run, result, report)
        review_tasks = [
            item
            for item in self.runtime.store.list_tasks(target_id=self.target.id, limit=10)
            if item.kind == TaskKind.REVIEW_PREMIUM_ESCALATION
        ]

        self.assertEqual(len(review_tasks), 1)
        self.assertEqual(review_tasks[0].status, TaskStatus.PENDING)
        self.assertEqual(review_tasks[0].metadata["local_chat_wrapper"], "agent_chat_api")
        self.assertTrue(review_tasks[0].metadata["remote_premium_local_wrapper"])
        self.assertNotIn("remote_premium_policy_approval_required", review_tasks[0].metadata)

    def _manual_escalation_evidence(self) -> EvidenceRecord:
        return EvidenceRecord(
            target_id=self.target.id,
            type=EvidenceType.OPERATOR_NOTE,
            title="Manual evidence note",
            summary="Operator supplied live evidence for escalation.",
            source_ref="fixture://manual-note",
            verification_status=VerificationStatus.PARTIAL,
            confidence=0.6,
            freshness=0.8,
        )

    def _analysis_task(self) -> Task:
        return Task(
            target_id=self.target.id,
            phase=MethodologyPhase.ANALYSIS,
            kind=TaskKind.ANALYZE_EVIDENCE,
            title="Analyze accumulated evidence",
            summary="Generate escalation package.",
            role=AgentRole.ANALYSIS_WORKER,
            provider_route=ProviderRoute.LOCAL_DEEP,
            provider_model="fixture-model",
        )

    def _analysis_run(self, task: Task) -> TaskRun:
        return TaskRun(
            task_id=task.id,
            status=TaskRunStatus.RUNNING,
            attempt_number=1,
            role=task.role,
            provider_route=ProviderRoute.LOCAL_DEEP,
            model_name="fixture-model",
        )

    def _escalation_result(self, task: Task, evidence: EvidenceRecord) -> TaskExecutionResult:
        return TaskExecutionResult(
            success=True,
            summary="analysis complete",
            escalation_package=EscalationPackage(
                task_id=task.id,
                target_id=self.target.id,
                mode="planner_uncertainty_review",
                reason="Need local-wrapper Claude/GPT review",
                expected_value="Resolve planner uncertainty",
                cost_tier="remote_premium",
                question="What safe next action is valid?",
                evidence_refs=[evidence.id],
                evidence_summaries=[f"{evidence.id}: {evidence.title}"],
                disagreement_signal="planner_uncertainty",
                expected_output_type="planner_remote_review_v1",
                metadata={"packet": self._escalation_packet()},
            ),
        )

    def _escalation_packet(self) -> dict[str, object]:
        return {
            "handoff_type": "planner_uncertainty_review",
            "required_output": {
                "recommended_next_actions": "array<object>",
                "missing_evidence": "array<string>",
                "invalid_existing_tasks": "array<object>",
                "primitive_gaps": "array<string>",
                "confidence": "number",
                "rationale_with_evidence_refs": "array<object>",
            },
            "authority_limits": [
                "Remote review cannot approve credential use.",
                "Remote review cannot expand target scope.",
                "Remote review cannot execute tools.",
                "Remote review cannot override Operator Intent or deterministic policy.",
            ],
        }

__all__ = ["WorkflowTestsPart4"]
