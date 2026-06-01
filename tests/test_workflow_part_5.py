from __future__ import annotations

from tests.test_workflow_common import *


class WorkflowTestsPart5(WorkflowTestsBase):
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
                            "primitive_hint": "web_directory_enumeration",
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
                        {
                            "title": "Unsafe unmapped scan",
                            "primitive_hint": "web_vulnerability_scan",
                            "evidence_refs": [service_evidence.id],
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
        accepted = next(item for item in admission["accepted"] if item["title"].startswith("Run bounded web content"))
        self.assertEqual(accepted["primitive_hint"], "content-discovery")
        reasons = " ".join(item["reason"] for item in admission["rejected"])
        self.assertIn("no evidence refs", reasons)
        self.assertIn("different scope", reasons)
        self.assertIn("attempted to approve", reasons)
        self.assertIn("missing primitive mapping", reasons)

__all__ = ["WorkflowTestsPart5"]
