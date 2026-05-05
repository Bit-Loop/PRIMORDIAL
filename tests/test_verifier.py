from __future__ import annotations

import unittest

from primordial.core.domain.enums import (
    AgentRole,
    EventType,
    EvidenceType,
    FindingSeverity,
    InterestStatus,
    MethodologyPhase,
    ScopeProfile,
    TaskKind,
    TaskStatus,
    VerificationStatus,
)
from primordial.core.domain.models import AgentTrace, EventRecord, EvidenceRecord, Finding, Interest, Target, Task
from primordial.core.orchestration.verifier import BehaviorVerifier


class BehaviorVerifierTests(unittest.TestCase):
    def test_verifier_detects_generation_loops_no_progress_and_unsupported_claims(self) -> None:
        verifier = BehaviorVerifier()
        target = Target(
            handle="pirate.htb",
            display_name="Pirate",
            profile=ScopeProfile.HACK_THE_BOX,
            metadata={"active_ip_generation": 2},
        )
        tasks = [
            Task(
                target_id=target.id,
                phase=MethodologyPhase.ANALYSIS,
                kind=TaskKind.ANALYZE_EVIDENCE,
                title="Analyze evidence",
                summary="Analysis",
                role=AgentRole.ANALYSIS_WORKER,
                status=TaskStatus.FAILED,
                attempts=2,
            )
        ]
        traces = [
            AgentTrace(task_id="task-1", role=AgentRole.ANALYSIS_WORKER, status="completed", summary="Repeated trace", metadata={"summary_key": "analyze_evidence"}),
            AgentTrace(task_id="task-2", role=AgentRole.ANALYSIS_WORKER, status="completed", summary="Repeated trace", metadata={"summary_key": "analyze_evidence"}),
            AgentTrace(task_id="task-3", role=AgentRole.ANALYSIS_WORKER, status="completed", summary="Repeated trace", metadata={"summary_key": "analyze_evidence"}),
        ]
        evidence = [
            EvidenceRecord(
                target_id=target.id,
                type=EvidenceType.TOOL_OUTPUT,
                title="Current service discovery",
                summary="Current generation",
                source_ref="fixture://1",
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.8,
                freshness=0.9,
                metadata={"kind": "tcp_service_discovery", "active_ip_generation": 2},
            ),
            EvidenceRecord(
                target_id=target.id,
                type=EvidenceType.TOOL_OUTPUT,
                title="Old service discovery",
                summary="Old generation",
                source_ref="fixture://2",
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.8,
                freshness=0.9,
                metadata={"kind": "tcp_service_discovery", "active_ip_generation": 1},
            ),
        ]
        findings = [
            Finding(
                target_id=target.id,
                title="Unsupported verified finding",
                summary="No evidence refs attached",
                severity=FindingSeverity.HIGH,
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.9,
            )
        ]
        interests = [
            Interest(
                target_id=target.id,
                title="Inflated interest",
                summary="High confidence without evidence",
                status=InterestStatus.VERIFIED,
                confidence=0.9,
            )
        ]
        events = [
            EventRecord(type=EventType.NO_PROGRESS, summary="waiting on credentials", target_id=target.id),
            EventRecord(type=EventType.NO_PROGRESS, summary="waiting on credentials", target_id=target.id),
            EventRecord(type=EventType.NO_PROGRESS, summary="waiting on credentials", target_id=target.id),
        ]

        signals = verifier.inspect(
            tasks=tasks,
            traces=traces,
            evidence=evidence,
            targets=[target],
            interests=interests,
            findings=findings,
            events=events,
        )

        codes = {signal.code for signal in signals}
        self.assertIn("stale_generation_contamination", codes)
        self.assertIn("blocked_next_action_loop", codes)
        self.assertIn("unsupported_claim_promotion", codes)
        self.assertIn("confidence_without_evidence_growth", codes)


if __name__ == "__main__":
    unittest.main()
