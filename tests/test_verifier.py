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
        target = self._target()

        signals = verifier.inspect(
            tasks=self._failed_tasks(target.id),
            traces=self._repeated_traces(),
            evidence=self._mixed_generation_evidence(target.id),
            targets=[target],
            interests=self._unsupported_interests(target.id),
            findings=self._unsupported_findings(target.id),
            events=self._no_progress_events(target.id),
        )

        codes = {signal.code for signal in signals}
        self.assertIn("stale_generation_contamination", codes)
        self.assertIn("blocked_next_action_loop", codes)
        self.assertIn("unsupported_claim_promotion", codes)
        self.assertIn("confidence_without_evidence_growth", codes)

    def _target(self) -> Target:
        return Target(
            handle="pirate.htb",
            display_name="Pirate",
            profile=ScopeProfile.HACK_THE_BOX,
            metadata={"active_ip_generation": 2},
        )

    def _failed_tasks(self, target_id: str) -> list[Task]:
        return [
            Task(
                target_id=target_id,
                phase=MethodologyPhase.ANALYSIS,
                kind=TaskKind.ANALYZE_EVIDENCE,
                title="Analyze evidence",
                summary="Analysis",
                role=AgentRole.ANALYSIS_WORKER,
                status=TaskStatus.FAILED,
                attempts=2,
            )
        ]

    def _repeated_traces(self) -> list[AgentTrace]:
        return [
            AgentTrace(
                task_id=f"task-{index}",
                role=AgentRole.ANALYSIS_WORKER,
                status="completed",
                summary="Repeated trace",
                metadata={"summary_key": "analyze_evidence"},
            )
            for index in range(1, 4)
        ]

    def _mixed_generation_evidence(self, target_id: str) -> list[EvidenceRecord]:
        return [
            self._service_evidence(target_id, title="Current service discovery", source_ref="fixture://1", generation=2),
            self._service_evidence(target_id, title="Old service discovery", source_ref="fixture://2", generation=1),
        ]

    def _service_evidence(self, target_id: str, *, title: str, source_ref: str, generation: int) -> EvidenceRecord:
        return EvidenceRecord(
            target_id=target_id,
            type=EvidenceType.TOOL_OUTPUT,
            title=title,
            summary="Current generation" if generation == 2 else "Old generation",
            source_ref=source_ref,
            verification_status=VerificationStatus.VERIFIED,
            confidence=0.8,
            freshness=0.9,
            metadata={"kind": "tcp_service_discovery", "active_ip_generation": generation},
        )

    def _unsupported_findings(self, target_id: str) -> list[Finding]:
        return [
            Finding(
                target_id=target_id,
                title="Unsupported verified finding",
                summary="No evidence refs attached",
                severity=FindingSeverity.HIGH,
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.9,
            )
        ]

    def _unsupported_interests(self, target_id: str) -> list[Interest]:
        return [
            Interest(
                target_id=target_id,
                title="Inflated interest",
                summary="High confidence without evidence",
                status=InterestStatus.VERIFIED,
                confidence=0.9,
            )
        ]

    def _no_progress_events(self, target_id: str) -> list[EventRecord]:
        return [
            EventRecord(type=EventType.NO_PROGRESS, summary="waiting on credentials", target_id=target_id),
            EventRecord(type=EventType.NO_PROGRESS, summary="waiting on credentials", target_id=target_id),
            EventRecord(type=EventType.NO_PROGRESS, summary="waiting on credentials", target_id=target_id),
        ]


if __name__ == "__main__":
    unittest.main()
