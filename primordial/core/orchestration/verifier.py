from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass

from primordial.core.domain.enums import EventType, TaskKind, TaskStatus, VerificationStatus
from primordial.core.domain.models import AgentTrace, EvidenceRecord, EventRecord, Finding, Interest, Target, Task


@dataclass(slots=True, frozen=True)
class VerifierSignal:
    code: str
    score: int
    reason: str
    target_id: str | None = None


class BehaviorVerifier:
    def inspect(
        self,
        tasks: list[Task],
        traces: list[AgentTrace] | None = None,
        evidence: list[EvidenceRecord] | None = None,
        *,
        targets: list[Target] | None = None,
        interests: list[Interest] | None = None,
        findings: list[Finding] | None = None,
        events: list[EventRecord] | None = None,
    ) -> list[VerifierSignal]:
        signals: list[VerifierSignal] = []
        traces = traces or []
        evidence = evidence or []
        targets = targets or []
        interests = interests or []
        findings = findings or []
        events = events or []

        duplicates = Counter(
            (task.target_id, task.kind.value, task.status.value)
            for task in tasks
            if task.kind != TaskKind.VERIFY_AGENT_BEHAVIOR
            and task.status in {TaskStatus.PENDING, TaskStatus.RUNNING, TaskStatus.NEEDS_APPROVAL}
        )
        for (target_id, kind, _status), count in duplicates.items():
            if count > 1:
                signals.append(
                    VerifierSignal(
                        code="duplicate_task_pattern",
                        score=2,
                        reason=f"duplicate active task pattern for kind={kind}",
                        target_id=target_id,
                    )
                )

        failure_counts = Counter(
            task.target_id
            for task in tasks
            if task.kind != TaskKind.VERIFY_AGENT_BEHAVIOR
            and (task.status == TaskStatus.FAILED or task.attempts >= task.max_attempts)
        )
        for target_id, count in failure_counts.items():
            if count >= 2:
                signals.append(
                    VerifierSignal(
                        code="repeated_failure_loop",
                        score=3,
                        reason="multiple tasks failed or exhausted retries for one target",
                        target_id=target_id,
                    )
                )

        trace_counter = Counter(
            trace.metadata.get("summary_key")
            for trace in traces
            if trace.metadata.get("summary_key") and trace.metadata.get("summary_key") != TaskKind.VERIFY_AGENT_BEHAVIOR.value
        )
        for key, count in trace_counter.items():
            if count >= 3:
                signals.append(
                    VerifierSignal(
                        code="trace_repeat_loop",
                        score=2,
                        reason=f"trace pattern repeated excessively: {key}",
                    )
                )

        weak_evidence = [item for item in evidence if item.confidence < 0.45]
        if len(weak_evidence) >= 4:
            signals.append(
                VerifierSignal(
                    code="weak_evidence_accumulation",
                    score=2,
                    reason="many low-confidence evidence records are accumulating without consolidation",
                )
            )

        current_generation_by_target = {
            target.id: str(target.metadata.get("active_ip_generation", ""))
            for target in targets
            if target.metadata.get("active_ip_generation") is not None
        }
        evidence_generations: dict[str, set[str]] = defaultdict(set)
        generationless_current_targets: set[str] = set()
        for item in evidence:
            generation = str(item.metadata.get("active_ip_generation", ""))
            if item.target_id in current_generation_by_target and not generation:
                generationless_current_targets.add(item.target_id)
            if generation:
                evidence_generations[item.target_id].add(generation)
        for target_id, generations in evidence_generations.items():
            active_generation = current_generation_by_target.get(target_id)
            if active_generation and len(generations) > 1:
                signals.append(
                    VerifierSignal(
                        code="stale_generation_contamination",
                        score=3,
                        reason="multiple active-IP generations are present in evidence for one target; current reasoning may be polluted",
                        target_id=target_id,
                    )
                )
        for target_id in generationless_current_targets:
            signals.append(
                VerifierSignal(
                    code="generationless_evidence",
                    score=2,
                    reason="some evidence lacks active-IP generation metadata even though the target uses generation tracking",
                    target_id=target_id,
                )
            )

        no_progress_events = Counter(
            (event.target_id, event.summary)
            for event in events
            if event.type == EventType.NO_PROGRESS and event.target_id
        )
        for (target_id, reason), count in no_progress_events.items():
            if count >= 3:
                signals.append(
                    VerifierSignal(
                        code="blocked_next_action_loop",
                        score=3,
                        reason=f"same no-progress condition repeated for target: {reason}",
                        target_id=target_id,
                    )
                )

        verified_evidence_ids = {
            item.id
            for item in evidence
            if item.verification_status == VerificationStatus.VERIFIED
        }
        for finding in findings:
            if finding.verification_status == VerificationStatus.VERIFIED and not finding.evidence_refs:
                signals.append(
                    VerifierSignal(
                        code="unsupported_claim_promotion",
                        score=4,
                        reason="a verified finding has no evidence references",
                        target_id=finding.target_id,
                    )
                )
            if finding.confidence >= 0.8 and not any(ref in verified_evidence_ids for ref in finding.evidence_refs):
                signals.append(
                    VerifierSignal(
                        code="confidence_without_evidence_growth",
                        score=3,
                        reason="a high-confidence finding is not backed by verified evidence",
                        target_id=finding.target_id,
                    )
                )
        for interest in interests:
            if interest.status.value == "verified" and interest.confidence >= 0.85 and not any(
                ref in verified_evidence_ids for ref in interest.evidence_refs
            ):
                signals.append(
                    VerifierSignal(
                        code="confidence_without_evidence_growth",
                        score=2,
                        reason="a high-confidence verified interest is not backed by verified evidence",
                        target_id=interest.target_id,
                    )
                )

        return signals
