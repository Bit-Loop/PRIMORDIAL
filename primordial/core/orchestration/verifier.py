from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from primordial.core.domain.enums import TaskKind, TaskStatus
from primordial.core.domain.models import AgentTrace, EvidenceRecord, Task


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
    ) -> list[VerifierSignal]:
        signals: list[VerifierSignal] = []
        traces = traces or []
        evidence = evidence or []

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
        return signals
