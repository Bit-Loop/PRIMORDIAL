from __future__ import annotations

from primordial.modes.security.execution_common import *


class PrimitiveAnalysisHandlerMixin:
    def _handle_analyze_evidence(self, task: Task, context: ContextSlice) -> TaskExecutionResult:
        result = TaskExecutionResult(summary="analysis completed")
        target = self.store.get_target(task.target_id)
        if not target:
            result.success = False
            result.error = "target not found"
            return result

        analysis = self._analysis_inputs(task, target)
        result.notes.append(self._analysis_note(task, target, analysis))
        ai_review = self._run_ai_review(
            task,
            target_id=target.id,
            title="AI strategy review",
            snapshot=self._build_ai_target_snapshot(target.id),
            instruction=(
                "Act as a bounded autonomous security-analysis worker. Identify the most useful next "
                "primitive-backed actions, explain what is blocked, and propose concrete safe follow-up "
                "tasks. Do not claim a vulnerability or flag unless evidence proves it. Do not recommend "
                "DoS, flooding, password spraying, or unbounded brute force. Prefer version-specific "
                "triage, credential/scope prerequisites, and exact missing primitives."
            ),
        )
        self._apply_ai_review(result, task, ai_review)
        if analysis["auth_refs"]:
            result.interests.append(
                Interest(
                    target_id=target.id,
                    title="Auth-adjacent surface review backlog",
                    summary="Auth-adjacent routes or forms were observed. Manual or future primitive-backed verification is required before any exploit claim.",
                    evidence_refs=analysis["auth_refs"],
                    status=InterestStatus.OPEN,
                    confidence=0.76,
                    metadata={"rank": 1, "phase": task.phase.value},
                )
            )
        return result

    def _analysis_inputs(self, task: Task, target) -> dict[str, object]:
        raw = self._task_generation_records(task, target, self.store.list_evidence(target_id=target.id, limit=25))
        evidence = raw[:24]
        return {
            "evidence": evidence,
            "evidence_overflow": len(raw) > 24,
            "auth_refs": self._analysis_auth_refs(evidence),
            "observed_paths": self._analysis_observed_values(evidence, "paths"),
            "observed_parameters": self._analysis_observed_values(evidence, "parameters"),
        }

    def _analysis_auth_refs(self, evidence: list[EvidenceRecord]) -> list[str]:
        return [
            item.id
            for item in evidence
            if self._extract_auth_surfaces(
                list(item.metadata.get("paths", []))
                + list(item.metadata.get("auth_surfaces", []))
                + list(item.metadata.get("forms", []))
            )
        ]

    def _analysis_observed_values(self, evidence: list[EvidenceRecord], key: str) -> list[str]:
        return sorted(
            {
                value
                for item in evidence
                for value in item.metadata.get(key, [])
                if isinstance(value, str) and value
            }
        )

    def _analysis_note(self, task: Task, target, analysis: dict[str, object]) -> Note:
        observed_paths = list(analysis["observed_paths"])
        observed_parameters = list(analysis["observed_parameters"])
        body = self._build_analysis_summary(observed_paths, observed_parameters, len(analysis["auth_refs"]))
        if analysis["evidence_overflow"]:
            body += " [Warning: evidence truncated to 24 items; older records excluded from this analysis.]"
        return Note(
            target_id=target.id,
            task_id=task.id,
            title="Evidence analysis summary",
            body=body,
            confidence=0.78,
            freshness=0.9,
            metadata={
                "evidence_count": len(analysis["evidence"]),
                "evidence_truncated": analysis["evidence_overflow"],
                "observed_paths": observed_paths[:self.config.max_evidence_items],
                "observed_parameters": observed_parameters[:self.config.max_evidence_items],
            },
        )
