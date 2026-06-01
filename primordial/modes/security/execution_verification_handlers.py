from __future__ import annotations

from primordial.modes.security.execution_common import *


class PrimitiveVerificationHandlerMixin:
    def _handle_verify_hypothesis(self, task: Task, context: ContextSlice) -> TaskExecutionResult:
        result = TaskExecutionResult(summary="verification deferred")
        target = self.store.get_target(task.target_id)
        if not target:
            result.success = False
            result.error = "target not found"
            return result

        primitives = self.resolve_primitives(task)
        has_verification_adapter = any(
            primitive.name == "finding-verification" or "finding-verification" in primitive.capability_tags
            for primitive in primitives
        )
        interests = self._task_generation_records(task, target, self.store.list_interests(target_id=target.id, limit=20))
        if has_verification_adapter:
            return self._run_bounded_finding_verification(task, target, interests)

        result.summary = "verification planning complete; execution remains primitive-gated"
        result.notes.append(
            Note(
                target_id=target.id,
                task_id=task.id,
                title="Verification status",
                body=(
                    "No production verification primitive is registered for automatic claim validation yet. "
                    "The target remains in recon/analysis state until a real bounded verification adapter is implemented."
                ),
                confidence=0.9,
                freshness=0.9,
                metadata={"interest_count": len(interests), "deferred": True},
            )
        )
        ai_review = self._run_ai_review(
            task,
            target_id=target.id,
            title="AI verification plan",
            snapshot=self._build_ai_target_snapshot(target.id),
            instruction=(
                "Produce a safe bounded verification plan for the strongest current hypothesis. "
                "List prerequisites, exact evidence references to use, production primitives needed, "
                "and stop conditions. Do not write exploit code here and do not mark anything verified."
            ),
        )
        self._apply_ai_review(result, task, ai_review)
        return result

    def _run_bounded_finding_verification(self, task: Task, target, interests: list[Interest]) -> TaskExecutionResult:
        verified_interests = sorted(
            [item for item in interests if item.status == InterestStatus.VERIFIED],
            key=lambda item: item.confidence,
            reverse=True,
        )
        evidence = self._task_generation_records(task, target, self.store.list_evidence(target_id=target.id, limit=200))
        evidence_by_id = {item.id: item for item in evidence}
        verified_evidence_ids = {item.id for item in evidence if item.verification_status == VerificationStatus.VERIFIED}
        result = TaskExecutionResult(summary="bounded verification complete")
        if not verified_interests:
            return self._verification_rejected_result(
                task,
                target,
                result,
                summary="bounded verification rejected; no verified interest is available",
                evidence_summary="No current-generation verified interest was available for deterministic verification.",
                evidence_refs=[],
                metadata={"reason": "no_verified_interest"},
            )

        selected = verified_interests[0]
        selected_refs = [ref for ref in selected.evidence_refs if ref in evidence_by_id]
        verified_refs = [ref for ref in selected_refs if ref in verified_evidence_ids]
        if not verified_refs:
            return self._verification_rejected_result(
                task,
                target,
                result,
                summary="bounded verification rejected; verified interest lacks verified evidence",
                evidence_summary=(
                    f"Interest '{selected.title}' is marked verified, but none of its evidence references "
                    "are current-generation verified evidence."
                ),
                evidence_refs=selected_refs,
                metadata={"reason": "missing_verified_evidence", "interest_id": selected.id},
            )
        return self._verification_accepted_result(task, target, result, selected, selected_refs, verified_refs)

    def _verification_rejected_result(
        self,
        task: Task,
        target,
        result: TaskExecutionResult,
        *,
        summary: str,
        evidence_summary: str,
        evidence_refs: list[str],
        metadata: dict[str, object],
    ) -> TaskExecutionResult:
        result.summary = summary
        result.evidence.append(
            self._verification_result_evidence(
                task,
                target,
                status=VerificationStatus.REJECTED,
                summary=evidence_summary,
                evidence_refs=evidence_refs,
                metadata=metadata,
            )
        )
        return result

    def _verification_accepted_result(
        self,
        task: Task,
        target,
        result: TaskExecutionResult,
        selected: Interest,
        selected_refs: list[str],
        verified_refs: list[str],
    ) -> TaskExecutionResult:
        verification_evidence = self._verification_result_evidence(
            task,
            target,
            status=VerificationStatus.VERIFIED,
            summary=(
                f"Deterministic finding-verification confirmed '{selected.title}' against "
                f"{len(verified_refs)} current-generation verified evidence record(s). No PoC was executed."
            ),
            evidence_refs=verified_refs,
            metadata={
                "interest_id": selected.id,
                "interest_title": selected.title,
                "interest_confidence": selected.confidence,
                "verified_evidence_refs": verified_refs,
                "all_interest_evidence_refs": selected_refs,
            },
        )
        result.evidence.append(verification_evidence)
        result.notes.append(self._verification_note(task, target, selected, verification_evidence))
        result.findings.append(self._verification_finding(task, target, selected, verified_refs, verification_evidence))
        result.summary = "bounded verification completed with durable evidence linkage"
        return result

    def _verification_note(self, task: Task, target, selected: Interest, verification_evidence: EvidenceRecord) -> Note:
        return Note(
            target_id=target.id,
            task_id=task.id,
            title="Bounded verification result",
            body=(
                f"Verified interest '{selected.title}' is backed by current-generation verified evidence. "
                "This adapter produced durable verification evidence only; it did not execute exploit code."
            ),
            confidence=min(0.92, max(0.7, selected.confidence)),
            freshness=0.95,
            metadata={"adapter": "finding-verification", "interest_id": selected.id, "verification_evidence_ref": verification_evidence.id},
        )

    def _verification_finding(
        self,
        task: Task,
        target,
        selected: Interest,
        verified_refs: list[str],
        verification_evidence: EvidenceRecord,
    ) -> Finding:
        return Finding(
            target_id=target.id,
            title=f"Verified hypothesis: {selected.title}",
            summary=selected.summary,
            severity=FindingSeverity.MEDIUM,
            evidence_refs=[*verified_refs, verification_evidence.id],
            confidence=min(0.9, max(0.7, selected.confidence)),
            verification_status=VerificationStatus.VERIFIED,
            metadata={
                "source": task.kind.value,
                "adapter": "finding-verification",
                "auto_generated": True,
                "executes_pocs": False,
                "interest_id": selected.id,
                "verification_evidence_ref": verification_evidence.id,
            },
        )

    def _verification_result_evidence(
        self,
        task: Task,
        target,
        *,
        status: VerificationStatus,
        summary: str,
        evidence_refs: list[str],
        metadata: dict[str, object],
    ) -> EvidenceRecord:
        return EvidenceRecord(
            target_id=target.id,
            task_id=task.id,
            type=EvidenceType.TOOL_OUTPUT,
            title="Bounded finding verification result",
            summary=summary,
            source_ref=f"primitive://finding-verification/{task.id}",
            verification_status=status,
            confidence=0.9 if status == VerificationStatus.VERIFIED else 0.65,
            freshness=0.95,
            metadata={
                "kind": "bounded_verification_result",
                "adapter": "finding-verification",
                "executes_pocs": False,
                "source_evidence_refs": evidence_refs,
                **metadata,
            },
        )
