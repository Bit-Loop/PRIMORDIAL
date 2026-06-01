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

        _evidence_raw = self._task_generation_records(task, target, self.store.list_evidence(target_id=target.id, limit=25))
        _evidence_overflow = len(_evidence_raw) > 24
        evidence = _evidence_raw[:24]
        auth_refs = [
            item.id
            for item in evidence
            if self._extract_auth_surfaces(
                list(item.metadata.get("paths", []))
                + list(item.metadata.get("auth_surfaces", []))
                + list(item.metadata.get("forms", []))
            )
        ]
        observed_paths = sorted(
            {
                path
                for item in evidence
                for path in item.metadata.get("paths", [])
                if isinstance(path, str) and path
            }
        )
        observed_parameters = sorted(
            {
                name
                for item in evidence
                for name in item.metadata.get("parameters", [])
                if isinstance(name, str) and name
            }
        )
        _analysis_body = self._build_analysis_summary(observed_paths, observed_parameters, len(auth_refs))
        if _evidence_overflow:
            _analysis_body += " [Warning: evidence truncated to 24 items; older records excluded from this analysis.]"
        result.notes.append(
            Note(
                target_id=target.id,
                task_id=task.id,
                title="Evidence analysis summary",
                body=_analysis_body,
                confidence=0.78,
                freshness=0.9,
                metadata={
                    "evidence_count": len(evidence),
                    "evidence_truncated": _evidence_overflow,
                    "observed_paths": observed_paths[:self.config.max_evidence_items],
                    "observed_parameters": observed_parameters[:self.config.max_evidence_items],
                },
            )
        )
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
        if auth_refs:
            result.interests.append(
                Interest(
                    target_id=target.id,
                    title="Auth-adjacent surface review backlog",
                    summary="Auth-adjacent routes or forms were observed. Manual or future primitive-backed verification is required before any exploit claim.",
                    evidence_refs=auth_refs,
                    status=InterestStatus.OPEN,
                    confidence=0.76,
                    metadata={"rank": 1, "phase": task.phase.value},
                )
            )
        return result

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

    def _run_bounded_finding_verification(
        self,
        task: Task,
        target,
        interests: list[Interest],
    ) -> TaskExecutionResult:
        verified_interests = sorted(
            [item for item in interests if item.status == InterestStatus.VERIFIED],
            key=lambda item: item.confidence,
            reverse=True,
        )
        evidence = self._task_generation_records(task, target, self.store.list_evidence(target_id=target.id, limit=200))
        evidence_by_id = {item.id: item for item in evidence}
        verified_evidence_ids = {
            item.id
            for item in evidence
            if item.verification_status == VerificationStatus.VERIFIED
        }
        result = TaskExecutionResult(summary="bounded verification complete")
        if not verified_interests:
            result.summary = "bounded verification rejected; no verified interest is available"
            result.evidence.append(
                self._verification_result_evidence(
                    task,
                    target,
                    status=VerificationStatus.REJECTED,
                    summary="No current-generation verified interest was available for deterministic verification.",
                    evidence_refs=[],
                    metadata={"reason": "no_verified_interest"},
                )
            )
            return result

        selected = verified_interests[0]
        selected_refs = [ref for ref in selected.evidence_refs if ref in evidence_by_id]
        verified_refs = [ref for ref in selected_refs if ref in verified_evidence_ids]
        if not verified_refs:
            result.summary = "bounded verification rejected; verified interest lacks verified evidence"
            result.evidence.append(
                self._verification_result_evidence(
                    task,
                    target,
                    status=VerificationStatus.REJECTED,
                    summary=(
                        f"Interest '{selected.title}' is marked verified, but none of its evidence references "
                        "are current-generation verified evidence."
                    ),
                    evidence_refs=selected_refs,
                    metadata={"reason": "missing_verified_evidence", "interest_id": selected.id},
                )
            )
            return result

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
        result.notes.append(
            Note(
                target_id=target.id,
                task_id=task.id,
                title="Bounded verification result",
                body=(
                    f"Verified interest '{selected.title}' is backed by current-generation verified evidence. "
                    "This adapter produced durable verification evidence only; it did not execute exploit code."
                ),
                confidence=min(0.92, max(0.7, selected.confidence)),
                freshness=0.95,
                metadata={
                    "adapter": "finding-verification",
                    "interest_id": selected.id,
                    "verification_evidence_ref": verification_evidence.id,
                },
            )
        )
        result.findings.append(
            Finding(
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
        )
        result.summary = "bounded verification completed with durable evidence linkage"
        return result

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
