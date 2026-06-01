from __future__ import annotations

from primordial.modes.security.execution_common import *


class PrimitivePocHandlerMixin:
    def _handle_poc_applicability_validation(self, task: Task, context: ContextSlice) -> TaskExecutionResult:
        blocked = self._require_intent(task)
        if blocked is not None:
            return blocked
        result = TaskExecutionResult(summary="PoC applicability validation completed")
        target = self.store.get_target(task.target_id)
        if not target:
            result.success = False
            result.error = "target not found"
            return result

        evidence = self._task_generation_records(task, target, self.store.list_evidence(target_id=target.id, limit=100))
        research_items = [item for item in evidence if item.metadata.get("kind") == "exploit_research"]
        service_items = [
            item
            for item in evidence
            if item.metadata.get("kind") in {"tcp_service_discovery", "dns_enumeration", "ad_enumeration", "web_content_discovery"}
        ]
        candidates = self._load_poc_candidates(research_items)
        if not candidates:
            result.success = False
            result.error = "no retained public PoC candidates are available for applicability validation"
            return result

        service_facts = self._poc_service_facts(service_items)
        has_foothold = self._poc_has_foothold(evidence)
        classified = [self._classify_poc_candidate(candidate, service_facts, has_foothold) for candidate in candidates]
        ready_count = sum(1 for item in classified if item["status"] == "ready_for_review")
        blocked_count = len(classified) - ready_count
        artifact = self._write_artifact(
            task,
            target.id,
            f"poc-applicability-{self._safe_artifact_fragment(target.handle)}",
            {
                "target": target.as_payload(),
                "service_facts": service_facts,
                "classified_candidates": classified,
                "guardrails": {
                    "executes_pocs": False,
                    "writes_exploit_code": False,
                    "requires_policy_approval_before_execution": True,
                    "requires_exact_version_or_prerequisite_match": True,
                },
            },
        )
        result.artifacts.append(artifact)
        evidence_record = EvidenceRecord(
            target_id=target.id,
            task_id=task.id,
            type=EvidenceType.MODEL_REVIEW,
            title=f"PoC applicability validation: {target.handle}",
            summary=(
                f"Classified {len(classified)} retained public PoC candidate(s): "
                f"{ready_count} ready for gated review, {blocked_count} blocked or research-only. "
                "No PoC was executed and no exploit code was generated."
            ),
            source_ref=artifact.id,
            verification_status=VerificationStatus.PARTIAL,
            confidence=0.72,
            freshness=0.92,
            artifact_path=artifact.path,
            metadata={
                "kind": "poc_applicability_validation",
                "candidate_count": len(classified),
                "ready_count": ready_count,
                "blocked_count": blocked_count,
                "executes_pocs": False,
                "writes_exploit_code": False,
            },
        )
        result.evidence.append(evidence_record)
        result.notes.append(
            Note(
                target_id=target.id,
                task_id=task.id,
                title="PoC applicability validation summary",
                body=self._build_poc_applicability_note(classified, service_facts),
                confidence=0.74,
                freshness=0.9,
                metadata={"phase": task.phase.value, "candidate_count": len(classified), "ready_count": ready_count},
            )
        )
        if self._ai_review_requested(task):
            ai_review = self._run_ai_review(
                task,
                target_id=target.id,
                title="AI PoC applicability review",
                snapshot=(
                    f"{self._build_ai_target_snapshot(target.id)}\n\n"
                    f"Service facts: {json.dumps(service_facts, sort_keys=True)}\n"
                    f"Classified candidates: {json.dumps(classified[:10], sort_keys=True)}"
                ),
                instruction=(
                    "Review the deterministic PoC applicability classifications. Call out false positives, missing "
                    "version evidence, foothold prerequisites, safer alternate validations, and exact stop conditions. "
                    "This is a read-only review: do not execute PoCs, do not generate exploit code, and do not mark a "
                    "finding verified."
                ),
            )
            self._apply_ai_review(result, task, ai_review)
        else:
            evidence_record.metadata["ai_review_skipped"] = True
            evidence_record.metadata["ai_review_skip_reason"] = "operator-triggered AI review was not requested"
        if ready_count:
            result.interests.append(
                Interest(
                    target_id=target.id,
                    title="PoC applicability candidates ready for gated review",
                    summary=(
                        f"{ready_count} retained public PoC candidate(s) have enough evidence for a deeper gated "
                        "review. Execution still requires explicit policy approval and bounded stop conditions."
                    ),
                    evidence_refs=[evidence_record.id],
                    status=InterestStatus.OPEN,
                    confidence=0.72,
                    metadata={"origin_task": task.id, "class": "poc_applicability", "ready_count": ready_count},
                )
            )
        result.events.append(
            EventRecord(
                type=EventType.TASK_SUCCEEDED,
                summary=f"PoC applicability validation classified {len(classified)} candidate(s)",
                target_id=target.id,
                task_id=task.id,
                metadata={"ready_count": ready_count, "blocked_count": blocked_count},
            )
        )
        return result
