from __future__ import annotations

from primordial.core.orchestration.workflow_deps import (
    blueprint_for,
    field,
    Target,
    TaskKind,
)

from primordial.core.orchestration.workflow_types import (
    PlannedTargetAction,
    RemoteReviewAdmissionContext,
)

class WorkflowRemoteReviewAdmissionMixin:
    def _remote_review_admission_context(
        self,
        target: Target,
        evidence: list[object],
    ) -> RemoteReviewAdmissionContext:
        primitives = self.store.list_primitives()
        available_primitives = {
            value.lower()
            for primitive in primitives
            for value in [primitive.name, *primitive.capability_tags]
        }
        return RemoteReviewAdmissionContext(
            current_evidence_ids={item.id for item in evidence},
            available_primitives=available_primitives,
            active_generation=self._target_active_generation(target),
            surface=self._current_credentialed_access_surface(target),
        )

    def _remote_review_record_admission(
        self,
        target: Target,
        record: object,
        context: RemoteReviewAdmissionContext,
    ) -> dict[str, list[object]]:
        review = self._remote_review_payload(record.metadata)
        missing_fields = self._remote_review_missing_required_fields(review)
        if missing_fields:
            reason = "remote review response missing required fields: " + ", ".join(missing_fields)
            return self._admission_result(rejected=[self._remote_review_rejection(record, record.title, reason)])
        recommendations = review.get("recommended_next_actions")
        if not isinstance(recommendations, list):
            return self._admission_result(
                rejected=[self._remote_review_rejection(record, record.title, "recommended_next_actions is not a list")]
            )
        rationale_refs = self._review_rationale_evidence_refs(review.get("rationale_with_evidence_refs"))
        return self._remote_review_recommendations_admission(
            target, record, review, recommendations, rationale_refs, context
        )

    def _remote_review_missing_required_fields(self, review: dict[str, object]) -> list[str]:
        required_fields = (
            "recommended_next_actions",
            "missing_evidence",
            "invalid_existing_tasks",
            "primitive_gaps",
            "confidence",
            "rationale_with_evidence_refs",
        )
        return [field for field in required_fields if field not in review]

    def _remote_review_recommendations_admission(
        self,
        target: Target,
        record: object,
        review: dict[str, object],
        recommendations: list[object],
        rationale_refs: list[str],
        context: RemoteReviewAdmissionContext,
    ) -> dict[str, list[object]]:
        result = self._admission_result()
        for recommendation in recommendations[:8]:
            if not isinstance(recommendation, dict):
                rejection = self._remote_review_rejection(record, str(recommendation)[:80], "recommended action is not an object")
                result["rejected"].append(rejection)
                continue
            admission = self._remote_review_recommendation_admission(
                target, record, review, recommendation, rationale_refs, context
            )
            self._extend_admission_result(result, admission)
        return result

    def _remote_review_recommendation_admission(
        self,
        target: Target,
        record: object,
        review: dict[str, object],
        recommendation: dict[str, object],
        rationale_refs: list[str],
        context: RemoteReviewAdmissionContext,
    ) -> dict[str, list[object]]:
        title = str(recommendation.get("title") or recommendation.get("action") or "untitled action").strip()
        primitive_hint = self._normalized_primitive_hint(recommendation)
        reason = self._remote_review_action_reject_reason(
            target=target,
            recommendation=recommendation,
            available=context.available_primitives,
            current_evidence_ids=context.current_evidence_ids,
            rationale_refs=rationale_refs,
            surface=context.surface,
        )
        if reason:
            rejection = self._remote_review_rejection(record, title, reason, primitive_hint=primitive_hint)
            return self._admission_result(rejected=[rejection])
        task_kind = self.REMOTE_REVIEW_KIND_BY_PRIMITIVE[primitive_hint]
        if self._remote_review_task_exists(target, task_kind, context.active_generation):
            rejection = self._remote_review_rejection(
                record, title, "equivalent current-generation task already exists", primitive_hint=primitive_hint
            )
            return self._admission_result(rejected=[rejection])
        action_refs = self._remote_review_action_refs(recommendation, rationale_refs)
        action = self._remote_review_planned_action(record, review, recommendation, task_kind, action_refs)
        accepted = self._remote_review_acceptance(record, title, primitive_hint, task_kind, action_refs)
        return self._admission_result(actions=[action], accepted=[accepted])

    def _remote_review_task_exists(
        self,
        target: Target,
        task_kind: TaskKind,
        active_generation: str | None,
    ) -> bool:
        if task_kind == TaskKind.ANALYZE_EVIDENCE:
            return False
        return self._task_exists_for_current_generation(target.id, task_kind, active_generation)

    def _remote_review_planned_action(
        self,
        record: object,
        review: dict[str, object],
        recommendation: dict[str, object],
        task_kind: TaskKind,
        action_refs: list[str],
    ) -> PlannedTargetAction:
        title = str(recommendation.get("title") or recommendation.get("action") or "untitled action").strip()
        primitive_hint = self._normalized_primitive_hint(recommendation)
        metadata = self._remote_review_action_metadata(record, recommendation, primitive_hint, action_refs)
        return PlannedTargetAction(
            kind=task_kind,
            title=title,
            summary=str(recommendation.get("summary") or recommendation.get("rationale") or title),
            confidence=self._float_between_0_1(recommendation.get("confidence"), review.get("confidence")),
            phase_label=blueprint_for(task_kind).phase.value,
            subphase=f"remote_review:{task_kind.value}",
            transition_reason=(
                "Remote premium review recommended this action, and deterministic admission "
                "validated primitive, evidence, scope, policy, and Operator Intent gates."
            ),
            prerequisite=str(recommendation.get("prerequisite") or "current-generation evidence refs"),
            metadata=metadata,
        )

    def _remote_review_action_metadata(
        self,
        record: object,
        recommendation: dict[str, object],
        primitive_hint: str,
        action_refs: list[str],
    ) -> dict[str, object]:
        metadata: dict[str, object] = {
            "remote_review_admitted": True,
            "source_review_evidence_id": record.id,
            "primitive_hint": primitive_hint,
            "evidence_refs": action_refs,
            "supporting_evidence_refs": action_refs,
        }
        raw_primitive_hint = self._raw_primitive_hint(recommendation)
        if raw_primitive_hint and raw_primitive_hint.lower().replace("_", "-") != primitive_hint:
            metadata["raw_primitive_hint"] = raw_primitive_hint
        return metadata

    def _remote_review_acceptance(
        self,
        record: object,
        title: str,
        primitive_hint: str,
        task_kind: TaskKind,
        action_refs: list[str],
    ) -> dict[str, object]:
        return {
            "review_evidence_id": record.id,
            "title": title,
            "primitive_hint": primitive_hint,
            "task_kind": task_kind.value,
            "evidence_refs": action_refs,
        }

    def _remote_review_rejection(
        self,
        record: object,
        title: str,
        reason: str,
        *,
        primitive_hint: str | None = None,
    ) -> dict[str, object]:
        payload = {"review_evidence_id": record.id, "title": title, "reason": reason}
        if primitive_hint is not None:
            payload["primitive_hint"] = primitive_hint
        return payload

    def _admission_result(
        self,
        *,
        actions: list[PlannedTargetAction] | None = None,
        accepted: list[dict[str, object]] | None = None,
        rejected: list[dict[str, object]] | None = None,
    ) -> dict[str, list[object]]:
        return {"actions": actions or [], "accepted": accepted or [], "rejected": rejected or []}

    def _extend_admission_result(self, result: dict[str, list[object]], incoming: dict[str, list[object]]) -> None:
        result["actions"].extend(incoming["actions"])
        result["accepted"].extend(incoming["accepted"])
        result["rejected"].extend(incoming["rejected"])

    def _merge_admission_results(self, results: list[dict[str, list[object]]]) -> dict[str, object]:
        merged = self._admission_result()
        for result in results:
            self._extend_admission_result(merged, result)
        return {
            "actions": merged["actions"][:6],
            "accepted": merged["accepted"][:8],
            "rejected": merged["rejected"][:12],
        }
