from __future__ import annotations

from primordial.core.orchestration.workflow_deps import (
    blueprint_for,
    normalize_primitive_hint,
    Target,
    Task,
    TaskKind,
)

from primordial.core.orchestration.workflow_types import (
    PlannedTargetAction,
)

class WorkflowAiAdmissionMixin:
    def _evaluate_ai_proposal_admission(self, tasks: list[Task]) -> dict[str, list[dict[str, object]]]:
        available_primitives = {primitive.name.lower() for primitive in self.store.list_primitives()}
        available_capabilities = {
            tag.lower()
            for primitive in self.store.list_primitives()
            for tag in primitive.capability_tags
        }
        accepted: list[dict[str, object]] = []
        rejected: list[dict[str, object]] = []
        for task in tasks:
            proposal = task.metadata.get("ai_proposal")
            if not isinstance(proposal, dict):
                continue
            for action in proposal.get("candidate_actions", [])[:6]:
                if not isinstance(action, dict):
                    continue
                title = str(action.get("title") or "untitled action").strip()
                raw_primitive_hint = str(action.get("primitive_hint") or "").strip()
                primitive_hint = normalize_primitive_hint(raw_primitive_hint)
                if primitive_hint and (primitive_hint in available_primitives or primitive_hint in available_capabilities):
                    item = {
                        "task_id": task.id,
                        "title": title,
                        "primitive_hint": primitive_hint,
                    }
                    if raw_primitive_hint and raw_primitive_hint.lower().replace("_", "-") != primitive_hint:
                        item["raw_primitive_hint"] = raw_primitive_hint
                    accepted.append(item)
                else:
                    item = {
                        "task_id": task.id,
                        "title": title,
                        "primitive_hint": primitive_hint,
                        "reason": "missing primitive mapping" if primitive_hint else "no primitive hint supplied",
                    }
                    if raw_primitive_hint and raw_primitive_hint.lower().replace("_", "-") != primitive_hint:
                        item["raw_primitive_hint"] = raw_primitive_hint
                    rejected.append(item)
        return {"accepted": accepted[:8], "rejected": rejected[:8]}

    def _ai_admitted_candidate_actions(
        self,
        target: Target,
        ai_admission: dict[str, list[dict[str, object]]],
        *,
        reserved_kinds: set[TaskKind],
    ) -> list[PlannedTargetAction]:
        if not self._target_has_current_generation_evidence(target):
            return []
        active_generation = self._target_active_generation(target)
        actions: list[PlannedTargetAction] = []
        for item in ai_admission.get("accepted", []):
            primitive_hint = normalize_primitive_hint(str(item.get("primitive_hint") or ""))
            if not primitive_hint:
                continue
            task_kind = self.REMOTE_REVIEW_KIND_BY_PRIMITIVE.get(primitive_hint)
            if task_kind not in self.AI_PROPOSAL_MATERIALIZED_KINDS:
                continue
            if task_kind in reserved_kinds:
                continue
            if self._task_exists_for_current_generation(target.id, task_kind, active_generation):
                continue
            if not self._intent_allows_task(target, task_kind):
                continue
            blueprint = blueprint_for(task_kind)
            title = str(item.get("title") or blueprint.title).strip() or blueprint.title
            actions.append(
                PlannedTargetAction(
                    kind=task_kind,
                    title=title,
                    summary=(
                        f"Run registered primitive {primitive_hint} from an admitted planner proposal; "
                        "execution remains bounded by scope, policy, and Operator Intent."
                    ),
                    confidence=0.68,
                    phase_label=blueprint.phase.value,
                    subphase=f"ai_proposal:{task_kind.value}",
                    transition_reason="AI proposal matched a registered safe recon primitive.",
                    prerequisite="current-generation evidence and registered primitive mapping",
                    metadata={
                        "ai_proposal_materialized": True,
                        "source_ai_task_id": item.get("task_id"),
                        "primitive_hint": primitive_hint,
                        "raw_primitive_hint": item.get("raw_primitive_hint", primitive_hint),
                    },
                )
            )
            reserved_kinds.add(task_kind)
        return actions

    def _evaluate_remote_review_admission(self, target: Target) -> dict[str, object]:
        evidence = self._current_generation_evidence(target, limit=200)
        review_records = self._remote_review_records(evidence)
        if not review_records:
            return {"actions": [], "accepted": [], "rejected": []}
        context = self._remote_review_admission_context(target, evidence)
        results = [self._remote_review_record_admission(target, record, context) for record in review_records]
        return self._merge_admission_results(results)

    def _remote_review_records(self, evidence: list[object]) -> list[object]:
        review_kinds = {"premium_review_result", "planner_remote_review", "remote_premium_review"}
        return [item for item in evidence if str(item.metadata.get("kind") or "").lower() in review_kinds]
