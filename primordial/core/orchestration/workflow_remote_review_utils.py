from __future__ import annotations

from primordial.core.orchestration.workflow_deps import (
    CredentialedAccessSurface,
    json,
    normalize_primitive_hint,
    Target,
    TaskKind,
)

class WorkflowRemoteReviewUtilsMixin:
    def _remote_review_payload(self, metadata: dict[str, object]) -> dict[str, object]:
        for key in ("review", "remote_review", "premium_review", "response"):
            value = metadata.get(key)
            if isinstance(value, dict):
                return value
        return metadata

    def _remote_review_action_reject_reason(
        self,
        *,
        target: Target,
        recommendation: dict[str, object],
        available: set[str],
        current_evidence_ids: set[str],
        rationale_refs: list[str],
        surface: CredentialedAccessSurface,
    ) -> str:
        if not target.in_scope:
            return "target is out of scope"
        target_hint = recommendation.get("target") or recommendation.get("target_handle") or recommendation.get("target_id")
        if target_hint and str(target_hint) not in {target.id, target.handle, target.display_name}:
            return "recommendation targets a different scope object"
        if self._remote_review_claims_authority(recommendation):
            return "remote review attempted to approve action, credential use, scope expansion, or execution"
        primitive_hint = self._normalized_primitive_hint(recommendation)
        if not primitive_hint:
            return "no primitive hint supplied"
        if primitive_hint not in available:
            return "missing primitive mapping"
        task_kind = self.REMOTE_REVIEW_KIND_BY_PRIMITIVE.get(primitive_hint)
        if task_kind is None:
            return "primitive maps to no deterministic task kind"
        action_refs = self._remote_review_action_refs(recommendation, rationale_refs)
        if not action_refs:
            return "recommendation has no evidence refs"
        if not set(action_refs).issubset(current_evidence_ids):
            return "recommendation references evidence outside the current target generation"
        if task_kind == TaskKind.CREDENTIALED_ACCESS_CHECK:
            if not surface.eligible:
                return surface.blocked_reason or "current evidence does not support credentialed Windows SMB/WinRM access"
            if not self._intent_allows_task(target, TaskKind.CREDENTIALED_ACCESS_CHECK):
                return "active operator intent does not allow credential validation"
        elif not self._intent_allows_task(target, task_kind):
            return "active operator intent does not allow this task kind"
        return ""

    def _normalized_primitive_hint(self, recommendation: dict[str, object]) -> str:
        raw = recommendation.get("primitive_hint") or recommendation.get("primitive") or recommendation.get("capability")
        return normalize_primitive_hint(raw)

    def _raw_primitive_hint(self, recommendation: dict[str, object]) -> str:
        raw = recommendation.get("primitive_hint") or recommendation.get("primitive") or recommendation.get("capability")
        return str(raw or "").strip()

    def _remote_review_action_refs(self, recommendation: dict[str, object], rationale_refs: list[str]) -> list[str]:
        refs = recommendation.get("evidence_refs")
        if isinstance(refs, list):
            return [str(item) for item in refs if str(item).strip()]
        return [str(item) for item in rationale_refs if str(item).strip()]

    def _review_rationale_evidence_refs(self, value: object) -> list[str]:
        refs: list[str] = []
        if isinstance(value, list):
            for item in value:
                if not isinstance(item, dict):
                    continue
                item_refs = item.get("evidence_refs")
                if isinstance(item_refs, list):
                    refs.extend(str(ref) for ref in item_refs if str(ref).strip())
        return sorted(set(refs))

    def _remote_review_claims_authority(self, recommendation: dict[str, object]) -> bool:
        authority_keys = {
            "approved",
            "approval",
            "approve",
            "credential_use_approved",
            "scope_expansion_approved",
            "execute",
            "execute_now",
            "tool_execution",
        }
        for key, value in recommendation.items():
            normalized = str(key).strip().lower()
            if normalized in authority_keys and bool(value):
                return True
        serialized = json.dumps(recommendation, sort_keys=True, default=str).lower()
        return any(
            phrase in serialized
            for phrase in (
                "credential use is approved",
                "scope expansion approved",
                "execute immediately",
                "run the tool now",
            )
        )

    def _float_between_0_1(self, *values: object) -> float:
        for value in values:
            try:
                parsed = float(value)
            except (TypeError, ValueError):
                continue
            return max(0.0, min(1.0, parsed))
        return 0.5
