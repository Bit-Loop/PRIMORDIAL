from __future__ import annotations

from primordial.core.orchestration.workflow_deps import (
    blueprint_for,
    Target,
    TaskKind,
)

from primordial.core.orchestration.workflow_types import (
    PlannedTargetAction,
)

class WorkflowActionCandidatesMixin:
    def _ai_materialized_action_payloads(self, actions: list[PlannedTargetAction]) -> list[dict[str, object]]:
        return [
            {
                "kind": item.kind.value,
                "title": item.title,
                "primitive_hint": item.metadata.get("primitive_hint"),
                "source_ai_task_id": item.metadata.get("source_ai_task_id"),
            }
            for item in actions
        ]

    def _methodology_candidate_actions(self, target: Target) -> list[PlannedTargetAction]:
        if not self._target_has_current_generation_evidence(target):
            return self._bootstrap_methodology_candidate_actions(target)
        return [
            *self._inventory_methodology_candidate_actions(target),
            *self._analysis_and_research_candidate_actions(target),
            *self._attack_and_access_candidate_actions(target),
            *self._verification_and_maintenance_candidate_actions(target),
        ]

    def _methodology_action(
        self,
        target: Target,
        kind: TaskKind,
        title: str,
        summary: str,
        *,
        confidence: float,
        subphase: str,
        transition_reason: str,
        prerequisite: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> PlannedTargetAction | None:
        active_generation = self._target_active_generation(target)
        if kind != TaskKind.ANALYZE_EVIDENCE and self._task_exists_for_current_generation(
            target.id, kind, active_generation
        ):
            return None
        return PlannedTargetAction(
            kind=kind,
            title=title,
            summary=summary,
            confidence=confidence,
            phase_label=blueprint_for(kind).phase.value,
            subphase=subphase,
            transition_reason=transition_reason,
            prerequisite=prerequisite,
            metadata=metadata or {},
        )

    def _methodology_actions(self, target: Target, specs: list[dict[str, object]]) -> list[PlannedTargetAction]:
        actions: list[PlannedTargetAction] = []
        for spec in specs:
            action = self._methodology_action(target, **spec)
            if action is not None:
                actions.append(action)
        return actions

    def _bootstrap_methodology_candidate_actions(self, target: Target) -> list[PlannedTargetAction]:
        specs: list[dict[str, object]] = [
            {
                "kind": TaskKind.RECON_SCAN,
                "title": "Run recon sweep",
                "summary": f"Collect initial recon evidence for {target.handle}.",
                "confidence": 0.95,
                "subphase": "bootstrap",
                "transition_reason": "No current-generation evidence exists for the active target generation.",
            }
        ]
        if self._should_plan_service_discovery(target):
            specs.append(
                {
                    "kind": TaskKind.SERVICE_DISCOVERY,
                    "title": "Run bounded service discovery",
                    "summary": f"Collect TCP service inventory evidence for {target.handle}.",
                    "confidence": 0.93,
                    "subphase": "service_inventory",
                    "transition_reason": "A fresh active-IP generation needs service inventory before deeper branching.",
                }
            )
        return self._methodology_actions(target, specs)

    def _inventory_methodology_candidate_actions(self, target: Target) -> list[PlannedTargetAction]:
        specs: list[dict[str, object]] = []
        if self._should_plan_service_discovery(target):
            specs.append(
                {
                    "kind": TaskKind.SERVICE_DISCOVERY,
                    "title": "Run bounded service discovery",
                    "summary": f"Collect TCP service inventory evidence for {target.handle}.",
                    "confidence": 0.93,
                    "subphase": "service_inventory",
                    "transition_reason": "Fresh service inventory is missing for the active target generation.",
                }
            )
        specs.extend(self._conditional_inventory_action_specs(target))
        return self._methodology_actions(target, specs)

    def _conditional_inventory_action_specs(self, target: Target) -> list[dict[str, object]]:
        checks = [
            (
                self._should_plan_dns_enumeration,
                {
                    "kind": TaskKind.DNS_ENUMERATION,
                    "title": "Run bounded DNS enumeration",
                    "summary": f"Collect DNS records and zone-transfer evidence for {target.handle}.",
                    "confidence": 0.88,
                    "subphase": "dns_inventory",
                    "transition_reason": "Port and host evidence indicates DNS is present and unresolved for the current generation.",
                    "prerequisite": "current-generation service discovery",
                },
            ),
            (
                self._should_plan_web_content_discovery,
                {
                    "kind": TaskKind.WEB_CONTENT_DISCOVERY,
                    "title": "Run bounded web content discovery",
                    "summary": f"Discover HTTP paths and virtual directories for {target.handle}.",
                    "confidence": 0.87,
                    "subphase": "web_surface",
                    "transition_reason": "HTTP evidence exists without bounded content-discovery coverage for the current generation.",
                    "prerequisite": "current-generation HTTP probe evidence",
                },
            ),
            (
                self._should_plan_ad_enumeration,
                {
                    "kind": TaskKind.AD_ENUMERATION,
                    "title": "Run bounded AD enumeration",
                    "summary": f"Collect anonymous SMB/LDAP/RPC inventory for {target.handle}.",
                    "confidence": 0.89,
                    "subphase": "ad_inventory",
                    "transition_reason": "Current-generation service evidence exposes AD-adjacent ports without corresponding AD inventory.",
                    "prerequisite": "current-generation service discovery",
                },
            ),
            (
                self._should_plan_kerberos_user_discovery,
                {
                    "kind": TaskKind.KERBEROS_USER_DISCOVERY,
                    "title": "Run Kerberos/LDAP user discovery",
                    "summary": f"Discover candidate AD/Kerberos principals for {target.handle}.",
                    "confidence": 0.83,
                    "subphase": "principal_discovery",
                    "transition_reason": "AD evidence exists, but current-generation principal discovery has not run yet.",
                    "prerequisite": "current-generation AD enumeration",
                },
            ),
        ]
        return [spec for predicate, spec in checks if predicate(target)]
