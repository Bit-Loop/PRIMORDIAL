from __future__ import annotations

from primordial.core.orchestration.workflow_deps import (
    classify_credentialed_access_surface,
    CredentialedAccessSurface,
    Target,
    TaskKind,
)

from primordial.core.orchestration.workflow_types import (
    PlannedTargetAction,
)

class WorkflowAttackCandidatesMixin:
    def _analysis_and_research_candidate_actions(self, target: Target) -> list[PlannedTargetAction]:
        specs: list[dict[str, object]] = []
        if self._analysis_is_stale(target):
            specs.append(
                {
                    "kind": TaskKind.ANALYZE_EVIDENCE,
                    "title": "Analyze accumulated evidence",
                    "summary": f"Cluster recon evidence and generate bounded hypotheses for {target.handle}.",
                    "confidence": 0.9,
                    "subphase": "evidence_review",
                    "transition_reason": "The current evidence signature has not been analyzed yet.",
                    "prerequisite": "current-generation recon evidence",
                }
            )
        if self._should_plan_exploit_research(target):
            specs.append(
                {
                    "kind": TaskKind.EXPLOIT_RESEARCH,
                    "title": "Research relevant public PoCs",
                    "summary": f"Search local exploit references for evidence-backed services on {target.handle}.",
                    "confidence": 0.81,
                    "subphase": "exploit_research",
                    "transition_reason": "Current-generation recon evidence supports public exploit research triage.",
                    "prerequisite": "current-generation service or AD evidence",
                }
            )
        if self._should_plan_poc_applicability_validation(target):
            specs.append(self._poc_applicability_action_spec(target))
        return self._methodology_actions(target, specs)

    def _poc_applicability_action_spec(self, target: Target) -> dict[str, object]:
        return {
            "kind": TaskKind.POC_APPLICABILITY_VALIDATION,
            "title": "Validate public PoC applicability",
            "summary": (
                "Classify retained public exploit references against exact service/version evidence, "
                f"foothold prerequisites, and policy gates for {target.handle}."
            ),
            "confidence": 0.79,
            "subphase": "poc_gating",
            "transition_reason": "Retained public PoC research exists, but deterministic applicability gating has not run.",
            "prerequisite": "current-generation exploit research",
        }

    def _attack_and_access_candidate_actions(self, target: Target) -> list[PlannedTargetAction]:
        specs: list[dict[str, object]] = []
        kerberos_checks = self._planned_kerberos_check_types(target)
        if kerberos_checks:
            specs.append(
                {
                    "kind": TaskKind.KERBEROS_ATTACK_CHECK,
                    "title": "Run Kerberos attack-path checks",
                    "summary": f"Check allowed Kerberos attack-path applicability for discovered principals on {target.handle}.",
                    "confidence": 0.76,
                    "subphase": "kerberos_attack_path",
                    "transition_reason": "Current-generation principal evidence supports bounded Kerberos attack-path checks.",
                    "prerequisite": "current-generation principal discovery",
                    "metadata": {"kerberos_checks": kerberos_checks},
                }
            )
        credential_surface = self._current_credentialed_access_surface(target)
        if self._should_plan_credentialed_access_check(target, credential_surface):
            specs.append(self._credentialed_access_action_spec(target, credential_surface))
        return self._methodology_actions(target, specs)

    def _credentialed_access_action_spec(
        self,
        target: Target,
        credential_surface: CredentialedAccessSurface,
    ) -> dict[str, object]:
        return {
            "kind": TaskKind.CREDENTIALED_ACCESS_CHECK,
            "title": "Verify credentialed Windows SMB/WinRM access",
            "summary": f"Use configured known credentials to verify evidence-supported Windows access for {target.handle}.",
            "confidence": 0.75,
            "subphase": "credentialed_verification",
            "transition_reason": (
                "Operator-configured known credentials are present and current evidence supports Windows SMB/WinRM "
                "or AD/DC access."
            ),
            "prerequisite": "configured known credentials and current-generation Windows SMB/WinRM or AD/DC evidence",
            "metadata": {
                "credential_namespace": "known",
                "credentialed_access_surface": credential_surface.as_payload(),
                "protocols": list(credential_surface.protocols),
                "os_family": credential_surface.os_family,
                "evidence_refs": list(credential_surface.evidence_refs),
            },
        }

    def _verification_and_maintenance_candidate_actions(self, target: Target) -> list[PlannedTargetAction]:
        specs: list[dict[str, object]] = []
        verified_interests = self._verified_interest_count_current_generation(target)
        if verified_interests >= 1:
            specs.append(
                {
                    "kind": TaskKind.VERIFY_HYPOTHESIS,
                    "title": "Verify prioritized hypothesis",
                    "summary": f"Run bounded verification for a high-value hypothesis on {target.handle}.",
                    "confidence": 0.71,
                    "subphase": "bounded_verification",
                    "transition_reason": "At least one current-generation verified interest exists and deserves bounded verification planning.",
                    "prerequisite": "current-generation verified interest",
                }
            )
        if verified_interests >= 2:
            specs.append(
                {
                    "kind": TaskKind.CHAIN_CANDIDATES,
                    "title": "Review exploit-chain candidates",
                    "summary": f"Review related verified interests for possible exploit chains on {target.handle}.",
                    "confidence": 0.67,
                    "subphase": "chain_review",
                    "transition_reason": "Multiple current-generation verified interests may support exploit-chain review.",
                    "prerequisite": "two or more current-generation verified interests",
                }
            )
        if self._memory_service().needs_compaction(target.id):
            specs.append(self._memory_compaction_action_spec(target))
        return self._methodology_actions(target, specs)

    def _memory_compaction_action_spec(self, target: Target) -> dict[str, object]:
        return {
            "kind": TaskKind.COMPACT_MEMORY,
            "title": "Compact notes and memory",
            "summary": f"Promote durable memory and compact noisy context for {target.handle}.",
            "confidence": 0.64,
            "subphase": "memory_maintenance",
            "transition_reason": "Memory service indicates the current target context needs compaction.",
        }

    def _methodology_blockers(self, target: Target, evidence) -> list[str]:
        blockers: list[str] = []
        capabilities = {
            tag.lower()
            for primitive in self.store.list_primitives()
            for tag in [primitive.name, *primitive.capability_tags]
        }
        credential_surface = classify_credentialed_access_surface(evidence)
        has_remote_admin_surface = credential_surface.eligible
        has_research_candidates = any(
            item.metadata.get("kind") == "exploit_research" and int(item.metadata.get("match_count", 0) or 0) > 0
            for item in evidence
        )
        has_ad_inventory_without_principals = any(item.metadata.get("kind") == "ad_enumeration" for item in evidence) and not any(
            item.metadata.get("kind") == "kerberos_user_discovery" for item in evidence
        )
        if has_research_candidates and not self._poc_adaptation_available(capabilities):
            blockers.append(
                "Retained public PoC candidates exist, but no gated PoC applicability/adaptation primitive is registered."
            )
        if has_remote_admin_surface and not self._known_credentials_configured():
            blockers.append(
                "Known username/password are not configured, so credentialed Windows SMB/WinRM verification cannot run."
            )
        if not has_remote_admin_surface and credential_surface.blocked_reason and self._surface_has_admin_adjacent_evidence(credential_surface):
            blockers.append(f"Credentialed Windows SMB/WinRM planning blocked: {credential_surface.blocked_reason}")
        policy = self._active_intent_policy()
        if policy is not None:
            if has_research_candidates and not policy.poc_applicability_validation:
                blockers.append("Active operator intent does not allow public PoC applicability validation.")
            if (
                has_ad_inventory_without_principals
                and not policy.kerberos_policy.asrep_roast_check_allowed
                and not policy.kerberos_policy.kerberoast_check_allowed
            ):
                blockers.append("Active operator intent does not allow Kerberos principal discovery.")
            if has_remote_admin_surface and not policy.credential_policy.credential_validation_allowed:
                blockers.append("Active operator intent does not allow credentialed access checks.")
        if target.metadata.get("active_ip"):
            active_generation = self._target_active_generation(target)
            has_current_recon = any(
                item.metadata.get("kind") == "tcp_service_discovery"
                and str(item.metadata.get("active_ip_generation", "")) == active_generation
                for item in evidence
            )
            if active_generation and not has_current_recon:
                blockers.append(
                    f"Active IP changed to {target.metadata['active_ip']}, but fresh current-generation service discovery has not completed."
                )
        return blockers
