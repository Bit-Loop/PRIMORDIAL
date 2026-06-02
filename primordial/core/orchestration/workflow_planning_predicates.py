from __future__ import annotations

from primordial.core.orchestration.workflow_deps import (
    AD_INDICATOR_PORTS,
    CredentialedAccessSurface,
    DNS_PORTS,
    json,
    OrchestrationReport,
    Target,
    TaskKind,
    TaskStatus,
)

class WorkflowPlanningPredicatesMixin:
    def _should_plan_service_discovery(self, target: Target) -> bool:
        if not self._profile_allows_task(target, "service_discovery") and not target.metadata.get("allow_service_discovery"):
            return False
        for evidence in self.store.list_evidence(target_id=target.id, limit=200):
            if evidence.metadata.get("kind") == "tcp_service_discovery" and self._evidence_matches_active_generation(target, evidence):
                return False
        return True

    def _should_plan_ad_enumeration(self, target: Target) -> bool:
        if not self._profile_allows_task(target, "ad_enumeration") and not target.metadata.get("allow_ad_enumeration"):
            return False
        service_evidence = [
            evidence
            for evidence in self.store.list_evidence(target_id=target.id, limit=200)
            if evidence.metadata.get("kind") == "tcp_service_discovery"
            and self._evidence_matches_active_generation(target, evidence)
        ]
        if not service_evidence:
            return False
        for evidence in self.store.list_evidence(target_id=target.id, limit=200):
            if evidence.metadata.get("kind") == "ad_enumeration" and self._evidence_matches_active_generation(target, evidence):
                return False
        open_ports = {
            int(service.get("port", 0))
            for evidence in service_evidence
            for service in evidence.metadata.get("open_services", [])
            if isinstance(service, dict)
        }
        return bool(open_ports.intersection(AD_INDICATOR_PORTS))

    def _should_plan_dns_enumeration(self, target: Target) -> bool:
        if not self._profile_allows_task(target, "dns_enumeration") and not target.metadata.get("allow_dns_enumeration"):
            return False
        service_evidence = [
            evidence
            for evidence in self.store.list_evidence(target_id=target.id, limit=200)
            if evidence.metadata.get("kind") == "tcp_service_discovery"
            and self._evidence_matches_active_generation(target, evidence)
        ]
        if not service_evidence:
            return False
        for evidence in self.store.list_evidence(target_id=target.id, limit=200):
            if evidence.metadata.get("kind") == "dns_enumeration" and self._evidence_matches_active_generation(target, evidence):
                return False
        for evidence in service_evidence:
            for service in evidence.metadata.get("open_services", []):
                if isinstance(service, dict) and int(service.get("port", 0)) in DNS_PORTS:
                    return True
        return False

    def _should_plan_web_content_discovery(self, target: Target) -> bool:
        if not self._profile_allows_task(target, "web_content_discovery") and not target.metadata.get("allow_content_discovery"):
            return False
        evidence = self.store.list_evidence(target_id=target.id, limit=200)
        if any(
            item.metadata.get("kind") == "web_content_discovery"
            and self._evidence_matches_active_generation(target, item)
            for item in evidence
        ):
            return False
        for item in evidence:
            if not self._evidence_matches_active_generation(target, item):
                continue
            effective_url = item.metadata.get("effective_url")
            status_code = item.metadata.get("status_code")
            if isinstance(effective_url, str) and effective_url.startswith(("http://", "https://")):
                if isinstance(status_code, int) and status_code < 500:
                    return True
        return False

    def _should_plan_exploit_research(self, target: Target) -> bool:
        if not self._intent_allows_task(target, TaskKind.EXPLOIT_RESEARCH):
            return False
        evidence = self.store.list_evidence(target_id=target.id, limit=200)
        if any(
            item.metadata.get("kind") == "exploit_research"
            and self._evidence_matches_active_generation(target, item)
            for item in evidence
        ):
            return False
        signal_kinds = {
            "tcp_service_discovery",
            "dns_enumeration",
            "ad_enumeration",
            "web_content_discovery",
        }
        return any(
            item.metadata.get("kind") in signal_kinds and self._evidence_matches_active_generation(target, item)
            for item in evidence
        )

    def _should_plan_poc_applicability_validation(self, target: Target) -> bool:
        if not self._intent_allows_task(target, TaskKind.POC_APPLICABILITY_VALIDATION):
            return False
        evidence = self.store.list_evidence(target_id=target.id, limit=200)
        has_research = any(
            item.metadata.get("kind") == "exploit_research"
            and self._evidence_matches_active_generation(target, item)
            and int(item.metadata.get("match_count", 0) or 0) > 0
            for item in evidence
        )
        if not has_research:
            return False
        return not any(
            item.metadata.get("kind") == "poc_applicability_validation"
            and self._evidence_matches_active_generation(target, item)
            for item in evidence
        )

    def _should_plan_kerberos_user_discovery(self, target: Target) -> bool:
        if not self._profile_allows_task(target, "kerberos_user_discovery") and not target.metadata.get("allow_kerberos_user_discovery"):
            return False
        if not self._intent_allows_task(target, TaskKind.KERBEROS_USER_DISCOVERY):
            return False
        evidence = self.store.list_evidence(target_id=target.id, limit=200)
        if any(
            item.metadata.get("kind") == "kerberos_user_discovery"
            and self._evidence_matches_active_generation(target, item)
            for item in evidence
        ):
            return False
        return any(
            item.metadata.get("kind") == "ad_enumeration" and self._evidence_matches_active_generation(target, item)
            for item in evidence
        )

    def _should_plan_kerberos_attack_check(self, target: Target) -> bool:
        return bool(self._planned_kerberos_check_types(target))

    def _planned_kerberos_check_types(self, target: Target) -> list[str]:
        evidence = self.store.list_evidence(target_id=target.id, limit=200)
        if any(
            item.metadata.get("kind") == "kerberos_attack_check"
            and self._evidence_matches_active_generation(target, item)
            for item in evidence
        ):
            return []
        supported: set[str] = set()
        for item in evidence:
            if item.metadata.get("kind") != "kerberos_user_discovery":
                continue
            if not self._evidence_matches_active_generation(target, item):
                continue
            users = item.metadata.get("users", [])
            spns = item.metadata.get("spn_candidates", [])
            if isinstance(users, list) and users:
                supported.add("asrep_roast")
            if isinstance(spns, list) and spns:
                supported.add("kerberoast")
        if not supported:
            return []
        policy = self._active_intent_policy()
        if policy is None:
            return sorted(supported)
        allowed: set[str] = set()
        if policy.kerberos_policy.asrep_roast_check_allowed:
            allowed.add("asrep_roast")
        if policy.kerberos_policy.kerberoast_check_allowed:
            allowed.add("kerberoast")
        requested = supported.intersection(allowed)
        if requested:
            return sorted(requested)
        self._record_operator_intent_block(
            target,
            TaskKind.KERBEROS_ATTACK_CHECK,
            "kerberos_attack_check",
            "ad_lab in-house AD attack path or htb_lab",
            "active intent does not allow requested Kerberos attack-path checks: " + ", ".join(sorted(supported)),
        )
        return []

    def _should_plan_credentialed_access_check(
        self,
        target: Target,
        surface: CredentialedAccessSurface | None = None,
    ) -> bool:
        if not self._intent_allows_task(target, TaskKind.CREDENTIALED_ACCESS_CHECK):
            return False
        evidence = self.store.list_evidence(target_id=target.id, limit=200)
        if any(
            item.metadata.get("kind") == "credentialed_access_check"
            and self._evidence_matches_active_generation(target, item)
            for item in evidence
        ):
            return False
        surface = surface or self._current_credentialed_access_surface(target)
        if not surface.eligible:
            return False
        return self._known_credentials_configured()

    def _plan_analysis_if_stale(
        self,
        target: Target,
        report: OrchestrationReport,
        session_id: str | None,
    ) -> None:
        signature = self._target_analysis_signature(target)
        if self.store.task_exists(
            target.id,
            TaskKind.ANALYZE_EVIDENCE,
            statuses=(
                TaskStatus.PENDING,
                TaskStatus.RUNNING,
                TaskStatus.WAITING,
                TaskStatus.NEEDS_APPROVAL,
            ),
        ):
            return
        for task in self.store.list_tasks(target_id=target.id, limit=100):
            if task.kind != TaskKind.ANALYZE_EVIDENCE or task.status != TaskStatus.SUCCEEDED:
                continue
            if task.metadata.get("analysis_signature") == signature:
                return
        task = self._build_task(
            target.id,
            TaskKind.ANALYZE_EVIDENCE,
            "Analyze accumulated evidence",
            f"Cluster recon evidence and generate bounded hypotheses for {target.handle}.",
            session_id=session_id,
        )
        task.metadata["analysis_signature"] = signature
        self._register_task(task, target, report)

    def _target_analysis_signature(self, target: Target) -> str:
        evidence = self._current_generation_evidence(target, limit=200)
        payload = {
            "active_ip_generation": self._target_active_generation(target),
            "evidence": sorted(item.id for item in evidence),
        }
        return json.dumps(payload, sort_keys=True)

    def _plan_if_missing(
        self,
        target: Target,
        kind: TaskKind,
        title: str,
        summary: str,
        report: OrchestrationReport,
        session_id: str | None,
    ) -> None:
        active_generation = self._target_active_generation(target)
        if self._task_exists_for_current_generation(target.id, kind, active_generation):
            return
        task = self._build_task(target.id, kind, title, summary, session_id=session_id)
        if active_generation is not None:
            task.metadata["active_ip_generation"] = active_generation
            task.metadata["active_ip"] = target.metadata.get("active_ip")
        self._register_task(task, target, report)

    def _target_active_generation(self, target: Target) -> str | None:
        generation = target.metadata.get("active_ip_generation")
        if generation is None:
            return None
        return str(generation)

    def _evidence_matches_active_generation(self, target: Target, evidence) -> bool:
        active_generation = self._target_active_generation(target)
        if active_generation is None:
            return True
        return str(evidence.metadata.get("active_ip_generation", "")) == active_generation

    def _task_exists_for_current_generation(self, target_id: str, kind: TaskKind, active_generation: str | None) -> bool:
        statuses = {
            TaskStatus.PENDING,
            TaskStatus.RUNNING,
            TaskStatus.WAITING,
            TaskStatus.NEEDS_APPROVAL,
            TaskStatus.SUCCEEDED,
        }
        for task in self.store.list_tasks(target_id=target_id, limit=500):
            if task.kind != kind or task.status not in statuses:
                continue
            if active_generation is None:
                return True
            if str(task.metadata.get("active_ip_generation", "")) == active_generation:
                return True
        return False
