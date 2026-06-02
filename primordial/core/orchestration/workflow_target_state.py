from __future__ import annotations

from primordial.core.orchestration.workflow_deps import (
    classify_credentialed_access_surface,
    CredentialedAccessSurface,
    EventRecord,
    EventType,
    OperatorIntentPolicy,
    Target,
    Task,
    TaskKind,
    TaskStatus,
    utc_now,
)

class WorkflowTargetStateMixin:
    def _target_has_current_generation_evidence(self, target: Target) -> bool:
        return bool(self._current_generation_evidence(target, limit=200))

    def _current_generation_evidence(self, target: Target, *, limit: int = 200):
        return [
            item
            for item in self.store.list_evidence(target_id=target.id, limit=limit)
            if self._evidence_matches_active_generation(target, item)
        ]

    def _current_generation_tasks(self, target: Target, *, limit: int = 500) -> list[Task]:
        active_generation = self._target_active_generation(target)
        tasks = self.store.list_tasks(target_id=target.id, limit=limit)
        if active_generation is None:
            return tasks
        return [
            task
            for task in tasks
            if task.metadata.get("active_ip_generation") is None
            or str(task.metadata.get("active_ip_generation", "")) == active_generation
        ]

    def _verified_interest_count_current_generation(self, target: Target) -> int:
        return len(
            [
                item
                for item in self.store.list_interests(target_id=target.id, limit=200)
                if item.status.value == "verified" and self._record_matches_active_generation(target, item)
            ]
        )

    def _analysis_is_stale(self, target: Target) -> bool:
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
            return False
        for task in self.store.list_tasks(target_id=target.id, limit=100):
            if task.kind != TaskKind.ANALYZE_EVIDENCE or task.status != TaskStatus.SUCCEEDED:
                continue
            if task.metadata.get("analysis_signature") == signature:
                return False
        return True

    def _build_analysis_task_if_stale(self, target: Target, session_id: str | None) -> Task | None:
        if not self._analysis_is_stale(target):
            return None
        task = self._build_task(
            target.id,
            TaskKind.ANALYZE_EVIDENCE,
            "Analyze accumulated evidence",
            f"Cluster recon evidence and generate bounded hypotheses for {target.handle}.",
            session_id=session_id,
        )
        task.metadata["analysis_signature"] = self._target_analysis_signature(target)
        active_generation = self._target_active_generation(target)
        if active_generation is not None:
            task.metadata["active_ip_generation"] = active_generation
            task.metadata["active_ip"] = target.metadata.get("active_ip")
        return task

    def _lab_credentials_configured(self) -> bool:
        return self._known_credentials_configured()

    def _known_credentials_configured(self) -> bool:
        if not self.credentials_status_loader:
            return False
        status = self.credentials_status_loader()
        services = status.get("services", {}) if isinstance(status, dict) else {}
        if not isinstance(services, dict):
            return False
        return self._credential_service_has_username_password(services, "known") or self._credential_service_has_username_password(
            services,
            "lab",
        )

    def _credential_service_has_username_password(self, services: dict[str, object], service: str) -> bool:
        payload = services.get(service, {})
        if not isinstance(payload, dict):
            return False
        username = payload.get("username", {})
        password = payload.get("password", {})
        return (
            isinstance(username, dict)
            and isinstance(password, dict)
            and bool(username.get("configured"))
            and bool(password.get("configured"))
        )

    def _notion_sync_auth_blocked(self) -> bool:
        if not self.credentials_status_loader:
            return False
        try:
            status = self.credentials_status_loader()
        except Exception:
            return False
        services = status.get("services", {}) if isinstance(status, dict) else {}
        notion = services.get("notion", {}) if isinstance(services, dict) else {}
        service_status = notion.get("service_status", {}) if isinstance(notion, dict) else {}
        return bool(isinstance(service_status, dict) and service_status.get("auth_blocked"))

    def _profile_allows_task(self, target: Target, task_kind_value: str) -> bool:
        allowed = self.autonomy.profile_task_allowlist.get(target.profile.value, frozenset())
        return task_kind_value in allowed

    def _active_intent_policy(self) -> OperatorIntentPolicy | None:
        return self.active_intent_policy_loader() if self.active_intent_policy_loader else None

    def _active_intent_id(self) -> str:
        return self.active_intent_id_loader() if self.active_intent_id_loader else "recon_only"

    def _intent_allows_task(self, target: Target, kind: TaskKind) -> bool:
        policy = self._active_intent_policy()
        if policy is None:
            return True
        allowed = True
        required = ""
        reason = ""
        category = "unknown"
        if kind == TaskKind.EXPLOIT_RESEARCH:
            allowed = policy.public_poc_research and policy.searchsploit_allowed
            required = "exploit_research_allowed or htb_lab"
            category = "public_poc_research"
            reason = "active intent does not allow public PoC research"
        elif kind == TaskKind.POC_APPLICABILITY_VALIDATION:
            allowed = policy.poc_applicability_validation
            required = "exploit_research_allowed or htb_lab"
            category = "poc_applicability_validation"
            reason = "active intent does not allow public PoC applicability validation"
        elif kind == TaskKind.AD_ENUMERATION:
            allowed = policy.kerberos_policy.asrep_roast_check_allowed or policy.kerberos_policy.kerberoast_check_allowed
            required = "ad_lab in-house AD attack path or htb_lab"
            category = "ad_enumeration"
            reason = "active intent does not allow anonymous AD enumeration"
        elif kind == TaskKind.KERBEROS_ATTACK_CHECK:
            allowed = policy.kerberos_policy.asrep_roast_check_allowed or policy.kerberos_policy.kerberoast_check_allowed
            required = "ad_lab in-house AD attack path or htb_lab"
            category = "kerberos_attack_check"
            reason = "active intent does not allow Kerberos attack-path checks"
        elif kind == TaskKind.KERBEROS_USER_DISCOVERY:
            allowed = policy.kerberos_policy.asrep_roast_check_allowed or policy.kerberos_policy.kerberoast_check_allowed
            required = "ad_lab in-house AD attack path or htb_lab"
            category = "kerberos_user_discovery"
            reason = "active intent does not allow Kerberos principal discovery"
        elif kind == TaskKind.CREDENTIALED_ACCESS_CHECK:
            allowed = policy.credential_policy.credential_validation_allowed
            required = "credential_validation or htb_lab"
            category = "credentialed_access_check"
            reason = "active intent does not allow credential validation"
        if allowed:
            return True
        self._record_operator_intent_block(target, kind, category, required, reason)
        return False

    def _record_operator_intent_block(
        self,
        target: Target,
        kind: TaskKind,
        category: str,
        required_intent: str,
        reason: str,
    ) -> None:
        active_generation = self._target_active_generation(target) or "none"
        active_intent = self._active_intent_id()
        key = f"{active_generation}:{kind.value}:{active_intent}"
        blocks = target.metadata.get("operator_intent_blocks", {})
        if not isinstance(blocks, dict):
            blocks = {}
        if blocks.get(key):
            return
        blocks[key] = True
        target.metadata["operator_intent_blocks"] = blocks
        target.updated_at = utc_now()
        self.store.insert_target(target)
        self.store.insert_event(
            EventRecord(
                type=EventType.TASK_BLOCKED,
                summary=f"Operator intent blocked {kind.value}: {reason}",
                target_id=target.id,
                metadata={
                    "blocked_by_operator_intent": True,
                    "task_kind": kind.value,
                    "capability_category": category,
                    "active_intent": active_intent,
                    "required_intent": required_intent,
                    "reason": reason,
                    "active_ip_generation": active_generation,
                },
            )
        )

    def _current_credentialed_access_surface(self, target: Target) -> CredentialedAccessSurface:
        return classify_credentialed_access_surface(self._current_generation_evidence(target, limit=200))

    def _surface_has_admin_adjacent_evidence(self, surface: CredentialedAccessSurface) -> bool:
        signals = surface.signals
        return any(
            signals.get(key)
            for key in (
                "smb_evidence_ids",
                "winrm_evidence_ids",
                "ad_evidence_ids",
                "samba_evidence_ids",
            )
        )

    def _target_has_remote_admin_surface(self, evidence) -> bool:
        return classify_credentialed_access_surface(evidence).eligible

    def _poc_adaptation_available(self, capabilities: set[str]) -> bool:
        return any(
            capability in capabilities
            for capability in {
                "poc-applicability-validation",
                "poc-adaptation",
                "exploit-safety-review",
            }
        )

    def _record_matches_active_generation(self, target: Target, record: object) -> bool:
        active_generation = self._target_active_generation(target)
        if active_generation is None:
            return True
        metadata = getattr(record, "metadata", {})
        if not isinstance(metadata, dict):
            return False
        return str(metadata.get("active_ip_generation", "")) == active_generation
