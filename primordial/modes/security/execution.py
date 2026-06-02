from __future__ import annotations

from primordial.modes.security.execution_common import *
from primordial.modes.security.execution_recon_handler import PrimitiveReconHandlerMixin
from primordial.modes.security.execution_service_handler import PrimitiveServiceHandlerMixin
from primordial.modes.security.execution_content_handler import PrimitiveContentHandlerMixin
from primordial.modes.security.execution_dns_handler import PrimitiveDnsHandlerMixin
from primordial.modes.security.execution_ad_handler import PrimitiveAdHandlerMixin
from primordial.modes.security.execution_kerberos_handlers import PrimitiveKerberosHandlerMixin
from primordial.modes.security.execution_credential_handler import PrimitiveCredentialHandlerMixin
from primordial.modes.security.execution_exploit_handler import PrimitiveExploitHandlerMixin
from primordial.modes.security.execution_poc_handler import PrimitivePocHandlerMixin
from primordial.modes.security.execution_analysis_handlers import PrimitiveAnalysisHandlerMixin
from primordial.modes.security.execution_verification_handlers import PrimitiveVerificationHandlerMixin
from primordial.modes.security.execution_misc_handlers import PrimitiveMiscHandlerMixin
from primordial.modes.security.execution_ai_review import PrimitiveAiReviewMixin
from primordial.modes.security.execution_generation_records import PrimitiveGenerationRecordMixin
from primordial.modes.security.execution_service_tools import PrimitiveServiceToolMixin
from primordial.modes.security.execution_web_tools import PrimitiveWebToolMixin
from primordial.modes.security.execution_dns_tools import PrimitiveDnsToolMixin
from primordial.modes.security.execution_command_tools import PrimitiveCommandToolMixin
from primordial.modes.security.execution_searchsploit_queries import PrimitiveSearchsploitQueryMixin
from primordial.modes.security.execution_searchsploit_runtime import PrimitiveSearchsploitRuntimeMixin
from primordial.modes.security.execution_poc_tools import PrimitivePocToolMixin
from primordial.modes.security.execution_ad_parsing import PrimitiveAdParsingMixin
from primordial.modes.security.execution_kerberos_user_tools import PrimitiveKerberosUserToolMixin
from primordial.modes.security.execution_kerberos_attack_tools import PrimitiveKerberosAttackToolMixin
from primordial.modes.security.execution_credential_tools import PrimitiveCredentialToolMixin
from primordial.modes.security.execution_probe_tools import PrimitiveProbeToolMixin

__all__ = ["AiGenerateCallable", "PrimitiveExecutor"]


class PrimitiveExecutor(PrimitiveReconHandlerMixin, PrimitiveServiceHandlerMixin, PrimitiveContentHandlerMixin, PrimitiveDnsHandlerMixin, PrimitiveAdHandlerMixin, PrimitiveKerberosHandlerMixin, PrimitiveCredentialHandlerMixin, PrimitiveExploitHandlerMixin, PrimitivePocHandlerMixin, PrimitiveAnalysisHandlerMixin, PrimitiveVerificationHandlerMixin, PrimitiveMiscHandlerMixin, PrimitiveAiReviewMixin, PrimitiveGenerationRecordMixin, PrimitiveServiceToolMixin, PrimitiveWebToolMixin, PrimitiveDnsToolMixin, PrimitiveCommandToolMixin, PrimitiveSearchsploitQueryMixin, PrimitiveSearchsploitRuntimeMixin, PrimitivePocToolMixin, PrimitiveAdParsingMixin, PrimitiveKerberosUserToolMixin, PrimitiveKerberosAttackToolMixin, PrimitiveCredentialToolMixin, PrimitiveProbeToolMixin):
    def __init__(
        self,
        store: RuntimeStore,
        catalog: PrimitiveCatalog,
        config: AppConfig,
        credentials: CredentialStore,
        ai_generate: AiGenerateCallable | None = None,
        active_intent_policy_loader: Callable[[], OperatorIntentPolicy] | None = None,
        active_intent_id_loader: Callable[[], str] | None = None,
    ) -> None:
        self.store = store
        self.catalog = catalog
        self.config = config
        self.credentials = credentials
        self.ai_generate = ai_generate
        self.active_intent_policy_loader = active_intent_policy_loader
        self.active_intent_id_loader = active_intent_id_loader

    def execute(self, task: Task, context: ContextSlice | None) -> TaskExecutionResult:
        handler = getattr(self, f"_handle_{task.kind.value}", self._handle_generic)
        return handler(task, context)

    def _active_intent_policy(self) -> OperatorIntentPolicy | None:
        return self.active_intent_policy_loader() if self.active_intent_policy_loader else None

    def _active_intent_id(self) -> str:
        return self.active_intent_id_loader() if self.active_intent_id_loader else "recon_only"

    def _blocked_by_intent_result(
        self,
        task: Task,
        *,
        capability_category: str,
        required_intent: str,
        reason: str,
    ) -> TaskExecutionResult:
        active_intent = self._active_intent_id()
        return TaskExecutionResult(
            success=False,
            summary=f"blocked by operator intent: {reason}",
            error=reason,
            events=[
                EventRecord(
                    type=EventType.TASK_BLOCKED,
                    summary=f"Operator intent blocked {task.kind.value}: {reason}",
                    target_id=task.target_id,
                    task_id=task.id,
                    metadata={
                        "blocked_by_operator_intent": True,
                        "task_kind": task.kind.value,
                        "capability_category": capability_category,
                        "active_intent": active_intent,
                        "required_intent": required_intent,
                        "reason": reason,
                    },
                )
            ],
        )

    def _require_intent(self, task: Task) -> TaskExecutionResult | None:
        policy = self._active_intent_policy()
        if policy is None:
            return None
        if task.kind == TaskKind.EXPLOIT_RESEARCH:
            if not (policy.public_poc_research and policy.searchsploit_allowed):
                return self._blocked_by_intent_result(
                    task,
                    capability_category="public_poc_research",
                    required_intent="exploit_research_allowed or htb_lab",
                    reason="active intent does not allow searchsploit public PoC research",
                )
        elif task.kind == TaskKind.POC_APPLICABILITY_VALIDATION:
            if not policy.poc_applicability_validation:
                return self._blocked_by_intent_result(
                    task,
                    capability_category="poc_applicability_validation",
                    required_intent="exploit_research_allowed or htb_lab",
                    reason="active intent does not allow public PoC applicability validation",
                )
        elif task.kind == TaskKind.KERBEROS_USER_DISCOVERY:
            if not (policy.kerberos_policy.asrep_roast_check_allowed or policy.kerberos_policy.kerberoast_check_allowed):
                return self._blocked_by_intent_result(
                    task,
                    capability_category="kerberos_user_discovery",
                    required_intent="ad_lab in-house AD attack path or htb_lab",
                    reason="active intent does not allow Kerberos principal discovery",
                )
        elif task.kind == TaskKind.KERBEROS_ATTACK_CHECK:
            requested = self._requested_kerberos_checks(task)
            if "asrep_roast" in requested and not policy.kerberos_policy.asrep_roast_check_allowed:
                return self._blocked_by_intent_result(
                    task,
                    capability_category="asrep_roast_check",
                    required_intent="ad_lab in-house AD attack path or htb_lab",
                    reason="active intent does not allow AS-REP roast checks",
                )
            if "kerberoast" in requested and not policy.kerberos_policy.kerberoast_check_allowed:
                return self._blocked_by_intent_result(
                    task,
                    capability_category="kerberoast_check",
                    required_intent="ad_lab in-house AD attack path or htb_lab",
                    reason="active intent does not allow Kerberoast candidate checks",
                )
        elif task.kind == TaskKind.CREDENTIALED_ACCESS_CHECK:
            if not policy.credential_policy.credential_validation_allowed:
                return self._blocked_by_intent_result(
                    task,
                    capability_category="credentialed_access_check",
                    required_intent="credential_validation or htb_lab",
                    reason="active intent does not allow credential validation",
                )
        return None

    def _requested_kerberos_checks(self, task: Task) -> set[str]:
        raw = task.metadata.get("kerberos_checks")
        if isinstance(raw, str):
            requested = {raw.strip().lower()}
        elif isinstance(raw, list):
            requested = {str(item).strip().lower() for item in raw}
        else:
            requested = {"asrep_roast", "kerberoast"}
        aliases = {
            "asrep": "asrep_roast",
            "asrep_roast_check": "asrep_roast",
            "kerberoast_check": "kerberoast",
            "spn_candidate_review": "kerberoast",
        }
        normalized = {aliases.get(item, item) for item in requested if item}
        return normalized.intersection({"asrep_roast", "kerberoast"}) or {"asrep_roast", "kerberoast"}

    def resolve_primitives(self, task: Task) -> list[PrimitiveManifest]:
        selected: dict[str, PrimitiveManifest] = {}
        hinted = primitives_for_hint(self.catalog.all(), task.metadata.get("primitive_hint"))
        if hinted:
            return hinted
        for capability in task.required_capabilities:
            for manifest in self.catalog.by_capability(capability):
                selected.setdefault(manifest.name, manifest)
        return list(selected.values())

    def _manifest_timeout(self, task: Task, fallback: int) -> int:
        primitives = self.resolve_primitives(task)
        if primitives:
            return primitives[0].timeout_seconds
        return fallback
