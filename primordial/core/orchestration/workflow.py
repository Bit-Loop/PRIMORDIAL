from __future__ import annotations

from primordial.core.orchestration.workflow_deps import *  # noqa: F401,F403
from primordial.core.orchestration.workflow_types import (
    MemoryServiceProtocol,
    PlannedTargetAction,
    PrimitiveResolverProtocol,
    RemoteReviewAdmissionContext,
)
from primordial.core.orchestration.workflow_lifecycle import WorkflowLifecycleMixin
from primordial.core.orchestration.workflow_methodology_state import WorkflowMethodologyStateMixin
from primordial.core.orchestration.workflow_action_candidates import WorkflowActionCandidatesMixin
from primordial.core.orchestration.workflow_attack_candidates import WorkflowAttackCandidatesMixin
from primordial.core.orchestration.workflow_methodology_persistence import WorkflowMethodologyPersistenceMixin
from primordial.core.orchestration.workflow_planner_uncertainty import WorkflowPlannerUncertaintyMixin
from primordial.core.orchestration.workflow_target_state import WorkflowTargetStateMixin
from primordial.core.orchestration.workflow_ai_admission import WorkflowAiAdmissionMixin
from primordial.core.orchestration.workflow_remote_review_admission import WorkflowRemoteReviewAdmissionMixin
from primordial.core.orchestration.workflow_rag_hints import WorkflowRagHintsMixin
from primordial.core.orchestration.workflow_remote_review_utils import WorkflowRemoteReviewUtilsMixin
from primordial.core.orchestration.workflow_planning_predicates import WorkflowPlanningPredicatesMixin
from primordial.core.orchestration.workflow_task_registration import WorkflowTaskRegistrationMixin
from primordial.core.orchestration.workflow_execution_claiming import WorkflowExecutionClaimingMixin
from primordial.core.orchestration.workflow_execution_running import WorkflowExecutionRunningMixin
from primordial.core.orchestration.workflow_execution_persistence import WorkflowExecutionPersistenceMixin
from primordial.core.orchestration.workflow_exception_validation import WorkflowExceptionValidationMixin


class WorkflowOrchestrator(
    WorkflowLifecycleMixin,
    WorkflowMethodologyStateMixin,
    WorkflowActionCandidatesMixin,
    WorkflowAttackCandidatesMixin,
    WorkflowMethodologyPersistenceMixin,
    WorkflowPlannerUncertaintyMixin,
    WorkflowTargetStateMixin,
    WorkflowAiAdmissionMixin,
    WorkflowRemoteReviewAdmissionMixin,
    WorkflowRagHintsMixin,
    WorkflowRemoteReviewUtilsMixin,
    WorkflowPlanningPredicatesMixin,
    WorkflowTaskRegistrationMixin,
    WorkflowExecutionClaimingMixin,
    WorkflowExecutionRunningMixin,
    WorkflowExecutionPersistenceMixin,
    WorkflowExceptionValidationMixin,
):
    STALE_RUN_MAX_AGE_SECONDS = 3600
    REMOTE_REVIEW_KIND_BY_PRIMITIVE = {
        "tcp-service-discovery": TaskKind.SERVICE_DISCOVERY,
        "service-identification": TaskKind.SERVICE_DISCOVERY,
        "http-probe": TaskKind.RECON_SCAN,
        "dns-enumeration": TaskKind.DNS_ENUMERATION,
        "content-discovery": TaskKind.WEB_CONTENT_DISCOVERY,
        "path-enumeration": TaskKind.WEB_CONTENT_DISCOVERY,
        "ad-enumeration": TaskKind.AD_ENUMERATION,
        "smb-enumeration": TaskKind.AD_ENUMERATION,
        "ldap-enumeration": TaskKind.AD_ENUMERATION,
        "kerberos-user-discovery": TaskKind.KERBEROS_USER_DISCOVERY,
        "principal-discovery": TaskKind.KERBEROS_USER_DISCOVERY,
        "kerberos-attack-check": TaskKind.KERBEROS_ATTACK_CHECK,
        "credentialed-access-check": TaskKind.CREDENTIALED_ACCESS_CHECK,
        "smb-session": TaskKind.CREDENTIALED_ACCESS_CHECK,
        "winrm": TaskKind.CREDENTIALED_ACCESS_CHECK,
        "searchsploit-research": TaskKind.EXPLOIT_RESEARCH,
        "exploit-research": TaskKind.EXPLOIT_RESEARCH,
        "poc-applicability-validation": TaskKind.POC_APPLICABILITY_VALIDATION,
        "poc-adaptation": TaskKind.POC_APPLICABILITY_VALIDATION,
        "hypothesis-analysis": TaskKind.ANALYZE_EVIDENCE,
        "evidence-analysis": TaskKind.ANALYZE_EVIDENCE,
        "finding-verification": TaskKind.VERIFY_HYPOTHESIS,
        "chain-review": TaskKind.CHAIN_CANDIDATES,
        "chain-reasoning": TaskKind.CHAIN_CANDIDATES,
    }
    RAG_HINT_CORPUS_TYPES = {"cve_advisory", "exploit_note", "htb_writeup"}
    AI_PROPOSAL_MATERIALIZED_KINDS = frozenset(
        {
            TaskKind.RECON_SCAN,
            TaskKind.SERVICE_DISCOVERY,
            TaskKind.DNS_ENUMERATION,
            TaskKind.WEB_CONTENT_DISCOVERY,
        }
    )

    def __init__(
        self,
        store: RuntimeStore,
        policy_engine: PolicyEngine,
        provider_router: ProviderRouter,
        model_scheduler: ModelScheduler,
        memory_service_loader: Callable[[], MemoryServiceProtocol],
        verifier: BehaviorVerifier,
        primitive_resolver_loader: Callable[[], PrimitiveResolverProtocol],
        worker_broker: WorkerBroker,
        validation_registry: ValidationRegistry,
        resume_tracker: ResumeTracker,
        autonomy: AutonomySettings,
        checkpoints_dir: Path,
        credentials_status_loader: Callable[[], dict[str, object]] | None = None,
        active_intent_policy_loader: Callable[[], OperatorIntentPolicy] | None = None,
        active_intent_id_loader: Callable[[], str] | None = None,
        rag_context_builder: Callable[..., dict[str, object]] | None = None,
        resource_status_loader: Callable[[], dict[str, object]] | None = None,
        resource_reserve_loader: Callable[[], dict[str, object]] | None = None,
        event_bus: EventBus | None = None,
    ) -> None:
        self.store = store
        self.policy_engine = policy_engine
        self.provider_router = provider_router
        self.model_scheduler = model_scheduler
        self.memory_service_loader = memory_service_loader
        self.verifier = verifier
        self.primitive_resolver_loader = primitive_resolver_loader
        self.worker_broker = worker_broker
        self.validation_registry = validation_registry
        self.resume_tracker = resume_tracker
        self.autonomy = autonomy
        self.checkpoints_dir = checkpoints_dir
        self.credentials_status_loader = credentials_status_loader
        self.active_intent_policy_loader = active_intent_policy_loader
        self.active_intent_id_loader = active_intent_id_loader
        self.rag_context_builder = rag_context_builder
        self.resource_status_loader = resource_status_loader
        self.resource_reserve_loader = resource_reserve_loader
        self.event_bus = event_bus
        self.stale_run_max_age_seconds = self.STALE_RUN_MAX_AGE_SECONDS
