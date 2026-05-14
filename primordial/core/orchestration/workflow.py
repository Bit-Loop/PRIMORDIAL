from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
from datetime import timedelta
from pathlib import Path
from typing import Callable, Protocol

from primordial.core.config import AutonomySettings
from primordial.core.domain.constants import AD_INDICATOR_PORTS, DNS_PORTS
from primordial.core.domain.enums import (
    AgentRole,
    CheckpointKind,
    EventType,
    ExternalSyncKind,
    NotificationChannel,
    NotificationStatus,
    PolicyVerdict,
    MethodologyPhase,
    ProviderRoute,
    TaskKind,
    TaskRunStatus,
    TaskStatus,
)
from primordial.core.domain.models import (
    AgentTrace,
    CheckpointRecord,
    DocumentChunk,
    EscalationPackage,
    EventRecord,
    ExternalSyncJob,
    NotificationRecord,
    OrchestrationReport,
    PrimitiveManifest,
    Target,
    TargetMethodologyState,
    Task,
    TaskExecutionResult,
    TaskRun,
    utc_now,
)
from primordial.core.evidence import CredentialedAccessSurface, classify_credentialed_access_surface
from primordial.core.events.bus import EventBus, RuntimeSignal
from primordial.core.intent.models import OperatorIntentPolicy
from primordial.core.orchestration.policy import PolicyEngine
from primordial.core.orchestration.verifier import BehaviorVerifier
from primordial.core.providers.router import ProviderRouter
from primordial.core.providers.scheduler import ModelScheduler
from primordial.core.recovery.resume_tracker import ResumeTracker
from primordial.core.storage.runtime import RuntimeStore
from primordial.core.validation import ValidationContext, ValidationRegistry, ValidationStage
from primordial.core.workers import WorkerBroker
from primordial.modes.security.methodology import blueprint_for


class MemoryServiceProtocol(Protocol):
    def needs_compaction(self, target_id: str) -> bool: ...

    def build_context_slice(self, target_id: str, role: AgentRole): ...

    def compact_target(self, target_id: str): ...

    def apply_freshness_decay(self, target_id: str) -> None: ...


class PrimitiveResolverProtocol(Protocol):
    def resolve_primitives(self, task: Task) -> list[PrimitiveManifest]: ...


@dataclass(slots=True, frozen=True)
class PlannedTargetAction:
    kind: TaskKind
    title: str
    summary: str
    confidence: float
    phase_label: str
    subphase: str
    transition_reason: str
    prerequisite: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)


class WorkflowOrchestrator:
    STALE_RUN_MAX_AGE_SECONDS = 3600
    REMOTE_REVIEW_KIND_BY_PRIMITIVE = {
        "tcp-service-discovery": TaskKind.SERVICE_DISCOVERY,
        "service-identification": TaskKind.SERVICE_DISCOVERY,
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
        self.resource_status_loader = resource_status_loader
        self.resource_reserve_loader = resource_reserve_loader
        self.event_bus = event_bus
        self.stale_run_max_age_seconds = self.STALE_RUN_MAX_AGE_SECONDS

    def preview_target_state(self, target: Target) -> TargetMethodologyState:
        return self._evaluate_target_methodology_state(target)

    def recover_stale_execution_state(self, *, limit: int = 500) -> int:
        recovered = 0
        now = utc_now()
        tasks_by_id = {task.id: task for task in self.store.list_tasks(limit=limit)}
        for run in self.store.list_task_runs(limit=limit):
            if run.status not in {TaskRunStatus.CLAIMED, TaskRunStatus.RUNNING} or run.finished_at is not None:
                continue
            task = tasks_by_id.get(run.task_id)
            reason = self._stale_run_reason(task, run, now)
            if reason is None:
                continue
            run.status = TaskRunStatus.CANCELLED
            run.error = f"recovered stale execution state: {reason}"
            run.finished_at = now
            run.heartbeat_at = now
            run.metadata["recovered_stale_execution"] = True
            run.metadata["recovery_reason"] = reason
            self.store.insert_task_run(run)
            if task is not None:
                task.metadata["recovered_stale_execution"] = True
                task.metadata["recovery_reason"] = reason
                if task.status == TaskStatus.RUNNING:
                    task.status = TaskStatus.PENDING if task.attempts < task.max_attempts else TaskStatus.FAILED
                task.updated_at = now
                self.store.insert_task(task)
            self.store.insert_trace(
                AgentTrace(
                    task_id=run.task_id,
                    role=task.role if task is not None else AgentRole.ORCHESTRATOR,
                    status="failed",
                    summary=f"Recovered stale execution state: {reason}",
                    metadata={"recovered_stale_execution": True, "recovery_reason": reason},
                )
            )
            self.store.insert_event(
                EventRecord(
                    type=EventType.TASK_FAILED,
                    summary=f"Recovered stale execution state for {task.title if task else run.task_id}",
                    target_id=task.target_id if task is not None else None,
                    task_id=run.task_id,
                    metadata={"reason": reason, "recovered_stale_execution": True},
                )
            )
            recovered += 1
        return recovered

    def tick(self, max_executions: int = 3) -> OrchestrationReport:
        report = OrchestrationReport()
        self.recover_stale_execution_state(limit=500)
        self.resume_tracker.resume_due_tasks(limit=200)
        targets = self.store.list_targets()
        active_session = self.store.get_active_session()

        for target in targets:
            self._plan_target(target, active_session.id if active_session else None, report)

        signals = self.verifier.inspect(
            tasks=self.store.list_tasks(limit=500),
            traces=self.store.list_traces(limit=200),
            evidence=self.store.list_evidence(limit=200),
            targets=targets,
            interests=self.store.list_interests(limit=200),
            findings=self.store.list_findings(limit=100),
            events=self.store.list_events(limit=200),
        )
        for signal in signals:
            if self._verifier_signal_already_handled(signal):
                continue
            if self.store.has_active_task(signal.target_id, TaskKind.VERIFY_AGENT_BEHAVIOR):
                continue
            self._register_task(
                self._build_task(
                    target_id=signal.target_id,
                    kind=TaskKind.VERIFY_AGENT_BEHAVIOR,
                    title="Review agent behavior",
                    summary=signal.reason,
                    session_id=active_session.id if active_session else None,
                ),
                self.store.get_target(signal.target_id),
                report,
            )

        self._execute_ready_tasks(report, max_executions=max_executions)
        return report

    def approve_task(self, task_id: str, approved: bool) -> Task | None:
        task = self.store.get_task(task_id)
        if not task or task.status != TaskStatus.NEEDS_APPROVAL:
            return task
        action = "approved" if approved else "denied"
        if task.metadata.get("proposal_only"):
            task.status = TaskStatus.SUCCEEDED if approved else TaskStatus.CANCELLED
            task.requires_approval = False
            task.updated_at = utc_now()
            task.metadata = {
                **task.metadata,
                "proposal_resolved": True,
                "proposal_approved": bool(approved),
                "proposal_resolved_at": task.updated_at.isoformat(),
            }
            event_type = EventType.APPROVAL_GRANTED if approved else EventType.APPROVAL_DENIED
            self.store.insert_task(task)
            self.store.insert_event(
                EventRecord(
                    type=event_type,
                    summary=f"UI command proposal {action}: {task.title}",
                    target_id=task.target_id,
                    task_id=task.id,
                    metadata={"proposal_only": True, "ui_command": task.metadata.get("ui_command")},
                )
            )
            return task
        if approved and task.kind == TaskKind.CREDENTIALED_ACCESS_CHECK:
            target = self.store.get_target(task.target_id) if task.target_id else None
            block_reason = self._credentialed_access_task_block_reason(task, target)
            if block_reason:
                self._invalidate_task(task, block_reason, event_summary=f"Task approval blocked: {task.title}")
                return task
        if approved and task.kind == TaskKind.REVIEW_PREMIUM_ESCALATION:
            if task.metadata.get("remote_premium_policy_approval_required"):
                task.metadata["remote_premium_operator_approved"] = True
                task.metadata["remote_premium_operator_approved_at"] = utc_now().isoformat()
        if approved:
            task.updated_at = utc_now()
            task.metadata = {
                **task.metadata,
                "operator_approved": True,
                "operator_approved_at": task.updated_at.isoformat(),
            }
            task.status = TaskStatus.PENDING
            task.requires_approval = False
            event_type = EventType.APPROVAL_GRANTED
        else:
            task.status = TaskStatus.CANCELLED
            event_type = EventType.APPROVAL_DENIED
        self.store.insert_task(task)
        self.store.insert_event(
            EventRecord(
                type=event_type,
                summary=f"Task {action}: {task.title}",
                target_id=task.target_id,
                task_id=task.id,
            )
        )
        return task

    def approve_all_safe_tasks(self, *, limit: int = 200) -> dict[str, object]:
        approved: list[str] = []
        skipped: list[dict[str, str]] = []
        for task in self.store.list_tasks(statuses=[TaskStatus.NEEDS_APPROVAL], limit=limit):
            if task.metadata.get("proposal_only"):
                skipped.append({"task_id": task.id, "reason": "proposal-only UI command requires explicit approval"})
                continue
            target = self.store.get_target(task.target_id) if task.target_id else None
            decision = self.policy_engine.evaluate_task(task, target)
            self.store.insert_policy_decision(decision)
            if decision.verdict != PolicyVerdict.ALLOW:
                skipped.append({"task_id": task.id, "reason": decision.reason})
                continue
            task.status = TaskStatus.PENDING
            task.requires_approval = False
            task.updated_at = utc_now()
            task.metadata = {
                **task.metadata,
                "batch_safe_approved": True,
                "batch_safe_approved_at": task.updated_at.isoformat(),
                "batch_safe_approval_reason": decision.reason,
            }
            self.store.insert_task(task)
            self.store.insert_event(
                EventRecord(
                    type=EventType.APPROVAL_GRANTED,
                    summary=f"Safe task batch-approved: {task.title}",
                    target_id=task.target_id,
                    task_id=task.id,
                    metadata={"batch_safe_approved": True, "reason": decision.reason},
                )
            )
            approved.append(task.id)
        return {"approved": approved, "skipped": skipped, "approved_count": len(approved), "skipped_count": len(skipped)}

    def _plan_target(self, target: Target, session_id: str | None, report: OrchestrationReport) -> None:
        if not target.handle.strip():
            self._record_invalid_target_block(target, report)
            return
        invalidated_tasks = self._invalidate_contradicted_credentialed_access_tasks(target, report)
        methodology_state = self._evaluate_target_methodology_state(target)
        self._persist_target_methodology_state(target, methodology_state, report)
        planned_any = False
        for action in methodology_state.candidate_actions:
            kind = TaskKind(str(action["kind"]))
            if kind == TaskKind.ANALYZE_EVIDENCE:
                task = self._build_analysis_task_if_stale(target, session_id)
                if task is None:
                    continue
                self._register_task(task, target, report)
                planned_any = True
                continue
            task = self._build_task(
                target.id,
                kind,
                str(action["title"]),
                str(action["summary"]),
                session_id=session_id,
            )
            active_generation = self._target_active_generation(target)
            if active_generation is not None:
                task.metadata["active_ip_generation"] = active_generation
                task.metadata["active_ip"] = target.metadata.get("active_ip")
            action_metadata = dict(action.get("metadata", {}))
            task.metadata.update(action_metadata)
            supporting_refs = action_metadata.get("evidence_refs") or action_metadata.get("supporting_evidence_refs")
            if isinstance(supporting_refs, list):
                task.evidence_refs = [str(item) for item in supporting_refs if str(item).strip()]
            self._register_task(task, target, report)
            planned_any = True
        if not planned_any and methodology_state.no_progress_reason:
            self._record_no_progress_state(target, methodology_state, report)
        uncertainty = self._planner_uncertainty_reasons(target, methodology_state, invalidated_tasks)
        if uncertainty:
            self.create_planner_uncertainty_escalation(
                target,
                reason_code="planner_uncertainty",
                question=self._planner_uncertainty_question(target, methodology_state),
                blockers=list(methodology_state.blockers),
                rejected_proposals=methodology_state.metadata.get("ai_proposal_admission", {}).get("rejected", []),
                invalid_existing_tasks=invalidated_tasks,
                session_id=session_id,
                report=report,
                uncertainty_reasons=uncertainty,
            )

    def _evaluate_target_methodology_state(self, target: Target) -> TargetMethodologyState:
        active_generation = self._target_active_generation(target)
        evidence = self._current_generation_evidence(target)
        tasks = self._current_generation_tasks(target)
        waiting_or_active = [
            task
            for task in tasks
            if task.status in {TaskStatus.PENDING, TaskStatus.RUNNING, TaskStatus.WAITING, TaskStatus.NEEDS_APPROVAL}
        ]
        candidate_actions = self._methodology_candidate_actions(target)
        remote_review_admission = self._evaluate_remote_review_admission(target)
        candidate_actions.extend(remote_review_admission["actions"])
        rag_hint_admission = self._evaluate_rag_hint_admission(target)
        candidate_actions.extend(rag_hint_admission["actions"])
        blockers = self._methodology_blockers(target, evidence)
        ai_admission = self._evaluate_ai_proposal_admission(tasks)
        if ai_admission["rejected"]:
            blockers.extend(
                f"AI proposal rejected: {item['title']} ({item['reason']})"
                for item in ai_admission["rejected"][:3]
            )
        if remote_review_admission["rejected"]:
            blockers.extend(
                f"Remote premium recommendation rejected: {item['title']} ({item['reason']})"
                for item in remote_review_admission["rejected"][:3]
            )
        if rag_hint_admission["rejected"]:
            blockers.extend(
                f"RAG hint rejected: {item['title']} ({item['reason']})"
                for item in rag_hint_admission["rejected"][:3]
            )
        verified_interests = self._verified_interest_count_current_generation(target)
        retry_budget = {
            task.kind.value: max(0, task.max_attempts - task.attempts)
            for task in tasks
            if task.status in {TaskStatus.PENDING, TaskStatus.RUNNING, TaskStatus.WAITING, TaskStatus.NEEDS_APPROVAL, TaskStatus.FAILED}
        }

        if candidate_actions:
            lead = candidate_actions[0]
            phase = blueprint_for(lead.kind).phase
            completion = "candidate_actions_ready"
            transition_reason = lead.transition_reason
            subphase = lead.subphase
        elif waiting_or_active:
            lead_task = waiting_or_active[0]
            phase = lead_task.phase
            subphase = lead_task.kind.value
            completion = "waiting_on_existing_tasks"
            transition_reason = f"Existing {lead_task.status.value} task is already covering the next methodology step."
        elif not evidence:
            phase = blueprint_for(TaskKind.RECON_SCAN).phase
            subphase = "bootstrap"
            completion = "blocked"
            transition_reason = "No current-generation target evidence is available yet."
        elif self._memory_service().needs_compaction(target.id):
            phase = blueprint_for(TaskKind.COMPACT_MEMORY).phase
            subphase = TaskKind.COMPACT_MEMORY.value
            completion = "memory_maintenance_due"
            transition_reason = "Memory maintenance is due, but an equivalent task is already satisfied or waiting."
        elif verified_interests >= 2:
            phase = blueprint_for(TaskKind.CHAIN_CANDIDATES).phase
            subphase = "chain_backlog"
            completion = "steady_state"
            transition_reason = "Verified exploit-chain inputs exist, but no new chain action is currently admissible."
        elif verified_interests >= 1:
            phase = blueprint_for(TaskKind.VERIFY_HYPOTHESIS).phase
            subphase = "verification_backlog"
            completion = "steady_state"
            transition_reason = "A verified hypothesis exists, but no new bounded verification action is currently admissible."
        else:
            phase = blueprint_for(TaskKind.ANALYZE_EVIDENCE).phase
            subphase = "analysis_backlog"
            completion = "steady_state"
            transition_reason = "No new methodology transition is currently admissible from the current evidence."

        next_unblock_action = blockers[0] if blockers else None
        no_progress_reason = None
        if not candidate_actions and not waiting_or_active:
            no_progress_reason = blockers[0] if blockers else transition_reason

        return TargetMethodologyState(
            phase=phase,
            subphase=subphase,
            completion=completion,
            transition_reason=transition_reason,
            candidate_actions=[
                {
                    "kind": item.kind.value,
                    "title": item.title,
                    "summary": item.summary,
                    "confidence": item.confidence,
                    "phase": item.phase_label,
                    "subphase": item.subphase,
                    "transition_reason": item.transition_reason,
                    "prerequisite": item.prerequisite,
                    "metadata": dict(item.metadata),
                }
                for item in candidate_actions
            ],
            blockers=blockers,
            next_unblock_action=next_unblock_action,
            no_progress_reason=no_progress_reason,
            retry_budget=retry_budget,
            metadata={
                "active_ip_generation": active_generation,
                "current_generation_evidence_count": len(evidence),
                "waiting_task_count": len(waiting_or_active),
                "verified_interest_count": verified_interests,
                "ai_proposal_admission": ai_admission,
                "remote_review_admission": {
                    "accepted": remote_review_admission["accepted"],
                    "rejected": remote_review_admission["rejected"],
                },
                "rag_hint_admission": {
                    "accepted": rag_hint_admission["accepted"],
                    "rejected": rag_hint_admission["rejected"],
                },
            },
        )

    def _methodology_candidate_actions(self, target: Target) -> list[PlannedTargetAction]:
        actions: list[PlannedTargetAction] = []

        def add(
            kind: TaskKind,
            title: str,
            summary: str,
            *,
            confidence: float,
            subphase: str,
            transition_reason: str,
            prerequisite: str | None = None,
            metadata: dict[str, object] | None = None,
        ) -> None:
            active_generation = self._target_active_generation(target)
            if kind != TaskKind.ANALYZE_EVIDENCE and self._task_exists_for_current_generation(target.id, kind, active_generation):
                return
            actions.append(
                PlannedTargetAction(
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
            )

        if not self._target_has_current_generation_evidence(target):
            add(
                TaskKind.RECON_SCAN,
                "Run recon sweep",
                f"Collect initial recon evidence for {target.handle}.",
                confidence=0.95,
                subphase="bootstrap",
                transition_reason="No current-generation evidence exists for the active target generation.",
            )
            if self._should_plan_service_discovery(target):
                add(
                    TaskKind.SERVICE_DISCOVERY,
                    "Run bounded service discovery",
                    f"Collect TCP service inventory evidence for {target.handle}.",
                    confidence=0.93,
                    subphase="service_inventory",
                    transition_reason="A fresh active-IP generation needs service inventory before deeper branching.",
                )
            return actions

        if self._should_plan_service_discovery(target):
            add(
                TaskKind.SERVICE_DISCOVERY,
                "Run bounded service discovery",
                f"Collect TCP service inventory evidence for {target.handle}.",
                confidence=0.93,
                subphase="service_inventory",
                transition_reason="Fresh service inventory is missing for the active target generation.",
            )
        if self._should_plan_dns_enumeration(target):
            add(
                TaskKind.DNS_ENUMERATION,
                "Run bounded DNS enumeration",
                f"Collect DNS records and zone-transfer evidence for {target.handle}.",
                confidence=0.88,
                subphase="dns_inventory",
                transition_reason="Port and host evidence indicates DNS is present and unresolved for the current generation.",
                prerequisite="current-generation service discovery",
            )
        if self._should_plan_web_content_discovery(target):
            add(
                TaskKind.WEB_CONTENT_DISCOVERY,
                "Run bounded web content discovery",
                f"Discover HTTP paths and virtual directories for {target.handle}.",
                confidence=0.87,
                subphase="web_surface",
                transition_reason="HTTP evidence exists without bounded content-discovery coverage for the current generation.",
                prerequisite="current-generation HTTP probe evidence",
            )
        if self._should_plan_ad_enumeration(target):
            add(
                TaskKind.AD_ENUMERATION,
                "Run bounded AD enumeration",
                f"Collect anonymous SMB/LDAP/RPC inventory for {target.handle}.",
                confidence=0.89,
                subphase="ad_inventory",
                transition_reason="Current-generation service evidence exposes AD-adjacent ports without corresponding AD inventory.",
                prerequisite="current-generation service discovery",
            )
        if self._should_plan_kerberos_user_discovery(target):
            add(
                TaskKind.KERBEROS_USER_DISCOVERY,
                "Run Kerberos/LDAP user discovery",
                f"Discover candidate AD/Kerberos principals for {target.handle}.",
                confidence=0.83,
                subphase="principal_discovery",
                transition_reason="AD evidence exists, but current-generation principal discovery has not run yet.",
                prerequisite="current-generation AD enumeration",
            )
        if self._analysis_is_stale(target):
            add(
                TaskKind.ANALYZE_EVIDENCE,
                "Analyze accumulated evidence",
                f"Cluster recon evidence and generate bounded hypotheses for {target.handle}.",
                confidence=0.9,
                subphase="evidence_review",
                transition_reason="The current evidence signature has not been analyzed yet.",
                prerequisite="current-generation recon evidence",
            )
        if self._should_plan_exploit_research(target):
            add(
                TaskKind.EXPLOIT_RESEARCH,
                "Research relevant public PoCs",
                f"Search local exploit references for evidence-backed services on {target.handle}.",
                confidence=0.81,
                subphase="exploit_research",
                transition_reason="Current-generation recon evidence supports public exploit research triage.",
                prerequisite="current-generation service or AD evidence",
            )
        if self._should_plan_poc_applicability_validation(target):
            add(
                TaskKind.POC_APPLICABILITY_VALIDATION,
                "Validate public PoC applicability",
                (
                    "Classify retained public exploit references against exact service/version evidence, "
                    f"foothold prerequisites, and policy gates for {target.handle}."
                ),
                confidence=0.79,
                subphase="poc_gating",
                transition_reason="Retained public PoC research exists, but deterministic applicability gating has not run.",
                prerequisite="current-generation exploit research",
            )
        kerberos_checks = self._planned_kerberos_check_types(target)
        if kerberos_checks:
            add(
                TaskKind.KERBEROS_ATTACK_CHECK,
                "Run Kerberos attack-path checks",
                f"Check allowed Kerberos attack-path applicability for discovered principals on {target.handle}.",
                confidence=0.76,
                subphase="kerberos_attack_path",
                transition_reason="Current-generation principal evidence supports bounded Kerberos attack-path checks.",
                prerequisite="current-generation principal discovery",
                metadata={"kerberos_checks": kerberos_checks},
            )
        credential_surface = self._current_credentialed_access_surface(target)
        if self._should_plan_credentialed_access_check(target, credential_surface):
            add(
                TaskKind.CREDENTIALED_ACCESS_CHECK,
                "Verify credentialed Windows SMB/WinRM access",
                f"Use configured known credentials to verify evidence-supported Windows access for {target.handle}.",
                confidence=0.75,
                subphase="credentialed_verification",
                transition_reason="Operator-configured known credentials are present and current evidence supports Windows SMB/WinRM or AD/DC access.",
                prerequisite="configured known credentials and current-generation Windows SMB/WinRM or AD/DC evidence",
                metadata={
                    "credential_namespace": "known",
                    "credentialed_access_surface": credential_surface.as_payload(),
                    "protocols": list(credential_surface.protocols),
                    "os_family": credential_surface.os_family,
                    "evidence_refs": list(credential_surface.evidence_refs),
                },
            )
        verified_interests = self._verified_interest_count_current_generation(target)
        if verified_interests >= 1:
            add(
                TaskKind.VERIFY_HYPOTHESIS,
                "Verify prioritized hypothesis",
                f"Run bounded verification for a high-value hypothesis on {target.handle}.",
                confidence=0.71,
                subphase="bounded_verification",
                transition_reason="At least one current-generation verified interest exists and deserves bounded verification planning.",
                prerequisite="current-generation verified interest",
            )
        if verified_interests >= 2:
            add(
                TaskKind.CHAIN_CANDIDATES,
                "Review exploit-chain candidates",
                f"Review related verified interests for possible exploit chains on {target.handle}.",
                confidence=0.67,
                subphase="chain_review",
                transition_reason="Multiple current-generation verified interests may support exploit-chain review.",
                prerequisite="two or more current-generation verified interests",
            )
        if self._memory_service().needs_compaction(target.id):
            add(
                TaskKind.COMPACT_MEMORY,
                "Compact notes and memory",
                f"Promote durable memory and compact noisy context for {target.handle}.",
                confidence=0.64,
                subphase="memory_maintenance",
                transition_reason="Memory service indicates the current target context needs compaction.",
            )
        return actions

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

    def _persist_target_methodology_state(
        self,
        target: Target,
        state: TargetMethodologyState,
        report: OrchestrationReport,
    ) -> None:
        previous_state = target.metadata.get("methodology_state", {})
        previous_payload = previous_state if isinstance(previous_state, dict) else {}
        payload = state.as_payload()
        payload["planner_version"] = 2
        payload["fingerprint"] = json.dumps(
            {
                "phase": payload["phase"],
                "subphase": payload["subphase"],
                "completion": payload["completion"],
                "candidate_actions": payload["candidate_actions"],
                "blockers": payload["blockers"],
                "no_progress_reason": payload["no_progress_reason"],
            },
            sort_keys=True,
        )
        target.metadata["methodology_state"] = payload
        target.updated_at = utc_now()
        self.store.insert_target(target)
        if previous_payload.get("fingerprint") != payload["fingerprint"]:
            event = EventRecord(
                type=EventType.TASK_PLANNED,
                summary=f"Methodology state updated: {state.phase.value}/{state.subphase}",
                target_id=target.id,
                metadata={
                    "phase": state.phase.value,
                    "subphase": state.subphase,
                    "completion": state.completion,
                    "candidate_actions": len(state.candidate_actions),
                },
            )
            self.store.insert_event(event)
            report.events.append(event)

    def _record_no_progress_state(
        self,
        target: Target,
        state: TargetMethodologyState,
        report: OrchestrationReport,
    ) -> None:
        current_state = target.metadata.get("methodology_state", {})
        if not isinstance(current_state, dict):
            return
        no_progress_key = json.dumps(
            {
                "reason": state.no_progress_reason,
                "next_unblock_action": state.next_unblock_action,
                "phase": state.phase.value,
                "subphase": state.subphase,
            },
            sort_keys=True,
        )
        if current_state.get("last_no_progress_key") == no_progress_key:
            return
        current_state["last_no_progress_key"] = no_progress_key
        target.metadata["methodology_state"] = current_state
        target.updated_at = utc_now()
        self.store.insert_target(target)
        event = EventRecord(
            type=EventType.NO_PROGRESS,
            summary=state.no_progress_reason or "No admissible methodology transition is currently available.",
            target_id=target.id,
            metadata={
                "phase": state.phase.value,
                "subphase": state.subphase,
                "next_unblock_action": state.next_unblock_action,
                "blockers": list(state.blockers),
            },
        )
        self.store.insert_event(event)
        report.events.append(event)

    def _record_invalid_target_block(self, target: Target, report: OrchestrationReport) -> None:
        if target.metadata.get("planner_invalid_target_blocked"):
            return
        target.metadata["planner_invalid_target_blocked"] = True
        target.updated_at = utc_now()
        self.store.insert_target(target)
        event = EventRecord(
            type=EventType.TASK_BLOCKED,
            summary="Planner skipped invalid target: target handle is empty",
            target_id=target.id,
            metadata={
                "invalid_target": True,
                "reason": "target handle is empty",
            },
        )
        self.store.insert_event(event)
        report.events.append(event)

    def _invalidate_contradicted_credentialed_access_tasks(
        self,
        target: Target,
        report: OrchestrationReport,
    ) -> list[dict[str, object]]:
        invalidated: list[dict[str, object]] = []
        for task in self.store.list_tasks(target_id=target.id, limit=500):
            if task.kind != TaskKind.CREDENTIALED_ACCESS_CHECK:
                continue
            if task.status not in {TaskStatus.PENDING, TaskStatus.WAITING, TaskStatus.NEEDS_APPROVAL}:
                continue
            reason = self._credentialed_access_task_block_reason(task, target)
            if not reason:
                continue
            event = self._invalidate_task(
                task,
                reason,
                event_summary=f"Credentialed access task invalidated: {task.title}",
            )
            report.events.append(event)
            invalidated.append(
                {
                    "task_id": task.id,
                    "title": task.title,
                    "status": task.status.value,
                    "reason": reason,
                }
            )
        return invalidated

    def _credentialed_access_task_block_reason(self, task: Task, target: Target | None) -> str:
        if target is None:
            return "target record is missing"
        active_generation = self._target_active_generation(target)
        if active_generation is not None:
            task_generation = task.metadata.get("active_ip_generation")
            if str(task_generation or "") != active_generation:
                return "task was planned for a stale target evidence generation"
        policy = self._active_intent_policy()
        if policy is not None and not policy.credential_policy.credential_validation_allowed:
            return "active operator intent does not allow credential validation"
        surface = self._current_credentialed_access_surface(target)
        if not surface.eligible:
            return surface.blocked_reason or "current evidence does not support Windows SMB/WinRM credential validation"
        task_protocols = {
            str(item).strip().lower()
            for item in task.metadata.get("protocols", [])
            if str(item).strip()
        } if isinstance(task.metadata.get("protocols"), list) else set()
        if task_protocols and not task_protocols.intersection(surface.protocols):
            return "task protocols no longer match the current credentialed-access surface"
        current_refs = {item.id for item in self._current_generation_evidence(target, limit=500)}
        if task.evidence_refs and not set(task.evidence_refs).issubset(current_refs):
            return "task evidence references are not current for the active target generation"
        return ""

    def _invalidate_task(self, task: Task, reason: str, *, event_summary: str) -> EventRecord:
        task.status = TaskStatus.BLOCKED
        task.requires_approval = False
        task.updated_at = utc_now()
        task.metadata["invalidated_by_planner"] = True
        task.metadata["invalidation_reason"] = reason
        self.store.insert_task(task)
        event = EventRecord(
            type=EventType.TASK_BLOCKED,
            summary=event_summary,
            target_id=task.target_id,
            task_id=task.id,
            metadata={"reason": reason, "invalidated_by_planner": True},
        )
        self.store.insert_event(event)
        return event

    def _planner_uncertainty_reasons(
        self,
        target: Target,
        state: TargetMethodologyState,
        invalidated_tasks: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        reasons: list[dict[str, object]] = []
        if invalidated_tasks:
            reasons.append(
                {
                    "code": "contradictory_existing_task",
                    "summary": "Current evidence contradicted an existing credentialed-access task or approval.",
                    "tasks": invalidated_tasks,
                }
            )
        ai_admission = state.metadata.get("ai_proposal_admission", {})
        accepted = ai_admission.get("accepted", []) if isinstance(ai_admission, dict) else []
        rejected = ai_admission.get("rejected", []) if isinstance(ai_admission, dict) else []
        if rejected and not accepted:
            reasons.append(
                {
                    "code": "all_ai_proposals_rejected",
                    "summary": "All AI-proposed actions lacked registered primitive mappings.",
                    "rejected": rejected,
                }
            )
        if (
            not state.candidate_actions
            and int(state.metadata.get("current_generation_evidence_count", 0) or 0) > 0
            and int(state.metadata.get("waiting_task_count", 0) or 0) == 0
            and state.no_progress_reason
        ):
            reasons.append(
                {
                    "code": "no_admissible_next_task",
                    "summary": "Live evidence exists, but no admissible next task is derivable.",
                    "no_progress_reason": state.no_progress_reason,
                }
            )
        return reasons

    def _planner_uncertainty_question(self, target: Target, state: TargetMethodologyState) -> str:
        return (
            f"What is the next valid, evidence-linked task for {target.handle} under "
            f"operator intent {self._active_intent_id()}? Classify invalid existing tasks and missing evidence, "
            "but do not approve credential use, expand scope, execute tools, or override Operator Intent."
        )

    def create_planner_uncertainty_escalation(
        self,
        target: Target,
        *,
        reason_code: str,
        question: str,
        blockers: list[str] | None = None,
        rejected_proposals: object | None = None,
        invalid_existing_tasks: list[dict[str, object]] | None = None,
        session_id: str | None = None,
        report: OrchestrationReport | None = None,
        uncertainty_reasons: list[dict[str, object]] | None = None,
    ) -> Task | None:
        evidence = self._current_generation_evidence(target, limit=200)
        if not evidence:
            return None
        if self.store.has_active_task(target.id, TaskKind.REVIEW_PREMIUM_ESCALATION):
            return None
        evidence_ids = [item.id for item in evidence]
        reason_payload = uncertainty_reasons or [{"code": reason_code, "summary": question}]
        key = json.dumps(
            {
                "reason_code": reason_code,
                "question": question,
                "evidence_ids": evidence_ids,
                "reasons": reason_payload,
            },
            sort_keys=True,
        )
        if target.metadata.get("last_planner_uncertainty_escalation_key") == key:
            return None

        task = self._build_task(
            target_id=target.id,
            kind=TaskKind.REVIEW_PREMIUM_ESCALATION,
            title=(
                "Escalate uncertain planner state to Claude/GPT"
                if not self.autonomy.allow_remote_premium
                else "Premium planner review requested"
            ),
            summary="Resolve an evidence-linked planner uncertainty without bypassing policy.",
            session_id=session_id,
        )
        task.evidence_refs = evidence_ids
        active_generation = self._target_active_generation(target)
        if active_generation is not None:
            task.metadata["active_ip_generation"] = active_generation
            task.metadata["active_ip"] = target.metadata.get("active_ip")
        surface = classify_credentialed_access_surface(evidence)
        packet = self._planner_review_packet(
            target,
            evidence=evidence,
            surface=surface,
            question=question,
            blockers=blockers or [],
            rejected_proposals=rejected_proposals if isinstance(rejected_proposals, list) else [],
            invalid_existing_tasks=invalid_existing_tasks or [],
            uncertainty_reasons=reason_payload,
        )
        package = EscalationPackage(
            task_id=task.id,
            target_id=target.id,
            mode="planner_uncertainty_review",
            reason="; ".join(str(item.get("summary") or item.get("code") or reason_code) for item in reason_payload[:4]),
            expected_value="Recover a valid next action while preserving deterministic task admission.",
            cost_tier="remote_premium",
            question=question,
            evidence_refs=evidence_ids,
            evidence_summaries=[f"{item.id}: {item.title} - {item.summary[:240]}" for item in evidence[:12]],
            disagreement_signal=reason_code,
            expected_output_type="planner_remote_review_v1",
            metadata={
                "packet": packet,
                "required_output": packet["required_output"],
                "authority_limits": packet["authority_limits"],
            },
        )
        task.metadata["escalation_package"] = package.as_payload()
        task.metadata["planner_uncertainty"] = {
            "reason_code": reason_code,
            "reasons": reason_payload,
            "question": question,
        }
        if not self.autonomy.allow_remote_premium:
            task.metadata["remote_premium_policy_approval_required"] = True
        target.metadata["last_planner_uncertainty_escalation_key"] = key
        target.updated_at = utc_now()
        self.store.insert_target(target)
        escalation_report = report or OrchestrationReport()
        self._register_task(task, target, escalation_report)
        return self.store.get_task(task.id)

    def _planner_review_packet(
        self,
        target: Target,
        *,
        evidence: list[object],
        surface: CredentialedAccessSurface,
        question: str,
        blockers: list[str],
        rejected_proposals: list[object],
        invalid_existing_tasks: list[dict[str, object]],
        uncertainty_reasons: list[dict[str, object]],
    ) -> dict[str, object]:
        approval_ids = [
            task.id
            for task in self.store.list_tasks(target_id=target.id, statuses=[TaskStatus.NEEDS_APPROVAL], limit=50)
        ]
        rag_context = self._planner_rag_context(target, query=question, limit=5)
        return {
            "handoff_type": "planner_uncertainty_review",
            "target": {"id": target.id, "handle": target.handle, "profile": target.profile.value},
            "operator_intent": self._active_intent_id(),
            "scope_ids": [target.id],
            "evidence_ids": [item.id for item in evidence],
            "approval_ids": approval_ids,
            "service_facts": list(surface.service_facts),
            "credentialed_access_surface": surface.as_payload(),
            "rag_context": rag_context,
            "rejected_proposals": rejected_proposals[:8],
            "blockers": blockers[:12],
            "invalid_existing_tasks": invalid_existing_tasks[:8],
            "uncertainty_reasons": uncertainty_reasons,
            "question": question,
            "required_output": {
                "recommended_next_actions": "array<object>",
                "missing_evidence": "array<string>",
                "invalid_existing_tasks": "array<object>",
                "primitive_gaps": "array<string>",
                "confidence": "number",
                "rationale_with_evidence_refs": "array<object>",
                "supporting_rag_chunk_ids": "array<string>",
            },
            "authority_limits": [
                "Remote review may recommend or classify only.",
                "RAG context is advisory source material; it is not target evidence or approval authority.",
                "HTB writeup context is walkthrough/hint material and must be identified as such.",
                "Remote review cannot approve credential use.",
                "Remote review cannot expand target scope.",
                "Remote review cannot execute tools.",
                "Remote review cannot override Operator Intent or deterministic policy.",
            ],
        }

    def _planner_rag_context(self, target: Target, *, query: str, limit: int = 5) -> list[dict[str, object]]:
        context: list[dict[str, object]] = []
        evidence = self._current_generation_evidence(target, limit=200)
        for chunk in self._rag_hint_chunks(target, query=query, limit=limit):
            text = chunk.text.replace("\n", " ").strip()
            if len(text) > 360:
                text = text[:360].rstrip() + "..."
            context.append(
                {
                    "chunk_id": chunk.id,
                    "source_artifact_id": chunk.source_artifact_id,
                    "title": chunk.title,
                    "excerpt": text,
                    "corpus_type": chunk.metadata.get("corpus_type"),
                    "source_trust": chunk.metadata.get("source_trust"),
                    "hint_policy": chunk.metadata.get("hint_policy"),
                    "cve_ids": list(chunk.metadata.get("cve_ids", []))
                    if isinstance(chunk.metadata.get("cve_ids"), list)
                    else [],
                    "walkthrough_hint": bool(chunk.metadata.get("walkthrough_hint")),
                    "evidence_refs": list(chunk.evidence_refs),
                    "applicability_classification": self._rag_applicability_classification(chunk, evidence),
                }
            )
        return context

    def _stale_run_reason(self, task: Task | None, run: TaskRun, now) -> str | None:
        if task is None:
            return "task record is missing"
        if task.status != TaskStatus.RUNNING:
            return f"task status is {task.status.value}"
        last_seen = run.heartbeat_at or run.started_at
        age_seconds = (now - last_seen).total_seconds()
        if age_seconds > self.stale_run_max_age_seconds:
            return f"no execution heartbeat for {int(age_seconds)}s"
        return None

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
        elif kind == TaskKind.KERBEROS_ATTACK_CHECK:
            allowed = policy.kerberos_policy.asrep_roast_check_allowed or policy.kerberos_policy.kerberoast_check_allowed
            required = "ad_lab in-house AD attack path or htb_lab"
            category = "kerberos_attack_check"
            reason = "active intent does not allow Kerberos attack-path checks"
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
                primitive_hint = str(action.get("primitive_hint") or "").strip().lower()
                if primitive_hint and (primitive_hint in available_primitives or primitive_hint in available_capabilities):
                    accepted.append(
                        {
                            "task_id": task.id,
                            "title": title,
                            "primitive_hint": primitive_hint,
                        }
                    )
                else:
                    rejected.append(
                        {
                            "task_id": task.id,
                            "title": title,
                            "primitive_hint": primitive_hint,
                            "reason": "missing primitive mapping" if primitive_hint else "no primitive hint supplied",
                        }
                    )
        return {"accepted": accepted[:8], "rejected": rejected[:8]}

    def _evaluate_remote_review_admission(self, target: Target) -> dict[str, object]:
        evidence = self._current_generation_evidence(target, limit=200)
        current_evidence_ids = {item.id for item in evidence}
        review_records = [
            item
            for item in evidence
            if str(item.metadata.get("kind") or "").lower()
            in {"premium_review_result", "planner_remote_review", "remote_premium_review"}
        ]
        if not review_records:
            return {"actions": [], "accepted": [], "rejected": []}
        primitives = self.store.list_primitives()
        available = {
            value.lower()
            for primitive in primitives
            for value in [primitive.name, *primitive.capability_tags]
        }
        actions: list[PlannedTargetAction] = []
        accepted: list[dict[str, object]] = []
        rejected: list[dict[str, object]] = []
        active_generation = self._target_active_generation(target)
        surface = self._current_credentialed_access_surface(target)
        for record in review_records:
            review = self._remote_review_payload(record.metadata)
            missing_fields = [
                field
                for field in (
                    "recommended_next_actions",
                    "missing_evidence",
                    "invalid_existing_tasks",
                    "primitive_gaps",
                    "confidence",
                    "rationale_with_evidence_refs",
                )
                if field not in review
            ]
            if missing_fields:
                rejected.append(
                    {
                        "review_evidence_id": record.id,
                        "title": record.title,
                        "reason": "remote review response missing required fields: " + ", ".join(missing_fields),
                    }
                )
                continue
            recommendations = review.get("recommended_next_actions")
            if not isinstance(recommendations, list):
                rejected.append(
                    {
                        "review_evidence_id": record.id,
                        "title": record.title,
                        "reason": "recommended_next_actions is not a list",
                    }
                )
                continue
            rationale_refs = self._review_rationale_evidence_refs(review.get("rationale_with_evidence_refs"))
            for recommendation in recommendations[:8]:
                if not isinstance(recommendation, dict):
                    rejected.append(
                        {
                            "review_evidence_id": record.id,
                            "title": str(recommendation)[:80],
                            "reason": "recommended action is not an object",
                        }
                    )
                    continue
                title = str(recommendation.get("title") or recommendation.get("action") or "untitled action").strip()
                reason = self._remote_review_action_reject_reason(
                    target=target,
                    recommendation=recommendation,
                    available=available,
                    current_evidence_ids=current_evidence_ids,
                    rationale_refs=rationale_refs,
                    surface=surface,
                )
                primitive_hint = self._normalized_primitive_hint(recommendation)
                task_kind = self.REMOTE_REVIEW_KIND_BY_PRIMITIVE.get(primitive_hint)
                action_refs = self._remote_review_action_refs(recommendation, rationale_refs)
                if reason:
                    rejected.append(
                        {
                            "review_evidence_id": record.id,
                            "title": title,
                            "primitive_hint": primitive_hint,
                            "reason": reason,
                        }
                    )
                    continue
                assert task_kind is not None
                if task_kind != TaskKind.ANALYZE_EVIDENCE and self._task_exists_for_current_generation(target.id, task_kind, active_generation):
                    rejected.append(
                        {
                            "review_evidence_id": record.id,
                            "title": title,
                            "primitive_hint": primitive_hint,
                            "reason": "equivalent current-generation task already exists",
                        }
                    )
                    continue
                confidence = self._float_between_0_1(recommendation.get("confidence"), review.get("confidence"))
                summary = str(recommendation.get("summary") or recommendation.get("rationale") or title)
                actions.append(
                    PlannedTargetAction(
                        kind=task_kind,
                        title=title,
                        summary=summary,
                        confidence=confidence,
                        phase_label=blueprint_for(task_kind).phase.value,
                        subphase=f"remote_review:{task_kind.value}",
                        transition_reason=(
                            "Remote premium review recommended this action, and deterministic admission "
                            "validated primitive, evidence, scope, policy, and Operator Intent gates."
                        ),
                        prerequisite=str(recommendation.get("prerequisite") or "current-generation evidence refs"),
                        metadata={
                            "remote_review_admitted": True,
                            "source_review_evidence_id": record.id,
                            "primitive_hint": primitive_hint,
                            "evidence_refs": action_refs,
                            "supporting_evidence_refs": action_refs,
                        },
                    )
                )
                accepted.append(
                    {
                        "review_evidence_id": record.id,
                        "title": title,
                        "primitive_hint": primitive_hint,
                        "task_kind": task_kind.value,
                        "evidence_refs": action_refs,
                    }
                )
        return {"actions": actions[:6], "accepted": accepted[:8], "rejected": rejected[:12]}

    def build_rag_task_hints(self, target: Target, *, query: str = "", limit: int = 8) -> dict[str, object]:
        return self._evaluate_rag_hint_admission(target, query=query, limit=limit)

    def _evaluate_rag_hint_admission(self, target: Target, *, query: str = "", limit: int = 8) -> dict[str, object]:
        evidence = self._current_generation_evidence(target, limit=200)
        current_evidence_ids = {item.id for item in evidence}
        chunks = self._rag_hint_chunks(target, query=query, limit=limit)
        if not chunks:
            return {"actions": [], "accepted": [], "rejected": []}
        primitives = self.store.list_primitives()
        available = {
            value.lower()
            for primitive in primitives
            for value in [primitive.name, *primitive.capability_tags]
        }
        active_generation = self._target_active_generation(target)
        surface = self._current_credentialed_access_surface(target)
        actions: list[PlannedTargetAction] = []
        accepted: list[dict[str, object]] = []
        rejected: list[dict[str, object]] = []
        for chunk in chunks:
            recommendation, local_reject = self._rag_hint_recommendation(target, chunk, evidence)
            title = str(recommendation.get("title") if recommendation else chunk.title)
            corpus_type = str(chunk.metadata.get("corpus_type") or "operator_note")
            if local_reject:
                rejected.append(
                    {
                        "rag_chunk_id": chunk.id,
                        "title": title,
                        "corpus_type": corpus_type,
                        "reason": local_reject,
                    }
                )
                continue
            assert recommendation is not None
            reason = self._remote_review_action_reject_reason(
                target=target,
                recommendation=recommendation,
                available=available,
                current_evidence_ids=current_evidence_ids,
                rationale_refs=[],
                surface=surface,
            )
            primitive_hint = self._normalized_primitive_hint(recommendation)
            task_kind = self.REMOTE_REVIEW_KIND_BY_PRIMITIVE.get(primitive_hint)
            action_refs = self._remote_review_action_refs(recommendation, [])
            if reason:
                rejected.append(
                    {
                        "rag_chunk_id": chunk.id,
                        "title": title,
                        "corpus_type": corpus_type,
                        "primitive_hint": primitive_hint,
                        "reason": reason,
                    }
                )
                continue
            assert task_kind is not None
            if task_kind != TaskKind.ANALYZE_EVIDENCE and self._task_exists_for_current_generation(target.id, task_kind, active_generation):
                rejected.append(
                    {
                        "rag_chunk_id": chunk.id,
                        "title": title,
                        "corpus_type": corpus_type,
                        "primitive_hint": primitive_hint,
                        "reason": "equivalent current-generation task already exists",
                    }
                )
                continue
            confidence = self._float_between_0_1(recommendation.get("confidence"), 0.68)
            classification = str(recommendation.get("applicability_classification") or "unknown")
            summary = str(recommendation.get("summary") or recommendation.get("rationale") or title)
            metadata = {
                "rag_hint_admitted": True,
                "source_rag_chunk_id": chunk.id,
                "source_rag_artifact_id": chunk.source_artifact_id,
                "rag_corpus_type": corpus_type,
                "rag_source_trust": chunk.metadata.get("source_trust"),
                "rag_hint_policy": chunk.metadata.get("hint_policy"),
                "rag_walkthrough_hint": corpus_type == "htb_writeup",
                "rag_applicability_classification": classification,
                "rag_cve_ids": list(chunk.metadata.get("cve_ids", [])) if isinstance(chunk.metadata.get("cve_ids"), list) else [],
                "primitive_hint": primitive_hint,
                "evidence_refs": action_refs,
                "supporting_evidence_refs": action_refs,
                "supporting_rag_chunk_ids": [chunk.id],
            }
            actions.append(
                PlannedTargetAction(
                    kind=task_kind,
                    title=title,
                    summary=summary,
                    confidence=confidence,
                    phase_label=blueprint_for(task_kind).phase.value,
                    subphase=f"rag_hint:{task_kind.value}",
                    transition_reason=(
                        "RAG direct task hint was citation-bound and deterministic admission validated "
                        "current evidence, primitive coverage, scope, policy, and Operator Intent gates."
                    ),
                    prerequisite="current-generation evidence plus cited RAG chunk",
                    metadata=metadata,
                )
            )
            accepted.append(
                {
                    "rag_chunk_id": chunk.id,
                    "title": title,
                    "corpus_type": corpus_type,
                    "primitive_hint": primitive_hint,
                    "task_kind": task_kind.value,
                    "evidence_refs": action_refs,
                    "applicability_classification": classification,
                }
            )
        return {"actions": actions[:6], "accepted": accepted[:8], "rejected": rejected[:12]}

    def _rag_hint_chunks(self, target: Target, *, query: str, limit: int) -> list[DocumentChunk]:
        terms = {
            token
            for token in re.findall(r"[A-Za-z0-9_.:/-]+", query.lower())
            if len(token) > 2
        }
        chunks = [
            chunk
            for chunk in self.store.list_document_chunks(target_id=target.id, limit=500)
            if str(chunk.metadata.get("corpus_type") or "") in self.RAG_HINT_CORPUS_TYPES
            and str(chunk.metadata.get("hint_policy") or "direct_task_hints") == "direct_task_hints"
        ]
        if not terms:
            return chunks[:limit]
        ranked: list[tuple[float, DocumentChunk]] = []
        for chunk in chunks:
            chunk_terms = {
                token
                for token in re.findall(r"[A-Za-z0-9_.:/-]+", f"{chunk.title}\n{chunk.text}".lower())
                if len(token) > 2
            }
            overlap = terms & chunk_terms
            score = len(overlap) / max(1, len(terms))
            ranked.append((score, chunk))
        ranked.sort(key=lambda item: (-item[0], item[1].created_at, item[1].chunk_index))
        return [chunk for _score, chunk in ranked[:limit]]

    def _rag_hint_recommendation(
        self,
        target: Target,
        chunk: DocumentChunk,
        evidence: list[object],
    ) -> tuple[dict[str, object] | None, str]:
        corpus_type = str(chunk.metadata.get("corpus_type") or "")
        primitive_hint = self._rag_hint_primitive(chunk)
        if not primitive_hint:
            return None, "RAG chunk does not imply a supported primitive hint"
        if not evidence:
            return None, "RAG direct hints require current-generation target evidence"
        classification = self._rag_applicability_classification(chunk, evidence)
        if classification == "rejected":
            return None, "RAG applicability classified rejected"
        evidence_refs = [str(item.id) for item in evidence[:8] if getattr(item, "id", None)]
        cve_ids = chunk.metadata.get("cve_ids", [])
        cve_label = ", ".join(str(item) for item in cve_ids[:3]) if isinstance(cve_ids, list) and cve_ids else ""
        if corpus_type == "htb_writeup":
            title = f"HTB writeup hint: {chunk.title}"
            summary = (
                "Operator-enabled HTB writeup material suggests this next step. "
                "Treat this as walkthrough guidance only; current evidence and policy remain authoritative."
            )
        elif primitive_hint == "poc-applicability-validation":
            title = f"RAG CVE applicability review: {cve_label or chunk.title}"
            summary = (
                "CVE/exploit RAG material should be checked against current service/version evidence "
                f"before any execution path. Applicability is currently {classification}."
            )
        else:
            title = f"RAG exploit research hint: {chunk.title}"
            summary = "Exploit/CVE RAG material suggests a bounded research or triage step."
        return (
            {
                "title": title[:180],
                "summary": summary,
                "primitive_hint": primitive_hint,
                "target": target.handle,
                "evidence_refs": evidence_refs,
                "confidence": 0.72 if classification == "likely" else 0.62,
                "applicability_classification": classification,
            },
            "",
        )

    def _rag_hint_primitive(self, chunk: DocumentChunk) -> str:
        metadata_hint = str(chunk.metadata.get("primitive_hint") or "").strip().lower().replace("_", "-")
        if metadata_hint:
            return metadata_hint
        corpus_type = str(chunk.metadata.get("corpus_type") or "")
        text = f"{chunk.title}\n{chunk.text}".lower()
        if corpus_type in {"cve_advisory", "exploit_note"}:
            if re.search(r"\b(cve-\d{4}-\d{4,7}|poc|exploit|vulnerab|searchsploit)\b", text):
                return "poc-applicability-validation"
            return "exploit-research"
        if corpus_type == "htb_writeup":
            if re.search(r"\b(ffuf|feroxbuster|gobuster|dirsearch|directory|content discovery|hidden path|endpoint)\b", text):
                return "content-discovery"
            if re.search(r"\b(vhost|virtual host|subdomain|zone transfer|dns)\b", text):
                return "dns-enumeration"
            if re.search(r"\b(smb|ldap|rpc|active directory|domain controller)\b", text):
                return "ad-enumeration"
            if re.search(r"\b(kerberos|asrep|kerberoast|principal)\b", text):
                return "kerberos-attack-check"
            if re.search(r"\b(credential|winrm|evil-winrm|psexec|smb login)\b", text):
                return "credentialed-access-check"
            if re.search(r"\b(cve-\d{4}-\d{4,7}|poc|exploit|searchsploit)\b", text):
                return "poc-applicability-validation"
        return ""

    def _rag_applicability_classification(self, chunk: DocumentChunk, evidence: list[object]) -> str:
        override = str(chunk.metadata.get("applicability_classification") or "").strip().lower()
        if override in {"likely", "unknown", "rejected"}:
            return override
        text = f"{chunk.title}\n{chunk.text}".lower()
        if re.search(r"\b(not affected|unaffected|does not affect|not vulnerable|outside (the )?version range)\b", text):
            return "rejected"
        corpus_type = str(chunk.metadata.get("corpus_type") or "")
        if corpus_type == "htb_writeup":
            return "unknown"
        evidence_terms = self._rag_evidence_terms(evidence)
        chunk_terms = {
            token
            for token in re.findall(r"[A-Za-z0-9_.:/-]+", text)
            if len(token) > 2
        }
        service_terms = {
            "openssh",
            "ssh",
            "nginx",
            "apache",
            "httpd",
            "iis",
            "tomcat",
            "wordpress",
            "smb",
            "samba",
            "ldap",
            "kerberos",
            "windows",
            "linux",
            "php",
            "node",
            "express",
            "nagios",
            "jenkins",
            "postgres",
            "mysql",
            "mssql",
        }
        if (evidence_terms & chunk_terms & service_terms) and re.search(r"\b(cve-\d{4}-\d{4,7}|poc|exploit|vulnerab)\b", text):
            return "likely"
        return "unknown"

    def _rag_evidence_terms(self, evidence: list[object]) -> set[str]:
        blob = "\n".join(json.dumps(getattr(item, "as_payload", lambda: {})(), sort_keys=True, default=str).lower() for item in evidence)
        return {
            token
            for token in re.findall(r"[A-Za-z0-9_.:/-]+", blob)
            if len(token) > 2
        }

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
        return str(raw or "").strip().lower().replace("_", "-")

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
        tasks = self._current_generation_tasks(target, limit=200)
        payload = {
            "evidence": sorted(item.id for item in evidence),
            "blocked_or_failed_tasks": sorted(
                task.id
                for task in tasks
                if task.kind != TaskKind.ANALYZE_EVIDENCE
                and task.status in {TaskStatus.BLOCKED, TaskStatus.FAILED, TaskStatus.WAITING}
            ),
            "task_count": len([task for task in tasks if task.kind != TaskKind.ANALYZE_EVIDENCE]),
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

    def _build_task(
        self,
        target_id: str | None,
        kind: TaskKind,
        title: str,
        summary: str,
        session_id: str | None,
    ) -> Task:
        blueprint = blueprint_for(kind)
        task = Task(
            target_id=target_id,
            session_id=session_id,
            phase=blueprint.phase,
            kind=kind,
            title=title,
            summary=summary,
            role=blueprint.role,
            required_capabilities=list(blueprint.capabilities),
            priority=blueprint.default_priority,
            risk_tier=blueprint.risk_tier,
            max_attempts=min(blueprint.max_attempts, self.autonomy.max_auto_retries),
            metadata={"autonomy_mode": self.autonomy.mode.value},
        )
        task.metadata["operator_intent_id"] = self._active_intent_id()
        route = self.provider_router.select_route(task)
        task.provider_route = route.route
        task.provider_model = route.model_name
        task.metadata["provider_rationale"] = route.rationale
        task.metadata["cold_path"] = route.cold_path
        return task

    def _register_task(self, task: Task, target: Target | None, report: OrchestrationReport) -> None:
        validation_issues = self.validation_registry.validate(
            ValidationStage.TASK_REGISTRATION,
            ValidationContext(
                task=task,
                target=target,
                store=self.store,
                primitives=self._stored_primitives_for_task(task),
            ),
        )
        self._apply_validation_annotations(task, validation_issues)
        if any(issue.blocks_progress for issue in validation_issues):
            self._record_validation_failure(
                task,
                validation_issues,
                report,
                stage=ValidationStage.TASK_REGISTRATION,
                track_created=True,
            )
            return
        auto_approved = self._maybe_auto_approve_agent_chat_premium_review(task)
        decision = self.policy_engine.evaluate_task(task, target)
        self.policy_engine.apply_decision_to_task(task, decision)
        self.store.insert_task(task)
        self.store.insert_policy_decision(decision)
        report.created_tasks.append(task)
        report.decisions.append(decision)
        self.store.insert_event(
            EventRecord(
                type=(
                    EventType.TASK_NEEDS_APPROVAL
                    if task.status == TaskStatus.NEEDS_APPROVAL
                    else EventType.TASK_BLOCKED
                    if task.status == TaskStatus.BLOCKED
                    else EventType.TASK_PLANNED
                ),
                summary=f"{task.kind.value}: {task.title}",
                target_id=task.target_id,
                task_id=task.id,
                metadata={"status": task.status.value, "reason": decision.reason},
            )
        )
        if auto_approved and task.status != TaskStatus.BLOCKED:
            approval_event = EventRecord(
                type=EventType.APPROVAL_GRANTED,
                summary=f"Auto-approved agent_chat_api planner premium review: {task.title}",
                target_id=task.target_id,
                task_id=task.id,
                metadata={
                    "auto_approved": True,
                    "auto_approval_source": "agent_chat_api_wrapper",
                    "task_kind": task.kind.value,
                },
            )
            self.store.insert_event(approval_event)
            report.events.append(approval_event)
        if self.event_bus is not None:
            self.event_bus.emit(
                RuntimeSignal.TASK_PLANNED,
                {"task_id": task.id, "target_id": task.target_id, "status": task.status.value},
            )
        if task.status == TaskStatus.NEEDS_APPROVAL:
            self.store.insert_notification(
                NotificationRecord(
                    channel=NotificationChannel.DISCORD,
                    event_type="approval_needed",
                    summary=f"Approval required: {task.title}",
                    target_id=task.target_id,
                    task_id=task.id,
                    urgency="high",
                    dedupe_key=f"approval:{task.id}",
                )
            )

    def _maybe_auto_approve_agent_chat_premium_review(self, task: Task) -> bool:
        if not self._is_agent_chat_planner_review_auto_approval_candidate(task):
            return False
        approved_at = utc_now().isoformat()
        task.metadata.update(
            {
                "remote_premium_operator_approved": True,
                "remote_premium_operator_approved_at": approved_at,
                "operator_approved": True,
                "operator_approved_at": approved_at,
                "auto_approved": True,
                "auto_approval_source": "agent_chat_api_wrapper",
            }
        )
        task.requires_approval = False
        return True

    def _is_agent_chat_planner_review_auto_approval_candidate(self, task: Task) -> bool:
        if task.kind != TaskKind.REVIEW_PREMIUM_ESCALATION:
            return False
        if task.phase != MethodologyPhase.ANALYSIS:
            return False
        if task.role != AgentRole.CLAUDE_REVIEWER:
            return False
        if task.provider_route != ProviderRoute.REMOTE_PREMIUM:
            return False
        if not task.metadata.get("remote_premium_policy_approval_required"):
            return False
        if not self.worker_broker.has_runner_for(
            route=ProviderRoute.REMOTE_PREMIUM,
            kind=TaskKind.REVIEW_PREMIUM_ESCALATION,
            role=AgentRole.CLAUDE_REVIEWER,
            runner_id="agent-chat-premium-runner",
        ):
            return False
        package = task.metadata.get("escalation_package")
        if not isinstance(package, dict):
            return False
        if package.get("mode") != "planner_uncertainty_review":
            return False
        if package.get("expected_output_type") != "planner_remote_review_v1":
            return False
        package_metadata = package.get("metadata")
        if not isinstance(package_metadata, dict):
            return False
        packet = package_metadata.get("packet")
        if not isinstance(packet, dict):
            return False
        if packet.get("handoff_type") != "planner_uncertainty_review":
            return False
        required_output = packet.get("required_output")
        if not isinstance(required_output, dict):
            return False
        expected_keys = {
            "recommended_next_actions",
            "missing_evidence",
            "invalid_existing_tasks",
            "primitive_gaps",
            "confidence",
            "rationale_with_evidence_refs",
        }
        if not expected_keys.issubset(required_output):
            return False
        authority_limits = packet.get("authority_limits")
        if not isinstance(authority_limits, list):
            return False
        limit_text = "\n".join(str(item).lower() for item in authority_limits)
        for required_limit in (
            "cannot approve credential use",
            "cannot expand target scope",
            "cannot execute tools",
            "cannot override operator intent",
        ):
            if required_limit not in limit_text:
                return False
        return True

    def _execute_ready_tasks(self, report: OrchestrationReport, max_executions: int) -> None:
        for _ in range(max_executions):
            task = self.store.claim_next_pending_task()
            if not task:
                return
            target = self.store.get_target(task.target_id)
            if self._execution_target_is_invalid(task, target, report):
                continue
            resource_block = self._resource_reserve_block(task)
            if resource_block is not None:
                self.resume_tracker.defer_task(
                    task,
                    str(resource_block["reason"]),
                    delay_seconds=self.autonomy.defer_retry_seconds,
                    metadata=dict(resource_block["metadata"]),
                )
                continue
            selection = self.provider_router.select_route(task)
            scheduler_decision = self.model_scheduler.evaluate(
                task,
                selection,
                active_runs=self.store.list_running_task_runs(),
            )
            if not scheduler_decision.granted:
                self.resume_tracker.defer_task(
                    task,
                    scheduler_decision.reason,
                    delay_seconds=scheduler_decision.defer_seconds,
                    metadata={"lane": scheduler_decision.lane, "route": selection.route.value},
                )
                continue

            context = (
                self._memory_service().build_context_slice(task.target_id, task.role)
                if task.target_id
                else None
            )
            primitives = self._primitive_resolver().resolve_primitives(task)
            validation_issues = self.validation_registry.validate(
                ValidationStage.EXECUTION_PREFLIGHT,
                ValidationContext(task=task, target=target, store=self.store, primitives=primitives),
            )
            self._apply_validation_annotations(task, validation_issues)
            if any(issue.blocks_progress for issue in validation_issues):
                self._record_validation_failure(
                    task,
                    validation_issues,
                    report,
                    stage=ValidationStage.EXECUTION_PREFLIGHT,
                )
                continue

            primitive_decision = self._evaluate_primitives(task, primitives)
            if primitive_decision is not None:
                self.store.insert_policy_decision(primitive_decision)
                if primitive_decision.verdict == PolicyVerdict.NEEDS_APPROVAL:
                    task.status = TaskStatus.NEEDS_APPROVAL
                    task.requires_approval = True
                    self.store.insert_task(task)
                    self.store.insert_event(
                        EventRecord(
                            type=EventType.TASK_NEEDS_APPROVAL,
                            summary=primitive_decision.reason,
                            target_id=task.target_id,
                            task_id=task.id,
                        )
                    )
                    continue
                if primitive_decision.verdict == PolicyVerdict.DENY:
                    task.status = TaskStatus.BLOCKED
                    self.store.insert_task(task)
                    self.store.insert_event(
                        EventRecord(
                            type=EventType.TASK_BLOCKED,
                            summary=primitive_decision.reason,
                            target_id=task.target_id,
                            task_id=task.id,
                        )
                    )
                    continue

            run = TaskRun(
                task_id=task.id,
                status=TaskRunStatus.CLAIMED,
                attempt_number=task.attempts + 1,
                role=task.role,
                provider_route=selection.route,
                model_name=selection.model_name,
                cold_path=selection.cold_path,
                heartbeat_at=utc_now(),
                lease_expires_at=utc_now() + timedelta(minutes=5),
                trace_summary="task claimed for brokered execution",
                metadata={
                    "rationale": selection.rationale,
                    "risk_tier": task.risk_tier.value,
                    "scheduler_lane": scheduler_decision.lane,
                },
            )
            task.latest_run_id = run.id
            task.provider_route = selection.route
            task.provider_model = selection.model_name
            self.store.insert_task_run(run)
            self.store.insert_task(task)
            self._write_checkpoint(task, run, summary="pre-execution checkpoint", payload={"task": task.as_payload()}, phase="pre")
            dispatch = self.worker_broker.dispatch(task, selection)
            if not dispatch.accepted:
                run.status = TaskRunStatus.CANCELLED
                run.error = dispatch.reason
                run.finished_at = utc_now()
                run.metadata.update(
                    {
                        "worker_lane": dispatch.lane,
                        "runner_id": dispatch.runner_id,
                        "offer_id": dispatch.offer_id,
                        "offer_count": dispatch.offer_count,
                        "worker_contract": dispatch.worker_contract,
                        "suitability_score": dispatch.suitability_score,
                    }
                )
                self.store.insert_task_run(run)
                defer_count = int(task.metadata.get("defer_count", 0)) + 1
                task.metadata["defer_count"] = defer_count
                if defer_count >= self.autonomy.max_defer_count:
                    task.status = TaskStatus.NEEDS_APPROVAL
                    task.metadata["defer_escalation_reason"] = (
                        f"deferred {defer_count} times without dispatch: {dispatch.reason}"
                    )
                    self.store.insert_task(task)
                    report.events.append(
                        EventRecord(
                            type=EventType.TASK_FAILED,
                            summary=f"Task escalated to NEEDS_APPROVAL after {defer_count} defers: {task.title}",
                            target_id=task.target_id,
                            task_id=task.id,
                            metadata={"defer_count": defer_count, "reason": dispatch.reason},
                        )
                    )
                else:
                    self.resume_tracker.defer_task(
                        task,
                        dispatch.reason,
                        delay_seconds=dispatch.defer_seconds,
                        metadata={
                            "lane": dispatch.lane,
                            "runner_id": dispatch.runner_id,
                            "offer_count": dispatch.offer_count,
                            "defer_count": defer_count,
                        },
                    )
                continue

            run.status = TaskRunStatus.RUNNING
            run.metadata.update(
                {
                    "worker_lane": dispatch.lane,
                    "runner_id": dispatch.runner_id,
                    "offer_id": dispatch.offer_id,
                    "offer_count": dispatch.offer_count,
                    "worker_contract": dispatch.worker_contract,
                    "suitability_score": dispatch.suitability_score,
                }
            )
            if dispatch.worker_contract:
                task.metadata["worker_contract"] = dispatch.worker_contract
            self.store.insert_task_run(run)
            self.store.insert_event(
                EventRecord(
                    type=EventType.TASK_STARTED,
                    summary=task.title,
                    target_id=task.target_id,
                    task_id=task.id,
                    metadata={"runner_id": dispatch.runner_id, "lane": dispatch.lane},
                )
            )
            if self.event_bus is not None:
                self.event_bus.emit(
                    RuntimeSignal.TASK_STARTED,
                    {
                        "task_id": task.id,
                        "target_id": task.target_id,
                        "run_id": run.id,
                        "runner_id": dispatch.runner_id,
                    },
                )
            try:
                result = self.worker_broker.execute(dispatch, task, context)
                if result is None:
                    run.status = TaskRunStatus.CANCELLED
                    run.error = "worker assignment vanished before execution"
                    run.finished_at = utc_now()
                    self.store.insert_task_run(run)
                    self.resume_tracker.defer_task(
                        task,
                        "worker assignment vanished before execution",
                        delay_seconds=self.autonomy.defer_retry_seconds,
                        metadata={"runner_id": dispatch.runner_id, "lane": dispatch.lane},
                    )
                    continue
                self._persist_execution_result(task, run, result, report)
            except Exception as exc:  # noqa: BLE001 - finalize brokered runs even when execution crashes
                self._persist_execution_exception(task, run, exc, report)

    def _resource_reserve_block(self, task: Task) -> dict[str, object] | None:
        if self.resource_status_loader is None or self.resource_reserve_loader is None:
            return None
        metrics = self.resource_status_loader()
        reserves = self.resource_reserve_loader()
        cpu = metrics.get("cpu", {}) if isinstance(metrics, dict) else {}
        gpu = metrics.get("gpu", {}) if isinstance(metrics, dict) else {}
        min_cpu = self._metric_float(reserves.get("min_free_cpu_ram_mb"), 0.0) if isinstance(reserves, dict) else 0.0
        min_gpu = self._metric_float(reserves.get("min_free_gpu_ram_mb"), 0.0) if isinstance(reserves, dict) else 0.0
        observed_cpu = self._metric_float(cpu.get("memory_available_mb"), None) if isinstance(cpu, dict) else None
        observed_gpu = self._metric_float(gpu.get("memory_free_mb"), None) if isinstance(gpu, dict) else None
        blockers: list[str] = []
        if min_cpu > 0 and observed_cpu is not None and observed_cpu < min_cpu:
            blockers.append(f"CPU RAM available {observed_cpu:.0f} MB is below reserve {min_cpu:.0f} MB")
        if (
            min_gpu > 0
            and isinstance(gpu, dict)
            and bool(gpu.get("available"))
            and observed_gpu is not None
            and observed_gpu < min_gpu
        ):
            blockers.append(f"GPU VRAM free {observed_gpu:.0f} MB is below reserve {min_gpu:.0f} MB")
        if not blockers:
            return None
        reason = "resource reserve guard: " + "; ".join(blockers)
        return {
            "reason": reason,
            "metadata": {
                "resource_reserve_guard": True,
                "task_kind": task.kind.value,
                "provider_route": task.provider_route.value if task.provider_route else None,
                "min_free_cpu_ram_mb": min_cpu,
                "min_free_gpu_ram_mb": min_gpu,
                "observed_cpu_memory_available_mb": observed_cpu,
                "observed_gpu_memory_free_mb": observed_gpu,
            },
        }

    def _metric_float(self, raw: object, default: float | None) -> float | None:
        try:
            return float(raw) if raw is not None else default
        except (TypeError, ValueError):
            return default

    def _execution_target_is_invalid(self, task: Task, target: Target | None, report: OrchestrationReport) -> bool:
        if task.target_id is None:
            return False
        reason = ""
        if target is None:
            reason = "target record is missing"
        elif not target.handle.strip():
            reason = "target handle is empty"
        if not reason:
            return False
        task.status = TaskStatus.BLOCKED
        task.updated_at = utc_now()
        task.metadata["invalid_target"] = True
        task.metadata["invalid_target_reason"] = reason
        self.store.insert_task(task)
        event = EventRecord(
            type=EventType.TASK_BLOCKED,
            summary=f"Task blocked before execution: {reason}",
            target_id=task.target_id,
            task_id=task.id,
            metadata={"invalid_target": True, "reason": reason},
        )
        self.store.insert_event(event)
        report.events.append(event)
        return True

    def _persist_execution_result(self, task: Task, run: TaskRun, result, report: OrchestrationReport) -> None:
        for trace in result.traces:
            self.store.insert_trace(trace)
        if not result.traces:
            self.store.insert_trace(
                AgentTrace(
                    task_id=task.id,
                    role=task.role,
                    status="completed" if result.success else "failed",
                    summary=result.summary or task.summary,
                    metadata={"summary_key": task.kind.value},
                )
            )

        for artifact in result.artifacts:
            self.store.insert_artifact(artifact)
        for evidence in result.evidence:
            self._annotate_result_metadata(task, evidence.metadata)
            self.store.insert_evidence(evidence)
        for note in result.notes:
            self._annotate_result_metadata(task, note.metadata)
            self.store.insert_note(note)
        for interest in result.interests:
            self._annotate_result_metadata(task, interest.metadata)
            self.store.insert_interest(interest)
        for finding in result.findings:
            self._annotate_result_metadata(task, finding.metadata)
            self.store.insert_finding(finding)
            self.store.insert_event(
                EventRecord(
                    type=EventType.FINDING_UPDATED,
                    summary=finding.title,
                    target_id=finding.target_id,
                    task_id=task.id,
                )
            )
            if finding.confidence >= 0.8 or finding.severity.value in {"high", "critical"}:
                self.store.insert_notification(
                    NotificationRecord(
                        channel=NotificationChannel.DISCORD,
                        event_type="finding_candidate",
                        summary=f"{finding.severity.value.upper()}: {finding.title}",
                        target_id=finding.target_id,
                        task_id=task.id,
                        finding_id=finding.id,
                        urgency="high",
                        dedupe_key=f"finding:{finding.title}",
                    )
                )
        for handoff in result.handoffs:
            self.store.insert_handoff(handoff)
            self.store.insert_event(
                EventRecord(
                    type=EventType.HANDOFF_CREATED,
                    summary=handoff.reason,
                    task_id=task.id,
                    target_id=task.target_id,
                )
            )
        for notification in result.notifications:
            existing = notification.dedupe_key and self.store.find_latest_notification_by_dedupe(notification.dedupe_key)
            if existing and existing.status in {NotificationStatus.PENDING, NotificationStatus.DELIVERED}:
                continue
            self.store.insert_notification(notification)
        for sync_job in result.sync_jobs:
            self.store.insert_external_sync_job(sync_job)
            self.store.insert_event(
                EventRecord(
                    type=EventType.SYNC_QUEUED,
                    summary=sync_job.summary,
                    target_id=sync_job.target_id,
                    task_id=task.id,
                    metadata={"kind": sync_job.kind.value},
                )
            )
        if task.target_id and (result.notes or result.findings):
            self.store.insert_external_sync_job(
                ExternalSyncJob(
                    kind=ExternalSyncKind.NOTION,
                    target_id=task.target_id,
                    summary="Sync meaningful note/finding updates to Notion",
                    payload={"target_id": task.target_id, "task_id": task.id, "kind": task.kind.value},
                )
            )
        for next_task in result.next_tasks:
            target = self.store.get_target(next_task.target_id)
            self._register_task(next_task, target, report)
        for event in result.events:
            self.store.insert_event(event)
            report.events.append(event)

        if result.escalation_package:
            if not self.autonomy.allow_remote_premium:
                # Remote premium is policy-disabled — record the suppressed escalation so the
                # operator can act on it if they later enable allow_remote_premium.
                note = Note(
                    target_id=task.target_id,
                    task_id=task.id,
                    title="Premium escalation suppressed (allow_remote_premium=False)",
                    body=(
                        f"An escalation package was generated but remote premium review is "
                        f"policy-disabled. Reason: {result.escalation_package.reason}. "
                        "Enable PRIMORDIAL_ALLOW_REMOTE_PREMIUM to activate premium routing."
                    ),
                    confidence=0.95,
                    freshness=1.0,
                    metadata={"escalation_suppressed": True, "reason": result.escalation_package.reason},
                )
                self.store.insert_note(note)
            elif not self.store.has_active_task(task.target_id, TaskKind.REVIEW_PREMIUM_ESCALATION):
                escalation_task = self._build_task(
                    target_id=task.target_id,
                    kind=TaskKind.REVIEW_PREMIUM_ESCALATION,
                    title="Premium review requested",
                    summary=result.escalation_package.reason,
                    session_id=task.session_id,
                )
                escalation_task.evidence_refs = result.escalation_package.evidence_refs
                escalation_task.metadata["escalation_package"] = result.escalation_package.as_payload()
                self._register_task(escalation_task, self.store.get_target(task.target_id), report)

        if result.success:
            task.status = TaskStatus.SUCCEEDED
            run.status = TaskRunStatus.SUCCEEDED
            run.trace_summary = result.summary
            task.attempts += 1
            if task.target_id and self._memory_service().needs_compaction(task.target_id):
                self._memory_service().compact_target(task.target_id)
                self._memory_service().apply_freshness_decay(task.target_id)
        else:
            task.attempts += 1
            if task.attempts < task.max_attempts:
                task.status = TaskStatus.PENDING
                run.status = TaskRunStatus.FAILED
                self.store.insert_event(
                    EventRecord(
                        type=EventType.TASK_RETRIED,
                        summary=f"Retry scheduled for {task.title}",
                        target_id=task.target_id,
                        task_id=task.id,
                    )
                )
            else:
                task.status = TaskStatus.FAILED
                run.status = TaskRunStatus.FAILED
            run.error = result.error
            run.trace_summary = result.error or result.summary

        run.finished_at = utc_now()
        run.heartbeat_at = utc_now()
        self.store.insert_task_run(run)
        task.updated_at = utc_now()
        self.store.insert_task(task)
        self._write_checkpoint(
            task,
            run,
            summary="post-execution checkpoint",
            payload={"task": task.as_payload(), "run": run.as_payload(), "summary": result.summary},
            phase="post",
        )
        self.store.insert_event(
            EventRecord(
                type=EventType.TASK_SUCCEEDED if result.success else EventType.TASK_FAILED,
                summary=(result.summary if result.success else result.error or result.summary) or task.title,
                target_id=task.target_id,
                task_id=task.id,
                metadata={"error": result.error} if result.error else {},
            )
        )
        if self.event_bus is not None:
            self.event_bus.emit(
                RuntimeSignal.TASK_FINISHED,
                {
                    "task_id": task.id,
                    "target_id": task.target_id,
                    "run_id": run.id,
                    "success": result.success,
                },
            )
        report.completed_runs.append(run)

    @staticmethod
    def _is_transient_exception(exc: Exception) -> bool:
        # OSError covers socket/network/IO errors; TimeoutError is a subclass of OSError.
        # urllib errors are also OSError subclasses on Python 3.3+.
        # These failures are infrastructure-level — the task logic was never exercised,
        # so burning a retry budget on them is incorrect.
        return isinstance(exc, (OSError, TimeoutError))

    def _persist_execution_exception(
        self,
        task: Task,
        run: TaskRun,
        exc: Exception,
        report: OrchestrationReport,
    ) -> None:
        now = utc_now()
        transient = self._is_transient_exception(exc)
        if transient:
            # Network/IO glitch: reset to PENDING without consuming retry budget.
            task.status = TaskStatus.PENDING
        else:
            task.attempts += 1
            task.status = TaskStatus.PENDING if task.attempts < task.max_attempts else TaskStatus.FAILED
        task.updated_at = now
        task.metadata["execution_exception"] = str(exc)
        task.metadata["last_exception_transient"] = transient
        run.status = TaskRunStatus.FAILED
        run.error = str(exc)
        run.trace_summary = f"execution crashed: {exc}"
        run.finished_at = now
        run.heartbeat_at = now
        run.metadata["execution_exception"] = True
        self.store.insert_trace(
            AgentTrace(
                task_id=task.id,
                role=task.role,
                status="failed",
                summary=f"Execution crashed before result persistence: {exc}",
                metadata={"execution_exception": True, "error": str(exc), "model": task.provider_model},
            )
        )
        self.store.insert_task_run(run)
        self.store.insert_task(task)
        self._write_checkpoint(
            task,
            run,
            summary="execution exception checkpoint",
            payload={"task": task.as_payload(), "run": run.as_payload(), "error": str(exc)},
            phase="exception",
        )
        event = EventRecord(
            type=EventType.TASK_FAILED,
            summary=f"Execution crashed: {task.title}",
            target_id=task.target_id,
            task_id=task.id,
            metadata={"error": str(exc), "execution_exception": True},
        )
        self.store.insert_event(event)
        report.events.append(event)
        report.completed_runs.append(run)

    def _annotate_result_metadata(self, task: Task, metadata: dict[str, object]) -> None:
        if task.metadata.get("active_ip_generation") is not None:
            metadata.setdefault("active_ip_generation", task.metadata["active_ip_generation"])
        if task.metadata.get("active_ip"):
            metadata.setdefault("active_ip", task.metadata["active_ip"])

    def _verifier_signal_already_handled(self, signal) -> bool:
        for task in self.store.list_tasks(target_id=signal.target_id, limit=200):
            if task.kind != TaskKind.VERIFY_AGENT_BEHAVIOR:
                continue
            if task.summary != signal.reason:
                continue
            if task.status in {
                TaskStatus.PENDING,
                TaskStatus.RUNNING,
                TaskStatus.WAITING,
                TaskStatus.NEEDS_APPROVAL,
                TaskStatus.SUCCEEDED,
            }:
                return True
        return False

    def _write_checkpoint(self, task: Task, run: TaskRun, summary: str, payload: dict[str, object], *, phase: str = "checkpoint") -> None:
        task_dir = self.checkpoints_dir / (task.id or "task")
        task_dir.mkdir(parents=True, exist_ok=True)
        path = task_dir / f"{run.id}-{phase}.json"
        path.write_text(json.dumps(payload, indent=2, sort_keys=True))
        checkpoint = CheckpointRecord(
            task_id=task.id,
            run_id=run.id,
            kind=CheckpointKind.TASK,
            path=str(path),
            summary=summary,
        )
        self.store.insert_checkpoint(checkpoint)
        self.store.insert_event(
            EventRecord(
                type=EventType.TASK_CHECKPOINTED,
                summary=summary,
                target_id=task.target_id,
                task_id=task.id,
            )
        )
        if self.event_bus is not None:
            self.event_bus.emit(
                RuntimeSignal.TASK_CHECKPOINTED,
                {"task_id": task.id, "run_id": run.id, "path": str(path)},
            )

    def _evaluate_primitives(self, task: Task, primitives: list[PrimitiveManifest]):
        target = self.store.get_target(task.target_id)
        for primitive in primitives:
            decision = self.policy_engine.evaluate_primitive(task, target, primitive)
            if decision.verdict != PolicyVerdict.ALLOW:
                return decision
        return None

    def _memory_service(self) -> MemoryServiceProtocol:
        return self.memory_service_loader()

    def _primitive_resolver(self) -> PrimitiveResolverProtocol:
        return self.primitive_resolver_loader()

    def _stored_primitives_for_task(self, task: Task) -> list[PrimitiveManifest]:
        selected: dict[str, PrimitiveManifest] = {}
        manifests = self.store.list_primitives()
        primitive_hint = str(task.metadata.get("primitive_hint") or "").strip().lower()
        if primitive_hint:
            hinted = [
                manifest
                for manifest in manifests
                if manifest.name.lower() == primitive_hint
            ]
            if hinted:
                return hinted
        for capability in task.required_capabilities:
            for manifest in manifests:
                if capability in manifest.capability_tags:
                    selected.setdefault(manifest.name, manifest)
        return list(selected.values())

    def _apply_validation_annotations(self, task: Task, issues) -> None:
        if not issues:
            return
        warnings = [issue for issue in issues if not issue.blocks_progress]
        errors = [issue for issue in issues if issue.blocks_progress]
        if warnings:
            task.metadata["validation_warnings"] = [self._validation_payload(issue) for issue in warnings]
        if errors:
            task.metadata["validation_errors"] = [self._validation_payload(issue) for issue in errors]

    def _record_validation_failure(
        self,
        task: Task,
        issues,
        report: OrchestrationReport,
        *,
        stage: ValidationStage,
        track_created: bool = False,
    ) -> None:
        task.status = TaskStatus.BLOCKED
        self.store.insert_task(task)
        if track_created:
            report.created_tasks.append(task)
        event = EventRecord(
            type=EventType.TASK_BLOCKED,
            summary=issues[0].message,
            target_id=task.target_id,
            task_id=task.id,
            metadata={
                "stage": stage.value,
                "validation_issues": [self._validation_payload(issue) for issue in issues],
            },
        )
        self.store.insert_event(event)
        report.events.append(event)

    def _validation_payload(self, issue) -> dict[str, object]:
        return {
            "code": issue.code,
            "message": issue.message,
            "severity": issue.severity.value,
            "metadata": dict(issue.metadata),
        }
