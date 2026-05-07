from __future__ import annotations

from dataclasses import dataclass, field
import json
from datetime import timedelta
from pathlib import Path
from typing import Callable, Protocol

from primordial.core.config import AutonomySettings
from primordial.core.domain.constants import AD_INDICATOR_PORTS, DNS_PORTS, REMOTE_ADMIN_PORTS
from primordial.core.domain.enums import (
    AgentRole,
    CheckpointKind,
    EventType,
    ExternalSyncKind,
    NotificationChannel,
    NotificationStatus,
    PolicyVerdict,
    TaskKind,
    TaskRunStatus,
    TaskStatus,
)
from primordial.core.domain.models import (
    AgentTrace,
    CheckpointRecord,
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
from primordial.core.events.bus import EventBus, RuntimeSignal
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
        if approved:
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

    def _plan_target(self, target: Target, session_id: str | None, report: OrchestrationReport) -> None:
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
            task.metadata.update(dict(action.get("metadata", {})))
            self._register_task(task, target, report)
            planned_any = True
        if not planned_any and methodology_state.no_progress_reason:
            self._record_no_progress_state(target, methodology_state, report)

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
        blockers = self._methodology_blockers(target, evidence)
        ai_admission = self._evaluate_ai_proposal_admission(tasks)
        if ai_admission["rejected"]:
            blockers.extend(
                f"AI proposal rejected: {item['title']} ({item['reason']})"
                for item in ai_admission["rejected"][:3]
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
        if self._should_plan_kerberos_attack_check(target):
            add(
                TaskKind.KERBEROS_ATTACK_CHECK,
                "Run Kerberos attack-path checks",
                f"Check AS-REP/Kerberoast applicability for discovered principals on {target.handle}.",
                confidence=0.76,
                subphase="kerberos_attack_path",
                transition_reason="Current-generation principal evidence supports bounded Kerberos attack-path checks.",
                prerequisite="current-generation principal discovery",
            )
        if self._should_plan_credentialed_access_check(target):
            add(
                TaskKind.CREDENTIALED_ACCESS_CHECK,
                "Verify credentialed SMB/WinRM access",
                f"Use configured lab credentials to verify access and collect flags for {target.handle}.",
                confidence=0.75,
                subphase="credentialed_verification",
                transition_reason="Operator-configured lab credentials are present and remote-admin surfaces are in scope.",
                prerequisite="configured lab credentials and current-generation remote-admin evidence",
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
        has_remote_admin_surface = self._target_has_remote_admin_surface(evidence)
        has_research_candidates = any(
            item.metadata.get("kind") == "exploit_research" and int(item.metadata.get("match_count", 0) or 0) > 0
            for item in evidence
        )
        if has_research_candidates and not self._poc_adaptation_available(capabilities):
            blockers.append(
                "Retained public PoC candidates exist, but no gated PoC applicability/adaptation primitive is registered."
            )
        if has_remote_admin_surface and not self._lab_credentials_configured():
            blockers.append("Lab username/password are not configured, so credentialed SMB/WinRM verification cannot run.")
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
        if not self.credentials_status_loader:
            return False
        status = self.credentials_status_loader()
        services = status.get("services", {}) if isinstance(status, dict) else {}
        lab = services.get("lab", {}) if isinstance(services, dict) else {}
        if not isinstance(lab, dict):
            return False
        username = lab.get("username", {})
        password = lab.get("password", {})
        return (
            isinstance(username, dict)
            and isinstance(password, dict)
            and bool(username.get("configured"))
            and bool(password.get("configured"))
        )

    def _profile_allows_task(self, target: Target, task_kind_value: str) -> bool:
        allowed = self.autonomy.profile_task_allowlist.get(target.profile.value, frozenset())
        return task_kind_value in allowed

    def _target_has_remote_admin_surface(self, evidence) -> bool:
        for item in evidence:
            for service in item.metadata.get("open_services", []):
                if isinstance(service, dict) and int(service.get("port", 0) or 0) in REMOTE_ADMIN_PORTS:
                    return True
        return False

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
        if not self._profile_allows_task(target, "exploit_research") and not target.metadata.get("allow_exploit_research"):
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
        if not self._profile_allows_task(target, "poc_applicability_validation") and not target.metadata.get("allow_poc_applicability_validation"):
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
        if not self._profile_allows_task(target, "kerberos_attack_check") and not target.metadata.get("allow_kerberos_attack_check"):
            return False
        evidence = self.store.list_evidence(target_id=target.id, limit=200)
        if any(
            item.metadata.get("kind") == "kerberos_attack_check"
            and self._evidence_matches_active_generation(target, item)
            for item in evidence
        ):
            return False
        for item in evidence:
            if item.metadata.get("kind") != "kerberos_user_discovery":
                continue
            if not self._evidence_matches_active_generation(target, item):
                continue
            users = item.metadata.get("users", [])
            spns = item.metadata.get("spn_candidates", [])
            if isinstance(users, list) and users:
                return True
            if isinstance(spns, list) and spns:
                return True
        return False

    def _should_plan_credentialed_access_check(self, target: Target) -> bool:
        if not self._profile_allows_task(target, "credentialed_access_check") and not target.metadata.get("allow_credentialed_access_check"):
            return False
        evidence = self.store.list_evidence(target_id=target.id, limit=200)
        if any(
            item.metadata.get("kind") == "credentialed_access_check"
            and self._evidence_matches_active_generation(target, item)
            for item in evidence
        ):
            return False
        if not self.credentials_status_loader:
            return False
        status = self.credentials_status_loader()
        services = status.get("services", {}) if isinstance(status, dict) else {}
        lab = services.get("lab", {}) if isinstance(services, dict) else {}
        if not isinstance(lab, dict):
            return False
        username = lab.get("username", {})
        password = lab.get("password", {})
        return (
            isinstance(username, dict)
            and isinstance(password, dict)
            and bool(username.get("configured"))
            and bool(password.get("configured"))
        )

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
            max_attempts=blueprint.max_attempts,
            metadata={"autonomy_mode": self.autonomy.mode.value},
        )
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
        decision = self.policy_engine.evaluate_task(task, target)
        self.policy_engine.apply_decision_to_task(task, decision)
        self.store.insert_policy_decision(decision)
        self.store.insert_task(task)
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

    def _execute_ready_tasks(self, report: OrchestrationReport, max_executions: int) -> None:
        for _ in range(max_executions):
            task = self.store.claim_next_pending_task()
            if not task:
                return
            target = self.store.get_target(task.target_id)
            selection = self.provider_router.select_route(task)
            scheduler_decision = self.model_scheduler.evaluate(
                task,
                selection,
                active_runs=self.store.list_task_runs(limit=200),
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
            self._write_checkpoint(task, run, summary="pre-execution checkpoint", payload={"task": task.as_payload()})
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
                self.resume_tracker.defer_task(
                    task,
                    dispatch.reason,
                    delay_seconds=dispatch.defer_seconds,
                    metadata={
                        "lane": dispatch.lane,
                        "runner_id": dispatch.runner_id,
                        "offer_count": dispatch.offer_count,
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

        if result.escalation_package and not self.store.has_active_task(task.target_id, TaskKind.REVIEW_PREMIUM_ESCALATION):
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
            if task.target_id:
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
        )
        self.store.insert_event(
            EventRecord(
                type=EventType.TASK_SUCCEEDED if result.success else EventType.TASK_FAILED,
                summary=result.summary or task.title,
                target_id=task.target_id,
                task_id=task.id,
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

    def _persist_execution_exception(
        self,
        task: Task,
        run: TaskRun,
        exc: Exception,
        report: OrchestrationReport,
    ) -> None:
        now = utc_now()
        task.attempts += 1
        task.status = TaskStatus.PENDING if task.attempts < task.max_attempts else TaskStatus.FAILED
        task.updated_at = now
        task.metadata["execution_exception"] = str(exc)
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

    def _write_checkpoint(self, task: Task, run: TaskRun, summary: str, payload: dict[str, object]) -> None:
        task_dir = self.checkpoints_dir / (task.id or "task")
        task_dir.mkdir(parents=True, exist_ok=True)
        path = task_dir / f"{run.id}.json"
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
