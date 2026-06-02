from __future__ import annotations

from primordial.core.orchestration.workflow_deps import (
    classify_credentialed_access_surface,
    CredentialedAccessSurface,
    EscalationPackage,
    json,
    metadata_bool_value,
    metadata_list_value,
    metadata_value,
    OrchestrationReport,
    Target,
    Task,
    TaskKind,
    TaskRun,
    TaskStatus,
    utc_now,
)
from primordial.core.sensitive_text import redact_sensitive_text

class WorkflowPlannerUncertaintyMixin:
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
        reason_payload = self._planner_uncertainty_reason_payload(reason_code, question, uncertainty_reasons)
        key = self._planner_uncertainty_key(reason_code, question, evidence_ids, reason_payload)
        if target.metadata.get("last_planner_uncertainty_escalation_key") == key:
            return None

        task = self._build_task(
            target_id=target.id,
            kind=TaskKind.REVIEW_PREMIUM_ESCALATION,
            title=self._planner_uncertainty_title(),
            summary="Resolve an evidence-linked planner uncertainty without bypassing policy.",
            session_id=session_id,
        )
        task.evidence_refs = evidence_ids
        self._attach_planner_uncertainty_generation(task, target)
        self._attach_planner_uncertainty_package(
            task,
            target,
            evidence=evidence,
            evidence_ids=evidence_ids,
            question=question,
            blockers=blockers or [],
            rejected_proposals=rejected_proposals if isinstance(rejected_proposals, list) else [],
            invalid_existing_tasks=invalid_existing_tasks or [],
            reason_code=reason_code,
            uncertainty_reasons=reason_payload,
        )
        task.metadata["planner_uncertainty"] = {
            "reason_code": reason_code,
            "reasons": reason_payload,
            "question": question,
        }
        self._mark_agent_chat_wrapper_review(task)
        if not self.autonomy.allow_remote_premium and not task.metadata.get("remote_premium_local_wrapper"):
            task.metadata["remote_premium_policy_approval_required"] = True
        self._persist_planner_uncertainty_escalation(target, task, key, report)
        return self.store.get_task(task.id)

    def _planner_uncertainty_reason_payload(
        self,
        reason_code: str,
        question: str,
        uncertainty_reasons: list[dict[str, object]] | None,
    ) -> list[dict[str, object]]:
        return uncertainty_reasons or [{"code": reason_code, "summary": question}]

    def _planner_uncertainty_key(
        self,
        reason_code: str,
        question: str,
        evidence_ids: list[str],
        reason_payload: list[dict[str, object]],
    ) -> str:
        return json.dumps(
            {
                "reason_code": reason_code,
                "question": question,
                "evidence_ids": evidence_ids,
                "reasons": reason_payload,
            },
            sort_keys=True,
        )

    def _planner_uncertainty_title(self) -> str:
        if self.autonomy.allow_remote_premium:
            return "Premium planner review requested"
        return "Escalate uncertain planner state to Claude/GPT"

    def _attach_planner_uncertainty_generation(self, task: Task, target: Target) -> None:
        active_generation = self._target_active_generation(target)
        if active_generation is not None:
            task.metadata["active_ip_generation"] = active_generation
            task.metadata["active_ip"] = target.metadata.get("active_ip")

    def _attach_planner_uncertainty_package(
        self,
        task: Task,
        target: Target,
        *,
        evidence: list[object],
        evidence_ids: list[str],
        question: str,
        blockers: list[str],
        rejected_proposals: list[object],
        invalid_existing_tasks: list[dict[str, object]],
        reason_code: str,
        uncertainty_reasons: list[dict[str, object]],
    ) -> None:
        surface = classify_credentialed_access_surface(evidence)
        packet = self._planner_review_packet(
            target,
            evidence=evidence,
            surface=surface,
            question=question,
            blockers=blockers,
            rejected_proposals=rejected_proposals,
            invalid_existing_tasks=invalid_existing_tasks,
            uncertainty_reasons=uncertainty_reasons,
        )
        package = self._planner_uncertainty_package(
            task, target, evidence, evidence_ids, packet, question, reason_code, uncertainty_reasons
        )
        task.metadata["escalation_package"] = package.as_payload()

    def _planner_uncertainty_package(
        self,
        task: Task,
        target: Target,
        evidence: list[object],
        evidence_ids: list[str],
        packet: dict[str, object],
        question: str,
        reason_code: str,
        reason_payload: list[dict[str, object]],
    ) -> EscalationPackage:
        reason = "; ".join(str(item.get("summary") or item.get("code") or reason_code) for item in reason_payload[:4])
        return EscalationPackage(
            task_id=task.id,
            target_id=target.id,
            mode="planner_uncertainty_review",
            reason=reason,
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

    def _persist_planner_uncertainty_escalation(
        self,
        target: Target,
        task: Task,
        key: str,
        report: OrchestrationReport | None,
    ) -> None:
        target.metadata["last_planner_uncertainty_escalation_key"] = key
        target.updated_at = utc_now()
        self.store.insert_target(target)
        escalation_report = report or OrchestrationReport()
        self._register_task(task, target, escalation_report)

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
        rag_context_pack = self._planner_rag_context_pack(target, query=question, limit=5)
        rag_context = rag_context_pack.get("chunks", []) if isinstance(rag_context_pack.get("chunks"), list) else []
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
            "rag_context_policy": {
                "purpose": rag_context_pack.get("purpose", "planner_review"),
                "role": rag_context_pack.get("role", "local_deep"),
                "citation_map": rag_context_pack.get("citation_map", []),
                "omitted_sources": rag_context_pack.get("omitted_sources", []),
                "warnings": rag_context_pack.get("warnings", []),
            },
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

    def _planner_rag_context_pack(self, target: Target, *, query: str, limit: int = 5) -> dict[str, object]:
        if self.rag_context_builder is not None:
            try:
                return self.rag_context_builder(
                    query,
                    purpose="planner_review",
                    role="local_deep",
                    target=target,
                    limit=limit,
                )
            except Exception as exc:  # noqa: BLE001 - RAG is advisory and must not block planner review packets
                return {
                    "query": redact_sensitive_text(query),
                    "purpose": "planner_review",
                    "role": "local_deep",
                    "target_id": target.id,
                    "chunks": [],
                    "citation_map": [],
                    "omitted_sources": [],
                    "warnings": [str(exc)],
                    "prompt_context": "",
                }
        return {
            "query": redact_sensitive_text(query),
            "purpose": "planner_review",
            "role": "local_deep",
            "target_id": target.id,
            "chunks": self._planner_rag_context(target, query=query, limit=limit),
            "citation_map": [],
            "omitted_sources": [],
            "warnings": [],
            "prompt_context": "",
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
                    "corpus_type": metadata_value(chunk.metadata, "corpus_type"),
                    "source_trust": metadata_value(chunk.metadata, "source_trust"),
                    "hint_policy": metadata_value(chunk.metadata, "hint_policy"),
                    "cve_ids": metadata_list_value(chunk.metadata, "cve_ids"),
                    "walkthrough_hint": metadata_bool_value(chunk.metadata, "walkthrough_hint"),
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
