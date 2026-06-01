from __future__ import annotations

from primordial.app.runtime_deps import (
    AUTH_SURFACE_TERMS,
    classify_credentialed_access_surface,
    deterministic_operator_facts,
    evidence_kind_set,
    EvidenceRecord,
    Finding,
    flag_evidence_hits,
    Interest,
    json,
    merge_methodology_next_actions,
    OPEN_PORT_TERMS,
    operator_capability_sets,
    operator_question_has_any,
    PROBLEM_TASK_TERMS,
    render_deterministic_operator_answer,
    SCOPED_RECON_TERMS,
    Target,
    TARGET_STATE_TERMS,
    Task,
    TaskStatus,
)

class RuntimeOperatorAnswersMixin:
    def _deterministic_operator_answer(self, question: str, target_id: str | None) -> str:
        target = self.store.get_target(target_id) if target_id else None
        tasks = self.store.list_tasks(target_id=target_id, limit=12)
        evidence = self.store.list_evidence(target_id=target_id, limit=12)
        active_generation = self._target_active_generation(target)
        current_evidence = [
            item
            for item in evidence
            if self._record_matches_active_generation(item, active_generation)
        ]
        stale_evidence = [item for item in evidence if item not in current_evidence]
        raw_interests = self.store.list_interests(target_id=target_id, limit=12)
        raw_findings = self.store.list_findings(target_id=target_id, limit=8)
        interests = [item for item in raw_interests if self._record_matches_active_generation(item, active_generation)]
        findings = [item for item in raw_findings if self._record_matches_active_generation(item, active_generation)]
        primitive_names, capabilities = operator_capability_sets(self.store.list_primitives())
        evidence_kinds = evidence_kind_set(current_evidence)
        flag_hits = flag_evidence_hits(current_evidence)
        potential_paths = self._deterministic_potential_paths(current_evidence, interests, findings)
        lab_credentials_configured = self._lab_credentials_configured()
        credential_surface = classify_credentialed_access_surface(current_evidence)
        blockers = self._deterministic_blockers(
            flag_hits,
            findings,
            potential_paths,
            capabilities,
            lab_credentials_configured,
            credential_surface,
        )
        next_actions = self._deterministic_next_actions(current_evidence, interests, findings, capabilities, credential_surface)
        capability_gaps = self._deterministic_capability_gaps(current_evidence, evidence_kinds, capabilities, credential_surface)
        methodology_state = self._live_methodology_state_payload(target) if target else {}
        direct_answers = self._deterministic_direct_answers(
            question,
            target=target,
            tasks=tasks,
            evidence=current_evidence,
            interests=interests,
            findings=findings,
            next_actions=next_actions,
        )
        next_actions = merge_methodology_next_actions(methodology_state, next_actions)
        freshness_line = self._operator_recent_change_line(question, target_id)
        facts = deterministic_operator_facts(
            target=target,
            methodology_state=methodology_state,
            stale_evidence_count=len(stale_evidence),
            current_evidence=current_evidence,
            freshness_line=freshness_line,
        )
        return render_deterministic_operator_answer(
            direct_answers=direct_answers,
            facts=facts,
            tasks=tasks,
            primitive_names=primitive_names,
            potential_paths=potential_paths,
            blockers=blockers,
            methodology_state=methodology_state,
            next_actions=next_actions,
            capability_gaps=capability_gaps,
        )

    def _deterministic_direct_answers(
        self,
        question: str,
        *,
        target: Target | None,
        tasks: list[Task],
        evidence: list[EvidenceRecord],
        interests: list[Interest],
        findings: list[Finding],
        next_actions: list[str],
    ) -> list[str]:
        lowered = question.lower()
        if operator_question_has_any(lowered, TARGET_STATE_TERMS) and target is None:
            return ["No target is selected or named in the question, so I cannot give target-specific runtime state."]

        lines: list[str] = []
        lines.extend(self._direct_open_port_answers(lowered, evidence))
        lines.extend(self._direct_auth_surface_answers(lowered, evidence, interests, findings))
        lines.extend(self._direct_problem_task_answers(lowered, tasks))
        lines.extend(self._direct_scoped_recon_answers(lowered, next_actions))
        lines.extend(self._direct_premium_review_answers(question, target, evidence))
        return lines

    def _direct_open_port_answers(self, lowered: str, evidence: list[EvidenceRecord]) -> list[str]:
        if not operator_question_has_any(lowered, OPEN_PORT_TERMS):
            return []
        services = self._current_open_port_summary(evidence)
        if not services:
            return ["No current TCP service-discovery evidence is stored, so open ports cannot be answered from state."]
        lines = [
            f"Stored current evidence observes {len(services)} unique open TCP port(s): "
            + ", ".join(f"`{item}`" for item in services)
            + "."
        ]
        if not self._has_full_port_scan_evidence(evidence):
            lines.append(
                "That is an observed-port answer, not proof that no other ports exist; no full-range port sweep evidence is stored."
            )
        return lines

    def _direct_auth_surface_answers(
        self,
        lowered: str,
        evidence: list[EvidenceRecord],
        interests: list[Interest],
        findings: list[Finding],
    ) -> list[str]:
        if not operator_question_has_any(lowered, AUTH_SURFACE_TERMS):
            return []
        auth_paths = self._current_auth_surface_summary(evidence, interests, findings)
        if auth_paths:
            return [
                "Stored current evidence identifies auth/session candidate(s): "
                + ", ".join(f"`{item}`" for item in auth_paths[:10])
                + "."
            ]
        if any(self._evidence_has_http_surface(item) for item in evidence):
            return ["No stored current evidence identifies a login portal on port 80."]
        return ["No current HTTP evidence is stored, so login portals cannot be answered from state."]

    def _direct_problem_task_answers(self, lowered: str, tasks: list[Task]) -> list[str]:
        if not operator_question_has_any(lowered, PROBLEM_TASK_TERMS):
            return []
        task = self._latest_problem_task(tasks)
        if task is None:
            return ["No failed, blocked, cancelled, or approval-waiting task is present in the recent target task set."]
        reason = self._task_problem_reason(task)
        return [f"Latest problem task is `{task.kind.value}` `{task.id}` with status `{task.status.value}`: {reason}"]

    def _direct_scoped_recon_answers(self, lowered: str, next_actions: list[str]) -> list[str]:
        if not operator_question_has_any(lowered, SCOPED_RECON_TERMS):
            return []
        scoped = next_actions[:3]
        if not scoped:
            return ["No runnable scoped recon step is derivable from current evidence."]
        return [f"Scoped recon step {index}: {action}" for index, action in enumerate(scoped, start=1)]

    def _direct_premium_review_answers(
        self,
        question: str,
        target: Target | None,
        evidence: list[EvidenceRecord],
    ) -> list[str]:
        if not self._operator_requests_premium_escalation(question):
            return []
        if target is None:
            return ["Premium review was not created because no target is selected."]
        if not evidence:
            return [f"Premium review was not created for `{target.handle}` because no current evidence is stored."]
        return [
            f"Premium review requested for `{target.handle}`; a structured evidence-linked review task will be created if no active duplicate exists."
        ]

    def _current_open_port_summary(self, evidence: list[EvidenceRecord]) -> list[str]:
        ports: dict[int, set[str]] = {}
        for item in evidence:
            services = item.metadata.get("open_services", [])
            if not isinstance(services, list):
                continue
            for service in services:
                if not isinstance(service, dict):
                    continue
                try:
                    port = int(service.get("port", 0) or 0)
                except (TypeError, ValueError):
                    continue
                if port <= 0:
                    continue
                name = str(service.get("service") or service.get("name") or "").strip().lower()
                ports.setdefault(port, set())
                if name:
                    ports[port].add(name)
        summary = []
        for port in sorted(ports):
            names = sorted(ports[port])
            summary.append(f"{port}/{names[0]}" if names else str(port))
        return summary

    def _has_full_port_scan_evidence(self, evidence: list[EvidenceRecord]) -> bool:
        for item in evidence:
            payload = json.dumps(item.as_payload()).lower()
            if any(term in payload for term in ("full-range", "full range", "all 65535", "65535 ports", "1-65535")):
                return True
        return False

    def _current_auth_surface_summary(
        self,
        evidence: list[EvidenceRecord],
        interests: list[Interest],
        findings: list[Finding],
    ) -> list[str]:
        candidates: list[str] = []

        def add(value: object) -> None:
            text = str(value or "").strip()
            if not text:
                return
            lowered = text.lower()
            if any(term in lowered for term in ("login", "signin", "sign-in", "auth", "session", "admin", "account")):
                if text not in candidates:
                    candidates.append(text)

        for item in evidence:
            for key in ("auth_surfaces", "forms", "paths", "page_links", "interesting_paths"):
                values = item.metadata.get(key, [])
                if isinstance(values, list):
                    for value in values:
                        add(value)
        for item in interests:
            if item.metadata.get("class") == "auth":
                values = item.metadata.get("paths", [])
                if isinstance(values, list):
                    for value in values:
                        add(value)
                add(item.title)
                add(item.summary)
        for item in findings:
            values = item.metadata.get("auth_surfaces", [])
            if isinstance(values, list):
                for value in values:
                    add(value)
            values = item.metadata.get("interesting_paths", [])
            if isinstance(values, list):
                for value in values:
                    add(value)
        return candidates

    def _latest_problem_task(self, tasks: list[Task]) -> Task | None:
        problem_statuses = {
            TaskStatus.FAILED,
            TaskStatus.BLOCKED,
            TaskStatus.CANCELLED,
            TaskStatus.NEEDS_APPROVAL,
            TaskStatus.WAITING,
        }
        candidates = [task for task in tasks if task.status in problem_statuses]
        if not candidates:
            return None
        return sorted(candidates, key=lambda task: task.updated_at, reverse=True)[0]

    def _task_problem_reason(self, task: Task) -> str:
        for key in ("block_reason", "reason", "error", "validation_reason", "next_unblock_action"):
            value = task.metadata.get(key)
            if value:
                return str(value)
        validation = task.metadata.get("validation_issues")
        if isinstance(validation, list) and validation:
            first = validation[0]
            if isinstance(first, dict):
                return str(first.get("message") or first.get("reason") or task.summary)
            return str(first)
        return task.summary or task.title

    def _operator_recent_change_line(self, question: str, target_id: str | None) -> str:
        lowered = question.lower()
        if not any(term in lowered for term in ("anything new", "what's new", "whats new", "any new")):
            return ""
        messages = self.store.list_operator_messages(target_id=target_id, limit=20)
        last_assistant_at = None
        for message in messages:
            if message.role == "assistant":
                last_assistant_at = message.created_at
                break
        if last_assistant_at is None:
            return "No previous assistant response exists for comparison."
        new_tasks = [item for item in self.store.list_tasks(target_id=target_id, limit=100) if item.created_at > last_assistant_at]
        new_evidence = [
            item for item in self.store.list_evidence(target_id=target_id, limit=100) if item.created_at > last_assistant_at
        ]
        new_findings = [
            item for item in self.store.list_findings(target_id=target_id, limit=100) if item.created_at > last_assistant_at
        ]
        if not new_tasks and not new_evidence and not new_findings:
            return "No new task, evidence, or finding records have been stored since the last assistant response."
        return (
            "New since last assistant response: "
            f"{len(new_tasks)} task(s), {len(new_evidence)} evidence record(s), {len(new_findings)} finding(s)."
        )
