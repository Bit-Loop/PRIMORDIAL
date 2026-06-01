from __future__ import annotations

from primordial.app.runtime_deps import (
    Target,
    Task,
    TaskKind,
    TaskStatus,
)

class RuntimeOperatorContractMixin:
    def _should_answer_from_state(self, question: str) -> bool:
        lowered = question.lower()
        forced_terms = (
            "deterministic",
            "exact state",
            "raw state",
            "current status",
            "status and next step",
            "summarize",
            "summary",
            "next 3",
            "next three",
            "scoped recon",
            "recon steps",
            "latest task fail",
            "last task fail",
            "why did the latest task",
            "failed task",
            "blocked task",
            "open port",
            "open ports",
            "only 2 open",
            "only two open",
            "login portal",
            "login portals",
            "port 80",
            "escalate",
            "premium review",
            "remote review",
            "gpt",
            "anything new",
            "what is it doing",
            "what are you doing",
            "enough production primitives",
            "user.txt",
            "root.txt",
        )
        if any(term in lowered for term in forced_terms):
            return True
        if "flag" in lowered and any(term in lowered for term in ("status", "have", "found", "got", "obtained")):
            return True
        if "evidence" in lowered and any(term in lowered for term in ("list", "exact", "current", "stored", "status")):
            return True
        return False

    def _operator_question_requires_deterministic_only(self, question: str) -> bool:
        lowered = question.lower()
        deterministic_terms = (
            "summarize",
            "summary",
            "next 3",
            "next three",
            "scoped recon",
            "recon steps",
            "latest task fail",
            "last task fail",
            "why did the latest task",
            "failed task",
            "blocked task",
            "open port",
            "open ports",
            "only 2 open",
            "only two open",
            "login portal",
            "login portals",
            "port 80",
            "escalate",
            "premium review",
            "remote review",
            "gpt",
        )
        return any(term in lowered for term in deterministic_terms)

    def _operator_answer_violates_contract(self, body: str) -> bool:
        lowered = body.lower()
        unsupported_patterns = (
            "thought process",
            "ddos",
            "denial of service",
            "ethical considerations",
            "as an ai",
            "always ensure you have",
            "hello! i'm here to help",
            "how can i assist you today",
            "to help you best",
            "could you please tell me",
            "what you'd like to know or do",
        )
        return any(pattern in lowered for pattern in unsupported_patterns)

    def _operator_uncertainty_escalation_reason(
        self,
        question: str,
        body: str,
        metadata: dict[str, object],
        target: Target | None,
    ) -> str:
        if target is None:
            return ""
        current_evidence = [
            item
            for item in self.store.list_evidence(target_id=target.id, limit=100)
            if self._record_matches_active_generation(item, self._target_active_generation(target))
        ]
        if not current_evidence:
            return ""
        if self._operator_requests_premium_escalation(question):
            return "operator_requested_premium_review"
        if metadata.get("guardrail_replaced_model_output"):
            return "local_model_contract_violation"
        lowered_question = question.lower()
        asks_needed = "what is needed" in lowered_question or "what's needed" in lowered_question or "whats needed" in lowered_question
        if asks_needed and "No runnable next action is derivable from current evidence." in body:
            return "operator_needed_question_unresolved"
        return ""

    def _operator_requests_premium_escalation(self, question: str) -> bool:
        lowered = question.lower()
        mentions_premium = any(term in lowered for term in ("gpt", "premium", "remote review", "claude"))
        asks_escalation = any(term in lowered for term in ("escalate", "send", "ask", "review"))
        return mentions_premium and asks_escalation

    def _append_operator_escalation_status(
        self,
        body: str,
        target: Target,
        *,
        escalation_task: Task | None,
        reason: str,
    ) -> str:
        task = escalation_task
        if task is None:
            active = [
                item
                for item in self.store.list_tasks(target_id=target.id, limit=50)
                if item.kind == TaskKind.REVIEW_PREMIUM_ESCALATION
                and item.status
                in {TaskStatus.PENDING, TaskStatus.RUNNING, TaskStatus.WAITING, TaskStatus.NEEDS_APPROVAL}
            ]
            task = active[0] if active else None
        if task is None:
            status = (
                "**Premium Review**\n"
                f"- Request detected for `{target.handle}`, but no new premium review task was created. "
                "A duplicate review may already be recorded, or current evidence is insufficient for a structured packet."
            )
            return f"{body}\n\n{status}"
        approval = "auto-approved" if task.metadata.get("auto_approved") else task.status.value
        status = (
            "**Premium Review**\n"
            f"- Created or found `{task.kind.value}` task `{task.id}` for `{target.handle}`.\n"
            f"- Status: `{approval}`. Reason: `{reason}`.\n"
            "- The review packet is evidence-linked and cannot approve credential use, scope expansion, PoC execution, or Operator Intent changes."
        )
        return f"{body}\n\n{status}"
