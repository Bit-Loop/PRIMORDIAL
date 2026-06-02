from __future__ import annotations

from dataclasses import dataclass, replace

from primordial.core.domain.enums import EventType
from primordial.core.domain.models import EventRecord, OperatorMessage, Target, Task
from primordial.core.sensitive_text import redact_sensitive_text


@dataclass(frozen=True, slots=True)
class OperatorAiRoute:
    model: str
    num_gpu: int | None


@dataclass(frozen=True, slots=True)
class OperatorAiDraft:
    body: str
    model: str
    metadata: dict[str, object]
    ok: bool = True
    error: str | None = None


def operator_ai_route(*, wrapper_only: bool, wrapper_model: str, local_deep_model: str, num_gpu: int | None) -> OperatorAiRoute:
    model = wrapper_model if wrapper_only else local_deep_model
    return OperatorAiRoute(model=model, num_gpu=num_gpu)


def operator_chat_system_prompt() -> str:
    return (
        "You are Primordial's operator-facing runtime assistant. Answer only from the supplied "
        "runtime snapshot and recent operator messages. Be concise, cite record IDs when useful, "
        "do not invent findings, credentials, flags, or tool results, and distinguish facts from "
        "next-step recommendations. If a requested action would require a task, approval, or a "
        "new primitive, say so explicitly instead of pretending it has happened. Do not include "
        "generic security disclaimers or generic pentest playbooks; this console is for an "
        "authorized local runtime and needs concrete state-aware answers."
    )


def operator_question_message(question: str, target: Target | None, target_reference: str | None) -> OperatorMessage:
    return OperatorMessage(
        role="operator",
        body=question,
        target_id=target.id if target else None,
        metadata={"target_reference": target_reference},
    )


def assistant_message_from_draft(draft: OperatorAiDraft, target: Target | None) -> OperatorMessage:
    return OperatorMessage(
        role="assistant",
        body=draft.body,
        target_id=target.id if target else None,
        model=draft.model,
        metadata=draft.metadata,
    )


def operator_message_event(message: OperatorMessage) -> EventRecord:
    return EventRecord(
        type=EventType.OPERATOR_MESSAGE,
        summary="Operator message recorded",
        target_id=message.target_id,
        metadata={"message_id": message.id},
    )


def operator_response_event(message: OperatorMessage, draft: OperatorAiDraft) -> EventRecord:
    return EventRecord(
        type=EventType.OPERATOR_AI_RESPONSE,
        summary="Operator AI response recorded" if draft.ok else "Operator AI response failed",
        target_id=message.target_id,
        metadata={"message_id": message.id, "model": draft.model, "ok": draft.ok},
    )


def direct_state_draft(body: str, route: OperatorAiRoute) -> OperatorAiDraft:
    return OperatorAiDraft(
        body=body,
        model="deterministic-state",
        metadata={"ok": True, "mode": "operator_state_reducer", "route_model": route.model},
    )


def deterministic_state_draft(body: str, route: OperatorAiRoute, *, ai_review_attempted: bool) -> OperatorAiDraft:
    return OperatorAiDraft(
        body=body,
        model="deterministic-state",
        metadata={
            "ok": True,
            "mode": "deterministic_state_answer",
            "route_model": route.model,
            "ai_review_attempted": ai_review_attempted,
        },
    )


def draft_with_ai_review(
    draft: OperatorAiDraft,
    *,
    ai_review: dict[str, object],
    route: OperatorAiRoute,
) -> OperatorAiDraft:
    metadata = dict(draft.metadata)
    metadata.update(
        {
            "mode": "deterministic_state_with_local_review",
            "ai_review_model": ai_review["model"],
            "elapsed_seconds": ai_review["elapsed_seconds"],
            "route_num_gpu": route.num_gpu,
        }
    )
    return replace(
        draft,
        body=f"{draft.body}\n\n**AI Review**\n{ai_review['text']}",
        model=str(ai_review["model"]),
        metadata=metadata,
    )


def model_success_draft(
    *,
    body: str,
    model: str,
    elapsed_seconds: object,
    route: OperatorAiRoute,
    wrapper_only: bool,
    rag_context_ids: list[str],
) -> OperatorAiDraft:
    return OperatorAiDraft(
        body=body,
        model=model,
        metadata={
            "elapsed_seconds": elapsed_seconds,
            "ok": True,
            "mode": "wrapper_only" if wrapper_only else "local_model",
            "route_num_gpu": route.num_gpu,
            "rag_context_ids": rag_context_ids,
        },
    )


def guardrail_fallback_draft(draft: OperatorAiDraft, *, body: str, route: OperatorAiRoute, reason_key: str) -> OperatorAiDraft:
    metadata = dict(draft.metadata)
    metadata[reason_key] = True
    metadata["mode"] = "deterministic_state_answer"
    metadata["route_model"] = route.model
    return replace(draft, body=body, model="deterministic-state", metadata=metadata)


def provider_failure_draft(exc: Exception) -> OperatorAiDraft:
    error = redact_sensitive_text(str(exc))
    return OperatorAiDraft(
        body=f"AI response failed: {error}",
        model="deterministic-state",
        metadata={"ok": False, "error": error},
        ok=False,
        error=error,
    )


def draft_with_escalation(
    draft: OperatorAiDraft,
    *,
    body: str,
    escalation_task: Task | None,
    reason: str,
) -> OperatorAiDraft:
    metadata = dict(draft.metadata)
    if escalation_task is not None:
        metadata["planner_uncertainty_escalation_task_id"] = escalation_task.id
        metadata["planner_uncertainty_escalation_reason"] = reason
    return replace(draft, body=body, metadata=metadata)


def operator_ai_response_payload(
    *,
    draft: OperatorAiDraft,
    route: OperatorAiRoute,
    question: OperatorMessage,
    answer: OperatorMessage,
    chat: dict[str, object],
) -> dict[str, object]:
    return {
        "ok": draft.ok,
        "error": draft.error,
        "model": draft.model,
        "route_model": route.model,
        "route_num_gpu": route.num_gpu,
        "question": question.as_payload(),
        "answer": answer.as_payload(),
        "chat": chat,
    }
