from __future__ import annotations

from primordial.app.runtime_deps import (
    assistant_message_from_draft,
    deterministic_state_draft,
    direct_state_draft,
    draft_with_ai_review,
    draft_with_escalation,
    EventRecord,
    guardrail_fallback_draft,
    model_success_draft,
    operator_ai_response_payload,
    operator_ai_route,
    operator_chat_system_prompt,
    operator_message_event,
    operator_question_message,
    operator_response_event,
    OperatorAiDraft,
    OperatorAiRoute,
    OperatorMessage,
    provider_failure_draft,
    Target,
)

class RuntimeOperatorAiMixin:
    def ask_operator_ai(self, message: str, *, target: str | None = None) -> dict[str, object]:
        self.repair_execution_state()
        question = message.strip()
        if not question:
            raise ValueError("message is required")
        target_record = self._resolve_operator_chat_target(target, question)
        route = operator_ai_route(
            wrapper_only=self._use_only_wrapper_mode(),
            wrapper_model=self._wrapper_model_label(),
            local_deep_model=self.config.topology.local_deep,
            num_gpu=self._role_num_gpu("local_deep"),
        )
        operator_message = operator_question_message(question, target_record, target)
        self._persist_operator_chat_message(operator_message, operator_message_event(operator_message))
        draft = self._operator_ai_draft(question, target_record, route)
        draft = self._operator_ai_draft_with_escalation(question, target_record, draft)
        assistant_message = assistant_message_from_draft(draft, target_record)
        self._persist_operator_chat_message(assistant_message, operator_response_event(assistant_message, draft))
        return operator_ai_response_payload(
            draft=draft,
            route=route,
            question=operator_message,
            answer=assistant_message,
            chat=self.operator_chat_payload(target=target),
        )

    def _persist_operator_chat_message(self, message: OperatorMessage, event: EventRecord) -> None:
        self.store.insert_operator_message(message)
        self._write_operator_chat_log(message)
        self.store.insert_event(event)

    def _operator_ai_draft(
        self,
        question: str,
        target: Target | None,
        route: OperatorAiRoute,
    ) -> OperatorAiDraft:
        direct_state_answer = self._operator_state_update_or_direct_answer(question, target)
        if direct_state_answer is not None:
            return direct_state_draft(direct_state_answer, route)
        target_id = target.id if target else None
        if self._should_answer_from_state(question):
            return self._deterministic_operator_ai_draft(question, target_id, route)
        return self._model_operator_ai_draft(question, target_id, route)

    def _deterministic_operator_ai_draft(
        self,
        question: str,
        target_id: str | None,
        route: OperatorAiRoute,
    ) -> OperatorAiDraft:
        deterministic_body = self._deterministic_operator_answer(question, target_id)
        deterministic_only = self._operator_question_requires_deterministic_only(question)
        draft = deterministic_state_draft(
            deterministic_body,
            route,
            ai_review_attempted=not deterministic_only,
        )
        if deterministic_only:
            return draft
        ai_review = self._operator_state_ai_review(
            question=question,
            deterministic_body=deterministic_body,
            target_id=target_id,
            route_model=route.model,
            route_num_gpu=route.num_gpu,
        )
        return draft_with_ai_review(draft, ai_review=ai_review, route=route) if ai_review else draft

    def _model_operator_ai_draft(
        self,
        question: str,
        target_id: str | None,
        route: OperatorAiRoute,
    ) -> OperatorAiDraft:
        rag_context = self._rag_context_payload(question, target_id)
        prompt = self._build_operator_prompt(question, target_id)
        try:
            if self._use_only_wrapper_mode():
                response = self._wrapper_ai_generate(
                    role="operator_chat",
                    system=operator_chat_system_prompt(),
                    prompt=prompt,
                    persist=False,
                )
                body = str(response["text"])
                model = str(response["model"])
                elapsed_seconds = response.get("elapsed_seconds")
            else:
                response = self.ollama.generate(
                    model=route.model,
                    system=operator_chat_system_prompt(),
                    prompt=prompt,
                    num_gpu=route.num_gpu,
                )
                body = response.text
                model = route.model
                elapsed_seconds = response.elapsed_seconds
            draft = model_success_draft(
                body=body,
                model=model,
                elapsed_seconds=elapsed_seconds,
                route=route,
                wrapper_only=self._use_only_wrapper_mode(),
                rag_context_ids=self._rag_context_ids(rag_context),
            )
            return self._operator_ai_guardrailed_draft(question, target_id, rag_context, draft, route)
        except Exception as exc:  # noqa: BLE001 - convert provider failures into durable operator-visible state
            return provider_failure_draft(exc)

    def _operator_ai_guardrailed_draft(
        self,
        question: str,
        target_id: str | None,
        rag_context: list[dict[str, object]],
        draft: OperatorAiDraft,
        route: OperatorAiRoute,
    ) -> OperatorAiDraft:
        if rag_context and not self._operator_answer_cites_rag_context(draft.body, rag_context):
            body = self._deterministic_operator_answer(question, target_id)
            return guardrail_fallback_draft(
                draft,
                body=body,
                route=route,
                reason_key="guardrail_discarded_uncited_rag_output",
            )
        if self._operator_answer_violates_contract(draft.body):
            body = self._deterministic_operator_answer(question, target_id)
            return guardrail_fallback_draft(
                draft,
                body=body,
                route=route,
                reason_key="guardrail_replaced_model_output",
            )
        return draft

    def _operator_ai_draft_with_escalation(
        self,
        question: str,
        target: Target | None,
        draft: OperatorAiDraft,
    ) -> OperatorAiDraft:
        reason = self._operator_uncertainty_escalation_reason(question, draft.body, draft.metadata, target)
        if not reason or target is None:
            return draft
        escalation_task = self.workflow.create_planner_uncertainty_escalation(
            target,
            reason_code=reason,
            question=question,
            blockers=[],
            session_id=self.store.get_active_session().id if self.store.get_active_session() else None,
        )
        body = self._append_operator_escalation_status(
            draft.body,
            target,
            escalation_task=escalation_task,
            reason=reason,
        )
        return draft_with_escalation(draft, body=body, escalation_task=escalation_task, reason=reason)
