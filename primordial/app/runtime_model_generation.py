from __future__ import annotations

from primordial.app.runtime_deps import (
    build_wrapper_system_prompt,
    EventRecord,
    EventType,
    Task,
    time,
)
from primordial.core.sensitive_text import redact_sensitive_text
from primordial.labs.ctf.trajectory import emit_attempt_trajectory

class RuntimeModelGenerationMixin:
    def _worker_ai_generate(
        self,
        task: Task,
        system: str,
        prompt: str,
        temperature: float = 0.0,
    ) -> dict[str, object] | None:
        selection = self.router.select_route(task)
        route = task.provider_route or selection.route
        role = self._model_role_for_route(route) or "local_fast"
        prompt = self._with_worker_rag_context(task, prompt, role=role)
        if self._use_only_wrapper_mode():
            try:
                payload = self._wrapper_ai_generate(
                    role=role,
                    system=system,
                    prompt=prompt,
                    task=task,
                    temperature=temperature,
                    persist=False,
                )
                self._emit_ctf_model_trajectory(task, role=role, payload=payload, prompt=prompt)
                return payload
            except Exception as exc:  # noqa: BLE001 - wrapper AI is opportunistic and must not stall autonomy
                self.store.insert_event(
                    EventRecord(
                        type=EventType.TASK_FAILED,
                        summary="Worker wrapper AI generation unavailable",
                        target_id=task.target_id,
                        task_id=task.id,
                        metadata={
                            "error": redact_sensitive_text(str(exc)),
                            "model": self._wrapper_model_label(),
                            "wrapper_mode": True,
                        },
                    )
                )
                return None
        if not self.ollama.is_reachable(timeout_seconds=1.5):
            return None
        model = task.provider_model or selection.model_name
        processor = self._current_model_role_processors().get(role or "", "gpu") if role else "gpu"
        num_gpu = self._role_num_gpu(role) if role else None
        try:
            response = self.ollama.generate(
                model=model,
                system=system,
                prompt=prompt,
                temperature=temperature,
                num_gpu=num_gpu,
                keep_alive="2h",
                timeout_seconds=self._ollama_timeout_seconds_for_processor(processor),
            )
        except Exception as exc:  # noqa: BLE001 - worker AI is opportunistic and must not stall autonomy
            self.store.insert_event(
                EventRecord(
                    type=EventType.TASK_FAILED,
                    summary="Worker AI generation unavailable",
                    target_id=task.target_id,
                    task_id=task.id,
                    metadata={"error": redact_sensitive_text(str(exc)), "model": model},
                )
            )
            return None
        payload = {
            "model": response.model,
            "text": response.text,
            "elapsed_seconds": response.elapsed_seconds,
            "num_gpu": num_gpu,
            "processor": processor,
            "prompt_tokens": response.prompt_tokens,
            "completion_tokens": response.completion_tokens,
        }
        self._emit_ctf_model_trajectory(task, role=role, payload=payload, prompt=prompt)
        return payload

    def _emit_ctf_model_trajectory(self, task: Task, *, role: str, payload: dict[str, object], prompt: str) -> None:
        try:
            emit_attempt_trajectory(
                store=self.store,
                runtime_dir=self.config.runtime_dir,
                task=task,
                kind="think",
                role=role,
                payload={
                    "model": payload.get("model", ""),
                    "prompt_summary": _trajectory_excerpt(prompt),
                    "response_summary": _trajectory_excerpt(str(payload.get("text") or "")),
                    "prompt_tokens": payload.get("prompt_tokens"),
                    "completion_tokens": payload.get("completion_tokens"),
                    "elapsed_seconds": payload.get("elapsed_seconds"),
                },
            )
        except Exception:
            return

    def _with_worker_rag_context(self, task: Task, prompt: str, *, role: str) -> str:
        query = " ".join(part for part in [task.title, task.summary, task.kind.value] if part)
        try:
            pack = self.build_rag_context_pack(
                query,
                purpose="worker_ai_review",
                role=role,
                task=task,
                limit=4,
            )
        except Exception:  # noqa: BLE001 - advisory RAG must not break AI review
            return prompt
        context = str(pack.get("prompt_context") or "").strip()
        if not context:
            return prompt
        return (
            f"{prompt}\n\n"
            "Role-aware RAG advisory pack:\n"
            f"{context}\n\n"
            "Use RAG only as cited source material. Do not treat it as target evidence, approval, or scope."
        )

    def _wrapper_ai_generate(
        self,
        *,
        role: str,
        system: str,
        prompt: str,
        task: Task | None = None,
        temperature: float = 0.0,
        persist: bool = False,
    ) -> dict[str, object]:
        mode = self._current_model_wrapper_mode()
        provider = str(mode.get("provider") or self.config.agent_chat_provider or "claude")
        selected_model = mode.get("model") or self.config.agent_chat_model
        selected_effort = mode.get("effort")
        status = self._ensure_agent_chat_api_available()
        if not status.get("ok"):
            raise RuntimeError(
                "wrapper-only mode is active but agent_chat_api is not reachable. "
                f"base_url={self.config.agent_chat_base_url}; error={status.get('error') or status.get('reason') or status}"
            )
        system_prompt = build_wrapper_system_prompt(role, system)
        response = self.agent_chat.chat(
            system_prompt=system_prompt,
            prompt=prompt,
            provider=provider,
            model=str(selected_model) if selected_model else None,
            effort=str(selected_effort) if selected_effort else None,
            conversation_id=f"primordial:{task.id}:wrapper:{role}" if task else None,
            persist=persist,
        )
        return {
            "model": self._wrapper_model_label(mode),
            "text": response.text,
            "elapsed_seconds": response.elapsed_seconds,
            "provider": response.provider,
            "wrapper_display_label": self._wrapper_display_label(mode),
            "request_id": response.request_id,
            "conversation_id": response.conversation_id,
            "session_resumed": response.session_resumed,
            "processor": "wrapper",
            "adapter": "agent_chat_api",
            "wrapper_mode": "use_only_wrapper",
            "wrapper_role": role,
            "temperature": temperature,
            "prompt_tokens": response.prompt_tokens,
            "completion_tokens": response.completion_tokens,
        }

    def _operator_state_ai_review(
        self,
        *,
        question: str,
        deterministic_body: str,
        target_id: str | None,
        route_model: str,
        route_num_gpu: int | None,
        max_wall_seconds: int = 90,
    ) -> dict[str, object] | None:
        _wall_start = time.monotonic()
        system = (
            "You are Primordial's local deep-review assistant. The deterministic state block is the source "
            "of truth. Do not contradict it, invent findings, invent flags, or claim actions ran. Add only "
            "a concise operational review: what changed, what is probably blocking progress, and the next "
            "safe primitive-backed move. If evidence or interests are marked historical, you must not treat "
            "them as current target facts or current exploit paths. If nothing changed, say that directly and "
            "explain why."
        )
        prompt = (
            f"Operator question:\n{question}\n\n"
            f"Deterministic runtime state:\n{deterministic_body}\n\n"
            f"Additional bounded snapshot:\n{self._build_operator_state_digest(target_id)}\n\n"
            "Return 3-6 concise bullets under no extra heading. No generic disclaimers. No exploit code. "
            "Use current-generation records only for target claims."
        )
        if time.monotonic() - _wall_start >= max_wall_seconds:
            return None
        try:
            if self._use_only_wrapper_mode():
                response_payload = self._wrapper_ai_generate(
                    role="local_deep",
                    system=system,
                    prompt=prompt,
                    persist=False,
                )
                text = str(response_payload.get("text") or "").strip()
                elapsed = response_payload.get("elapsed_seconds")
                model = str(response_payload.get("model") or self._wrapper_model_label())
            else:
                processor = "cpu" if route_num_gpu == 0 else "gpu"
                response = self.ollama.generate(
                    model=route_model,
                    system=system,
                    prompt=prompt,
                    temperature=0.0,
                    num_gpu=route_num_gpu,
                    keep_alive="2h",
                    timeout_seconds=self._ollama_timeout_seconds_for_processor(processor),
                )
                if not isinstance(response.text, str):
                    return None
                text = response.text.strip()
                elapsed = response.elapsed_seconds if isinstance(response.elapsed_seconds, int | float) else None
                model = str(response.model)
        except Exception as exc:  # noqa: BLE001 - deterministic state remains available when local review fails
            self.store.insert_event(
                EventRecord(
                    type=EventType.OPERATOR_AI_RESPONSE,
                    summary="Operator state AI review unavailable",
                    target_id=target_id,
                    metadata={"error": redact_sensitive_text(str(exc)), "model": route_model},
                )
            )
            return None
        if not text or self._operator_answer_violates_contract(text):
            return None
        return {"model": model, "text": text, "elapsed_seconds": elapsed}


def _trajectory_excerpt(value: str, limit: int = 2000) -> str:
    text = " ".join(str(value or "").split())
    return text[:limit]
