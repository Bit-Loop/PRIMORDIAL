from __future__ import annotations

import json
from datetime import timedelta
from typing import Any, Callable

from primordial.core.domain.enums import (
    AgentRole,
    EventType,
    EvidenceType,
    ProviderRoute,
    TaskKind,
    VerificationStatus,
)
from primordial.core.domain.models import (
    AgentTrace,
    ContextSlice,
    EventRecord,
    EvidenceRecord,
    Note,
    RouteSelection,
    Target,
    Task,
    TaskExecutionResult,
    json_ready,
    utc_now,
)
from primordial.core.providers.agent_chat_client import (
    AgentChatClient,
    AgentChatError,
    AgentChatResponse,
    AgentChatSettings,
)
from primordial.core.sensitive_text import redact_sensitive_text
from primordial.core.workers import WorkerContract, WorkerOffer


class AgentChatPremiumReviewRunner:
    runner_id = "agent-chat-premium-runner"
    lane = "remote-premium"
    supported_routes = {ProviderRoute.REMOTE_PREMIUM}
    contract = WorkerContract(
        name="premium_review_contract",
        supported_roles={AgentRole.CLAUDE_REVIEWER},
        preferred_kinds={TaskKind.REVIEW_PREMIUM_ESCALATION},
        processor="cpu",
        quality_tier=98,
    )

    def __init__(
        self,
        client: AgentChatClient,
        *,
        target_loader: Callable[[str | None], Target | None],
        remote_cost_recorder: Callable[..., None] | None = None,
        max_concurrency: int = 1,
        offer_ttl_seconds: int = 5,
    ) -> None:
        self.client = client
        self._target_loader = target_loader
        self._remote_cost_recorder = remote_cost_recorder
        self.max_concurrency = max(1, max_concurrency)
        self.offer_ttl_seconds = max(1, offer_ttl_seconds)
        self._running = 0
        self._offers: dict[str, WorkerOffer] = {}
        self._recent_target_id: str | None = None

    def create_offer(self, task: Task, selection: RouteSelection) -> WorkerOffer | None:
        self._drop_stale_offers()
        if selection.route not in self.supported_routes:
            return None
        if task.role not in self.contract.supported_roles:
            return None
        if task.kind not in self.contract.preferred_kinds:
            return None
        if self._running + len(self._offers) >= self.max_concurrency:
            return None
        offer = WorkerOffer(
            offer_id=f"{self.runner_id}:{task.id}:{len(self._offers) + 1}",
            runner_id=self.runner_id,
            lane=self.lane,
            valid_until=utc_now() + timedelta(seconds=self.offer_ttl_seconds),
            metadata={
                "route": selection.route.value,
                "contract": self.contract.name,
                "processor": self.contract.processor,
                "quality_tier": self.contract.quality_tier,
                "supports_role": True,
                "preferred_kind": True,
                "headroom": max(0, self.max_concurrency - (self._running + len(self._offers))),
                "target_affinity": bool(task.target_id and task.target_id == self._recent_target_id),
                "adapter": "agent_chat_api",
            },
        )
        self._offers[offer.offer_id] = offer
        return offer

    def accept_offer(self, offer_id: str, task: Task, selection: RouteSelection) -> bool:
        self._drop_stale_offers()
        offer = self._offers.pop(offer_id, None)
        if offer is None or offer.valid_until < utc_now():
            return False
        self._running += 1
        return True

    def execute_assignment(
        self,
        offer_id: str,
        task: Task,
        context: ContextSlice | None,
    ) -> TaskExecutionResult:
        try:
            return self._execute(task, context)
        finally:
            self._running = max(0, self._running - 1)
            self._recent_target_id = task.target_id

    def _execute(self, task: Task, context: ContextSlice | None) -> TaskExecutionResult:
        target = self._target_loader(task.target_id)
        if target is None:
            result = TaskExecutionResult(summary="remote premium review completed")
            result.success = False
            result.summary = "remote premium review failed"
            result.error = "target not found"
            return result

        model = self.client.settings.model
        system_prompt, prompt = self._build_review_prompt(task, target, context)
        try:
            response = self.client.chat(
                system_prompt=system_prompt,
                prompt=prompt,
                model=model,
                conversation_id=f"primordial:{task.id}",
                persist=True,
            )
        except AgentChatError as exc:
            return _remote_review_failure_result(self, task, target, model, exc)

        return _remote_review_success_result(self, task, target, response, model)

    def _record_remote_cost(self, task: Task, response: AgentChatResponse) -> dict[str, object]:
        estimated_cost = self._estimated_remote_cost(task, response)
        payload: dict[str, object] = {
            "recorded": False,
            "route": ProviderRoute.REMOTE_PREMIUM.value,
            "model": response.model or self.client.settings.model or "provider-default",
            "prompt_tokens": response.prompt_tokens,
            "completion_tokens": response.completion_tokens,
            "estimated_cost_usd": estimated_cost,
        }
        if self._remote_cost_recorder is None:
            return payload
        try:
            self._remote_cost_recorder(
                route=ProviderRoute.REMOTE_PREMIUM.value,
                model=str(payload["model"]),
                task_id=task.id,
                prompt_tokens=response.prompt_tokens,
                completion_tokens=response.completion_tokens,
                estimated_cost_usd=estimated_cost,
            )
        except Exception as exc:  # noqa: BLE001 - cost telemetry must not hide a completed review
            payload["error"] = _redact_agent_chat_text(str(exc))
            return payload
        payload["recorded"] = True
        return payload

    def _estimated_remote_cost(self, task: Task, response: AgentChatResponse) -> float:
        if response.estimated_cost_usd > 0:
            return response.estimated_cost_usd
        raw = task.metadata.get("estimated_remote_cost_usd", 0.0)
        try:
            return max(0.0, float(raw))
        except (TypeError, ValueError):
            return 0.0

    def _build_review_prompt(
        self,
        task: Task,
        target: Target,
        context: ContextSlice | None,
    ) -> tuple[str, str]:
        package = task.metadata.get("escalation_package")
        package_payload = package if isinstance(package, dict) else {}
        context_payload = {
            "summary": context.summary if context else "",
            "recent_evidence": [
                {
                    "id": item.id,
                    "title": item.title,
                    "summary": item.summary,
                    "verification_status": item.verification_status.value,
                }
                for item in (context.recent_evidence[:25] if context else [])
            ],
            "recent_interests": [
                {"id": item.id, "title": item.title, "summary": item.summary, "status": item.status.value}
                for item in (context.recent_interests[:12] if context else [])
            ],
        }
        system_prompt = (
            "You are a remote premium reviewer for Primordial, a policy-gated authorized security runtime. "
            "Use only the supplied escalation package and evidence summaries. Recommend or classify only. "
            "Do not approve credential use, expand target scope, execute tools, generate exploit code, provide "
            "public PoC instructions, or override Operator Intent. Return one JSON object only."
        )
        package_metadata = package_payload.get("metadata") if isinstance(package_payload, dict) else {}
        package_metadata = package_metadata if isinstance(package_metadata, dict) else {}
        prompt = {
            "task": {
                "id": task.id,
                "kind": task.kind.value,
                "title": task.title,
                "summary": task.summary,
                "role": task.role.value,
                "evidence_refs": task.evidence_refs,
            },
            "target": target.as_payload(),
            "escalation_package": package_payload,
            "context": context_payload,
            "required_output": package_metadata.get("required_output")
            or package_payload.get("required_output")
            or {
                "recommended_next_actions": "array<object>",
                "missing_evidence": "array<string>",
                "invalid_existing_tasks": "array<object>",
                "primitive_gaps": "array<string>",
                "confidence": "number",
                "rationale_with_evidence_refs": "array<object>",
            },
            "output_rules": [
                "Return JSON only, with no markdown fences.",
                "Every recommended_next_actions item must include title, rationale, confidence, primitive_hint, and evidence_refs.",
                "Use exact primitive_hint values when applicable: content-discovery, http-probe, tcp-service-discovery.",
                "Only reference evidence IDs supplied in task.evidence_refs or the escalation package.",
                "Leave recommended_next_actions empty when evidence or policy is insufficient.",
            ],
        }
        return system_prompt, json.dumps(json_ready(prompt), indent=2, sort_keys=True)

    def _render_note(self, response: AgentChatResponse, *, structured: bool) -> str:
        lines = [
            f"Agent chat provider: {response.provider}",
            f"Model: {response.model or 'provider-default'}",
            f"Request ID: {response.request_id or 'unknown'}",
            f"Structured output: {structured}",
        ]
        if response.warnings:
            lines.append("Warnings: " + "; ".join(_redact_agent_chat_value(response.warnings)))
        if response.text:
            lines.append("")
            lines.append(_redact_agent_chat_text(response.text)[:4000])
        return "\n".join(lines)

    def _trace(
        self,
        task: Task,
        *,
        status: str,
        summary: str,
        model: str | None,
        provider: str,
        metadata: dict[str, Any] | None = None,
    ) -> AgentTrace:
        return AgentTrace(
            task_id=task.id,
            role=task.role,
            status=status,
            summary=summary,
            metadata={
                "model": model or provider,
                "role_name": task.role.value,
                "task_type": task.kind.value,
                "stage": "remote_premium_review",
                "provider": provider,
                "processor": "agent_chat_api",
                **(metadata or {}),
            },
        )

    def _expected_output_type(self, task: Task) -> str | None:
        package = task.metadata.get("escalation_package")
        if isinstance(package, dict):
            value = package.get("expected_output_type")
            return str(value) if value else None
        return None

    def _drop_stale_offers(self) -> None:
        now = utc_now()
        stale = [offer_id for offer_id, offer in self._offers.items() if offer.valid_until < now]
        for offer_id in stale:
            self._offers.pop(offer_id, None)


def _remote_review_failure_result(
    runner: AgentChatPremiumReviewRunner,
    task: Task,
    target: Target,
    model: str | None,
    exc: AgentChatError,
) -> TaskExecutionResult:
    result = TaskExecutionResult(summary="remote premium review failed")
    result.success = False
    result.error = _redact_agent_chat_text(str(exc))
    result.traces.append(
        runner._trace(
            task,
            status="failed",
            summary="Agent chat API call failed",
            model=model,
            provider=runner.client.settings.provider,
            metadata={"error": _redact_agent_chat_text(str(exc))},
        )
    )
    result.events.append(
        EventRecord(
            type=EventType.TASK_FAILED,
            summary="Remote premium review failed",
            target_id=target.id,
            task_id=task.id,
            metadata={"error": _redact_agent_chat_text(str(exc)), "adapter": "agent_chat_api"},
        )
    )
    return result


def _remote_review_success_result(
    runner: AgentChatPremiumReviewRunner,
    task: Task,
    target: Target,
    response: AgentChatResponse,
    model: str | None,
) -> TaskExecutionResult:
    review = parse_review_json(response.text)
    structured = isinstance(review, dict)
    cost_payload = runner._record_remote_cost(task, response)
    summary = _remote_review_summary(structured)
    result = TaskExecutionResult(summary=summary)
    result.traces.append(_remote_review_trace(runner, task, response, model, structured, summary, cost_payload))
    result.evidence.append(
        _remote_review_evidence(runner, task, target, response, model, structured, review, summary, cost_payload)
    )
    result.notes.append(_remote_review_note(runner, task, target, response, structured))
    result.events.append(_remote_review_event(task, target, response, model, structured, summary, cost_payload))
    return result


def _remote_review_summary(structured: bool) -> str:
    if structured:
        return "Remote premium review returned structured planner output."
    return "Remote premium review returned unstructured output; deterministic admission will reject it."


def _remote_review_trace(
    runner: AgentChatPremiumReviewRunner,
    task: Task,
    response: AgentChatResponse,
    model: str | None,
    structured: bool,
    summary: str,
    cost_payload: dict[str, object],
) -> AgentTrace:
    return runner._trace(
        task,
        status="completed" if structured else "parse_failed",
        summary=summary,
        model=response.model or model,
        provider=response.provider,
        metadata={
            "request_id": response.request_id,
            "conversation_id": response.conversation_id,
            "elapsed_seconds": response.elapsed_seconds,
            "session_resumed": response.session_resumed,
            "warnings": _redact_agent_chat_value(response.warnings),
            "structured_output": structured,
            "remote_cost": _redact_agent_chat_value(cost_payload),
        },
    )


def _remote_review_evidence(
    runner: AgentChatPremiumReviewRunner,
    task: Task,
    target: Target,
    response: AgentChatResponse,
    model: str | None,
    structured: bool,
    review: dict[str, Any] | None,
    summary: str,
    cost_payload: dict[str, object],
) -> EvidenceRecord:
    return EvidenceRecord(
        target_id=target.id,
        task_id=task.id,
        type=EvidenceType.MODEL_REVIEW,
        title=f"Remote premium review: {target.handle}",
        summary=summary,
        source_ref=f"agent-chat-api:{response.request_id or task.id}",
        verification_status=VerificationStatus.PARTIAL if structured else VerificationStatus.UNVERIFIED,
        confidence=float(review.get("confidence", 0.65)) if structured and review is not None else 0.45,
        freshness=0.95,
        metadata={
            "kind": "premium_review_result",
            "review": _redact_agent_chat_value(review) if structured else {},
            "response_text": _redact_agent_chat_text(response.text),
            "structured_output": structured,
            "provider": response.provider,
            "model": response.model or model or "provider-default",
            "request_id": response.request_id,
            "conversation_id": response.conversation_id,
            "adapter": "agent_chat_api",
            "expected_output_type": runner._expected_output_type(task),
            "remote_cost": _redact_agent_chat_value(cost_payload),
        },
    )


def _remote_review_note(
    runner: AgentChatPremiumReviewRunner,
    task: Task,
    target: Target,
    response: AgentChatResponse,
    structured: bool,
) -> Note:
    return Note(
        target_id=target.id,
        task_id=task.id,
        title="Remote premium review status",
        body=runner._render_note(response, structured=structured),
        confidence=0.75 if structured else 0.55,
        freshness=0.95,
        metadata={
            "kind": "remote_premium_review_note",
            "structured_output": structured,
            "request_id": response.request_id,
            "adapter": "agent_chat_api",
        },
    )


def _remote_review_event(
    task: Task,
    target: Target,
    response: AgentChatResponse,
    model: str | None,
    structured: bool,
    summary: str,
    cost_payload: dict[str, object],
) -> EventRecord:
    return EventRecord(
        type=EventType.ESCALATION_REVIEWED,
        summary=summary,
        target_id=target.id,
        task_id=task.id,
        metadata={
            "adapter": "agent_chat_api",
            "provider": response.provider,
            "model": response.model or model or "provider-default",
            "structured_output": structured,
            "remote_cost": _redact_agent_chat_value(cost_payload),
        },
    )


def parse_review_json(text: str) -> dict[str, Any] | None:
    stripped = text.strip()
    if not stripped:
        return None
    candidates = [stripped]
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        candidates.append("\n".join(lines).strip())
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start >= 0 and end > start:
        candidates.append(stripped[start : end + 1])
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _redact_agent_chat_text(value: object) -> str:
    return redact_sensitive_text(str(value or ""))


def _redact_agent_chat_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _redact_agent_chat_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_agent_chat_value(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_agent_chat_value(item) for item in value]
    if isinstance(value, str):
        return _redact_agent_chat_text(value)
    return value
