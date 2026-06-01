from __future__ import annotations

from typing import Any


def persist_model_eval_summary(summary: Any, store: object) -> None:
    from primordial.core.domain.enums import AgentRole, EventType
    from primordial.core.domain.models import AgentTrace, EventRecord

    for result in summary.results:
        store.insert_trace(
            AgentTrace(
                task_id=None,
                role=AgentRole.VALIDATION,
                status="passed" if result.passed else "failed",
                summary=f"ModelEval {result.recommendation_id}/{result.case_id}: score={result.score:.3f} passed={result.passed}",
                metadata={
                    "provider": result.provider,
                    "model": result.model,
                    "recommendation_id": result.recommendation_id,
                    "role_name": result.role_name or result.category,
                    "task_type": "model_evaluation",
                    "stage": result.stage,
                    "case_id": result.case_id,
                    "category": result.category,
                    "score": result.score,
                    "passed": result.passed,
                    "elapsed_seconds": result.elapsed_seconds,
                    "context_length": result.context_length,
                    "prompt_tokens": result.prompt_tokens,
                    "completion_tokens": result.completion_tokens,
                    "tokens_per_second": result.tokens_per_second,
                    "ttft_seconds": result.ttft_seconds,
                    "retry_count": result.retry_count,
                    "reasons": result.reasons,
                },
            )
        )
    store.insert_event(
        EventRecord(
            type=EventType.BOOTSTRAP,
            summary=f"ModelEval completed: {len(summary.models)} models, recommendations={summary.recommendations}",
            metadata=summary.as_payload(),
        )
    )
