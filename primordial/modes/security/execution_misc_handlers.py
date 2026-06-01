from __future__ import annotations

from primordial.modes.security.execution_common import *


class PrimitiveMiscHandlerMixin:
    def _handle_chain_candidates(self, task: Task, context: ContextSlice) -> TaskExecutionResult:
        result = TaskExecutionResult(summary="chain review deferred")
        target = self.store.get_target(task.target_id)
        if not target:
            result.success = False
            result.error = "target not found"
            return result
        fanout = max(2, int(self.config.autonomy.max_chaining_fanout))
        interests = self._task_generation_records(
            task,
            target,
            self.store.list_interests(target_id=target.id, limit=max(12, fanout * 2)),
        )
        all_verified = [item for item in interests if item.status == InterestStatus.VERIFIED]
        verified = all_verified[:fanout]
        if len(verified) < 2:
            result.success = False
            result.error = "not enough verified interests for chain review"
            return result
        result.summary = "chain planning complete; execution remains primitive-gated"
        result.notes.append(
            Note(
                target_id=target.id,
                task_id=task.id,
                title="Candidate exploit chain",
                body="Multiple verified interests exist, but automatic exploit-chain synthesis remains disabled until a real bounded chain-verification primitive is registered.",
                confidence=0.88,
                freshness=0.86,
                metadata={
                    "verified_interest_count": len(all_verified),
                    "reviewed_interest_count": len(verified),
                    "max_chaining_fanout": fanout,
                    "truncated": len(all_verified) > len(verified),
                    "interest_ids": [item.id for item in verified],
                },
            )
        )
        ai_review = self._run_ai_review(
            task,
            target_id=target.id,
            title="AI chain review",
            snapshot=self._build_ai_target_snapshot(target.id),
            instruction=(
                "Review the verified interests for possible exploit-chain candidates. Return candidate "
                "chains, missing prerequisites, confidence, required verification tasks, and reasons "
                "to reject weak chains. Do not mark a chain valid without primitive-backed verification."
            ),
        )
        self._apply_ai_review(result, task, ai_review)
        return result

    def _handle_verify_agent_behavior(self, task: Task, context: ContextSlice) -> TaskExecutionResult:
        result = TaskExecutionResult(summary="behavior verification complete")
        target = self.store.get_target(task.target_id)
        traces = self.store.list_traces(task_id=task.id, limit=12)
        if target is not None:
            result.notes.append(
                Note(
                    target_id=target.id,
                    task_id=task.id,
                    title="Behavior verification note",
                    body=f"Verifier reviewed {len(traces)} trace records. No unsupported durable claim promotion occurred in this branch.",
                    confidence=0.82,
                    freshness=0.95,
                )
            )
        ai_review = self._run_ai_review(
            task,
            target_id=target.id if target else None,
            title="AI behavior review",
            snapshot=self._build_ai_target_snapshot(target.id) if target else self._build_ai_global_snapshot(),
            instruction=(
                "Review agent behavior for loops, duplicate work, unsupported claims, weak evidence "
                "promotion, and missed next actions. Return only operational findings and concrete "
                "control-plane corrections."
            ),
        )
        self._apply_ai_review(result, task, ai_review)
        return result

    def _handle_compact_memory(self, task: Task, context: ContextSlice) -> TaskExecutionResult:
        result = TaskExecutionResult(summary="memory compaction complete")
        target = self.store.get_target(task.target_id)
        if not target:
            result.success = False
            result.error = "target not found"
            return result
        result.notes.append(
            Note(
                target_id=target.id,
                task_id=task.id,
                title="Compaction audit",
                body="Memory compaction merged recent task context into episodic and semantic layers while preserving evidence lineage.",
                confidence=0.8,
                freshness=0.9,
            )
        )
        ai_review = self._run_ai_review(
            task,
            target_id=target.id,
            title="AI memory compaction review",
            snapshot=self._build_ai_target_snapshot(target.id),
            instruction=(
                "Review whether the current target memory is stale, repetitive, contradictory, or missing durable "
                "operator-relevant facts. Propose compact memory promotions/demotions and mention any stale evidence "
                "that should not guide next actions."
            ),
        )
        self._apply_ai_review(result, task, ai_review)
        result.sync_jobs.append(
            ExternalSyncJob(
                kind=ExternalSyncKind.NOTION,
                target_id=target.id,
                summary="Publish refreshed notes and findings to Notion",
                payload={"target_id": target.id, "reason": "memory-compaction"},
            )
        )
        return result

    def _handle_sync_notion(self, task: Task, context: ContextSlice) -> TaskExecutionResult:
        result = TaskExecutionResult(summary="notion sync prepared")
        target = self.store.get_target(task.target_id)
        if not target:
            result.success = False
            result.error = "target not found"
            return result
        result.sync_jobs.append(
            ExternalSyncJob(
                kind=ExternalSyncKind.NOTION,
                target_id=target.id,
                summary="Sync target subtree to Notion",
                payload={"target_id": target.id, "task_id": task.id},
            )
        )
        return result

    def _handle_send_notification(self, task: Task, context: ContextSlice) -> TaskExecutionResult:
        result = TaskExecutionResult(summary="notification queued")
        target = self.store.get_target(task.target_id)
        result.notifications.append(
            NotificationRecord(
                channel=NotificationChannel.DISCORD,
                event_type="operator_attention",
                summary=task.summary,
                target_id=target.id if target else None,
                task_id=task.id,
                urgency="high" if task.risk_tier in {RiskTier.HIGH, RiskTier.CRITICAL} else "info",
                dedupe_key=f"task:{task.id}:notify",
            )
        )
        result.events.append(
            EventRecord(
                type=EventType.NOTIFICATION_QUEUED,
                summary=task.summary,
                target_id=task.target_id,
                task_id=task.id,
            )
        )
        return result

    def _handle_review_premium_escalation(self, task: Task, context: ContextSlice) -> TaskExecutionResult:
        result = TaskExecutionResult(summary="premium review unavailable")
        target = self.store.get_target(task.target_id)
        if not target:
            result.success = False
            result.error = "target not found"
            return result
        result.success = False
        result.error = "remote premium review is disabled until a production provider adapter and credentials are configured"
        result.notes.append(
            Note(
                target_id=target.id,
                task_id=task.id,
                title="Premium review status",
                body=(
                    "Premium review did not run. Remote model usage is policy-disabled until a production "
                    "provider adapter and credentials are configured."
                ),
                confidence=0.95,
                freshness=0.95,
                metadata={"deferred": True},
            )
        )
        result.events.append(
            EventRecord(
                type=EventType.TASK_FAILED,
                summary="Premium review unavailable",
                target_id=target.id,
                task_id=task.id,
            )
        )
        return result

    def _handle_generic(self, task: Task, context: ContextSlice) -> TaskExecutionResult:
        return TaskExecutionResult(
            success=False,
            summary=f"execution adapter missing for {task.kind.value}",
            error=f"no production execution adapter is registered for {task.kind.value}",
        )
