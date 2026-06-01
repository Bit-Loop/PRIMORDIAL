from __future__ import annotations

from primordial.core.storage.runtime_common import *


class RuntimeCheckpointsTracesMixin:
    def insert_checkpoint(self, checkpoint: CheckpointRecord) -> None:
        self._execute(
            """
            INSERT INTO checkpoints
            (id, task_id, run_id, kind, path, summary, metadata, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET task_id = EXCLUDED.task_id, run_id = EXCLUDED.run_id, kind = EXCLUDED.kind, path = EXCLUDED.path, summary = EXCLUDED.summary, metadata = EXCLUDED.metadata, created_at = EXCLUDED.created_at
            """,
            (
                checkpoint.id,
                checkpoint.task_id,
                checkpoint.run_id,
                checkpoint.kind.value,
                checkpoint.path,
                checkpoint.summary,
                _dump(checkpoint.metadata),
                checkpoint.created_at.isoformat(),
            ),
        )

    def list_checkpoints(self, limit: int = 100) -> list[CheckpointRecord]:
        rows = self._query("SELECT * FROM checkpoints ORDER BY created_at DESC LIMIT %s", (limit,))
        return [self._checkpoint_from_row(row) for row in rows]

    def get_checkpoint(self, checkpoint_id: str) -> CheckpointRecord | None:
        row = self._query_one("SELECT * FROM checkpoints WHERE id = %s", (checkpoint_id,))
        return self._checkpoint_from_row(row) if row else None

    @staticmethod
    def _normalize_trace_metadata(trace: AgentTrace) -> dict[str, object]:
        metadata = dict(trace.metadata)
        metadata.setdefault("model", "")
        metadata.setdefault("role_name", trace.role.value)
        metadata.setdefault("task_type", str(metadata.get("summary_key") or metadata.get("kind") or "runtime.trace"))
        metadata.setdefault("stage", str(metadata.get("stage") or "runtime"))
        return metadata

    def insert_trace(self, trace: AgentTrace) -> None:
        trace.metadata = self._normalize_trace_metadata(trace)
        self._execute(
            """
            INSERT INTO agent_traces
            (id, task_id, role, status, summary, metadata, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET task_id = EXCLUDED.task_id, role = EXCLUDED.role, status = EXCLUDED.status, summary = EXCLUDED.summary, metadata = EXCLUDED.metadata, created_at = EXCLUDED.created_at
            """,
            (
                trace.id,
                trace.task_id,
                trace.role.value,
                trace.status,
                trace.summary,
                _dump(trace.metadata),
                trace.created_at.isoformat(),
            ),
        )

    def insert_remote_cost(
        self,
        *,
        route: str,
        model: str,
        task_id: str | None = None,
        prompt_tokens: int | None = None,
        completion_tokens: int | None = None,
        estimated_cost_usd: float = 0.0,
    ) -> None:
        self._execute(
            """
            INSERT INTO remote_provider_costs
            (id, route, model, task_id, prompt_tokens, completion_tokens, estimated_cost_usd, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                _new_id("rcost"),
                route,
                model,
                task_id,
                prompt_tokens,
                completion_tokens,
                estimated_cost_usd,
                utc_now().isoformat(),
            ),
        )

    def get_daily_remote_cost_usd(self) -> float:
        rows = self._query(
            """
            SELECT COALESCE(SUM(estimated_cost_usd), 0.0) AS total
            FROM remote_provider_costs
            WHERE created_at >= CURRENT_DATE
            """,
        )
        if rows:
            return float(rows[0]["total"] or 0.0)
        return 0.0

    def list_traces(self, task_id: str | None = None, limit: int = 100) -> list[AgentTrace]:
        if task_id:
            rows = self._query(
                "SELECT * FROM agent_traces WHERE task_id = %s ORDER BY created_at DESC LIMIT %s",
                (task_id, limit),
            )
        else:
            rows = self._query("SELECT * FROM agent_traces ORDER BY created_at DESC LIMIT %s", (limit,))
        return [self._trace_from_row(row) for row in rows]

    def get_trace(self, trace_id: str) -> AgentTrace | None:
        row = self._query_one("SELECT * FROM agent_traces WHERE id = %s", (trace_id,))
        return self._trace_from_row(row) if row else None
