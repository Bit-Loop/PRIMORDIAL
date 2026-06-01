from __future__ import annotations

from primordial.core.storage.runtime_common import *


class RuntimeHandoffsMixin:
    def insert_handoff(self, handoff: TaskHandoff) -> None:
        self._execute(
            """
            INSERT INTO task_handoffs
            (id, task_id, source_agent, destination_agent, reason, expected_output_type,
                evidence_refs, hypothesis, budget, deadline_at, status, metadata,
                created_at, consumed_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET task_id = EXCLUDED.task_id, source_agent = EXCLUDED.source_agent, destination_agent = EXCLUDED.destination_agent, reason = EXCLUDED.reason, expected_output_type = EXCLUDED.expected_output_type, evidence_refs = EXCLUDED.evidence_refs, hypothesis = EXCLUDED.hypothesis, budget = EXCLUDED.budget, deadline_at = EXCLUDED.deadline_at, status = EXCLUDED.status, metadata = EXCLUDED.metadata, created_at = EXCLUDED.created_at, consumed_at = EXCLUDED.consumed_at
            """,
            (
                handoff.id,
                handoff.task_id,
                handoff.source_agent.value,
                handoff.destination_agent.value,
                handoff.reason,
                handoff.expected_output_type,
                _dump(handoff.evidence_refs),
                handoff.hypothesis,
                handoff.budget,
                handoff.deadline_at.isoformat() if handoff.deadline_at else None,
                handoff.status.value,
                _dump(handoff.metadata),
                handoff.created_at.isoformat(),
                handoff.consumed_at.isoformat() if handoff.consumed_at else None,
            ),
        )

    def list_handoffs(self, task_id: str | None = None, limit: int = 100) -> list[TaskHandoff]:
        if task_id:
            rows = self._query(
                "SELECT * FROM task_handoffs WHERE task_id = %s ORDER BY created_at DESC LIMIT %s",
                (task_id, limit),
            )
        else:
            rows = self._query("SELECT * FROM task_handoffs ORDER BY created_at DESC LIMIT %s", (limit,))
        return [self._handoff_from_row(row) for row in rows]

    def get_handoff(self, handoff_id: str) -> TaskHandoff | None:
        row = self._query_one("SELECT * FROM task_handoffs WHERE id = %s", (handoff_id,))
        return self._handoff_from_row(row) if row else None

    def consume_handoffs_for_task(self, task: Task, *, limit: int = 100) -> int:
        if not task.target_id:
            return 0
        now = utc_now()
        with closing(self.connect()) as connection:
            rows = list(
                connection.execute(
                    """
                    UPDATE task_handoffs AS handoff
                    SET status = %s, consumed_at = %s, metadata = handoff.metadata || %s
                    FROM tasks AS source_task
                    WHERE handoff.task_id = source_task.id
                      AND source_task.target_id = %s
                      AND handoff.destination_agent = %s
                      AND handoff.status = %s
                      AND handoff.id IN (
                          SELECT h.id
                          FROM task_handoffs h
                          JOIN tasks st ON st.id = h.task_id
                          WHERE st.target_id = %s
                            AND h.destination_agent = %s
                            AND h.status = %s
                          ORDER BY h.created_at ASC
                          LIMIT %s
                      )
                    RETURNING handoff.*
                    """,
                    (
                        HandoffStatus.CONSUMED.value,
                        now.isoformat(),
                        _dump({"consumed_by_task_id": task.id, "consumed_by_task_kind": task.kind.value}),
                        task.target_id,
                        task.role.value,
                        HandoffStatus.OPEN.value,
                        task.target_id,
                        task.role.value,
                        HandoffStatus.OPEN.value,
                        limit,
                    ),
                )
            )
            connection.commit()
        return len(rows)

    def expire_handoffs(self, *, now: Any | None = None, limit: int = 500) -> int:
        effective_now = now or utc_now()
        with closing(self.connect()) as connection:
            rows = list(
                connection.execute(
                    """
                    UPDATE task_handoffs
                    SET status = %s, consumed_at = %s, metadata = metadata || %s
                    WHERE status = %s
                      AND deadline_at IS NOT NULL
                      AND deadline_at <= %s
                      AND id IN (
                          SELECT id
                          FROM task_handoffs
                          WHERE status = %s
                            AND deadline_at IS NOT NULL
                            AND deadline_at <= %s
                          ORDER BY deadline_at ASC
                          LIMIT %s
                      )
                    RETURNING *
                    """,
                    (
                        HandoffStatus.EXPIRED.value,
                        effective_now.isoformat(),
                        _dump({"expired_at": effective_now.isoformat()}),
                        HandoffStatus.OPEN.value,
                        effective_now.isoformat(),
                        HandoffStatus.OPEN.value,
                        effective_now.isoformat(),
                        limit,
                    ),
                )
            )
            connection.commit()
        return len(rows)
