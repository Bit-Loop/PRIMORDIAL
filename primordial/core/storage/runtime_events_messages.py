from __future__ import annotations

from primordial.core.storage.runtime_common import *


class RuntimeEventsMessagesMixin:
    def insert_event(self, event: EventRecord) -> None:
        self._execute(
            """
            INSERT INTO events
            (id, event_type, target_id, task_id, summary, metadata, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET event_type = EXCLUDED.event_type, target_id = EXCLUDED.target_id, task_id = EXCLUDED.task_id, summary = EXCLUDED.summary, metadata = EXCLUDED.metadata, created_at = EXCLUDED.created_at
            """,
            (
                event.id,
                event.type.value,
                event.target_id,
                event.task_id,
                event.summary,
                _dump(event.metadata),
                event.created_at.isoformat(),
            ),
        )

    def list_events(self, limit: int = 100) -> list[EventRecord]:
        rows = self._query("SELECT * FROM events ORDER BY created_at DESC LIMIT %s", (limit,))
        return [self._event_from_row(row) for row in rows]

    def get_event(self, event_id: str) -> EventRecord | None:
        row = self._query_one("SELECT * FROM events WHERE id = %s", (event_id,))
        return self._event_from_row(row) if row else None

    def insert_operator_message(self, message: OperatorMessage) -> None:
        self._execute(
            """
            INSERT INTO operator_messages
            (id, role, target_id, model, body, metadata, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET role = EXCLUDED.role, target_id = EXCLUDED.target_id, model = EXCLUDED.model, body = EXCLUDED.body, metadata = EXCLUDED.metadata, created_at = EXCLUDED.created_at
            """,
            (
                message.id,
                message.role,
                message.target_id,
                message.model,
                message.body,
                _dump(message.metadata),
                message.created_at.isoformat(),
            ),
        )

    def list_operator_messages(
        self,
        *,
        target_id: str | None = None,
        limit: int = 50,
    ) -> list[OperatorMessage]:
        if target_id:
            rows = self._query(
                """
                SELECT * FROM operator_messages
                WHERE target_id = %s OR target_id IS NULL
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (target_id, limit),
            )
        else:
            rows = self._query("SELECT * FROM operator_messages ORDER BY created_at DESC LIMIT %s", (limit,))
        return [self._operator_message_from_row(row) for row in rows]
