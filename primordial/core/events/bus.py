from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Callable

from primordial.core.domain.models import utc_now


class RuntimeSignal(StrEnum):
    MODULE_REGISTERED = "module_registered"
    MODULE_INITIALIZED = "module_initialized"
    MODULE_SHUTDOWN = "module_shutdown"
    CRASH_RECOVERY_DETECTED = "crash_recovery_detected"
    CRASH_JOURNAL_MARKED = "crash_journal_marked"
    TASK_PLANNED = "task_planned"
    TASK_STARTED = "task_started"
    TASK_DEFERRED = "task_deferred"
    TASK_RESUMED = "task_resumed"
    TASK_FINISHED = "task_finished"
    TASK_CHECKPOINTED = "task_checkpointed"
    WORKER_DISPATCHED = "worker_dispatched"
    NOTIFICATION_DELIVERED = "notification_delivered"
    SYNC_COMPLETED = "sync_completed"


@dataclass(slots=True, frozen=True)
class BusEvent:
    signal: RuntimeSignal
    payload: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=utc_now)


Listener = Callable[[BusEvent], None]


class EventBus:
    def __init__(self, history_limit: int = 200) -> None:
        self._listeners: dict[RuntimeSignal, list[Listener]] = defaultdict(list)
        self._wildcard_listeners: list[Listener] = []
        self._history: deque[BusEvent] = deque(maxlen=history_limit)

    def on(self, signal: RuntimeSignal, listener: Listener) -> None:
        self._listeners[signal].append(listener)

    def on_any(self, listener: Listener) -> None:
        self._wildcard_listeners.append(listener)

    def off(self, signal: RuntimeSignal, listener: Listener) -> None:
        listeners = self._listeners.get(signal)
        if not listeners:
            return
        if listener in listeners:
            listeners.remove(listener)

    def emit(self, signal: RuntimeSignal, payload: dict[str, Any] | None = None) -> BusEvent:
        event = BusEvent(signal=signal, payload=payload or {})
        self._history.append(event)
        for listener in list(self._listeners.get(signal, [])):
            listener(event)
        for listener in list(self._wildcard_listeners):
            listener(event)
        return event

    def recent(self, limit: int | None = None) -> list[BusEvent]:
        events = list(self._history)
        if limit is None:
            return events
        return events[-limit:]
