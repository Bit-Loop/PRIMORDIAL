from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from primordial.core.domain.enums import EventType, TaskStatus
from primordial.core.domain.models import EventRecord, Task, utc_now
from primordial.core.events.bus import EventBus, RuntimeSignal
from primordial.core.storage.runtime import RuntimeStore


@dataclass(slots=True, frozen=True)
class DeferredTaskState:
    task_id: str
    resume_after: str
    reason: str


class ResumeTracker:
    def __init__(self, store: RuntimeStore, event_bus: EventBus | None = None) -> None:
        self.store = store
        self.event_bus = event_bus

    def defer_task(
        self,
        task: Task,
        reason: str,
        *,
        delay_seconds: int = 20,
        metadata: dict[str, object] | None = None,
    ) -> DeferredTaskState:
        resume_after = utc_now() + timedelta(seconds=max(1, delay_seconds))
        task.status = TaskStatus.WAITING
        task.metadata["wait_reason"] = reason
        task.metadata["resume_after"] = resume_after.isoformat()
        task.metadata["deferred_runs"] = int(task.metadata.get("deferred_runs", 0)) + 1
        if metadata:
            task.metadata["wait_metadata"] = dict(metadata)
        self.store.insert_task(task)
        self.store.insert_event(
            EventRecord(
                type=EventType.TASK_DEFERRED,
                summary=reason,
                target_id=task.target_id,
                task_id=task.id,
                metadata={"resume_after": resume_after.isoformat()},
            )
        )
        if self.event_bus is not None:
            self.event_bus.emit(
                RuntimeSignal.TASK_DEFERRED,
                {
                    "task_id": task.id,
                    "target_id": task.target_id,
                    "resume_after": resume_after.isoformat(),
                },
            )
        return DeferredTaskState(task_id=task.id, resume_after=resume_after.isoformat(), reason=reason)

    def resume_due_tasks(self, limit: int = 100) -> int:
        resumed = 0
        now = utc_now()
        for task in self.store.list_tasks(statuses=(TaskStatus.WAITING,), limit=limit):
            resume_after_raw = task.metadata.get("resume_after")
            if not isinstance(resume_after_raw, str):
                task.status = TaskStatus.PENDING
            else:
                resume_after = datetime.fromisoformat(resume_after_raw)
                if resume_after > now:
                    continue
                task.status = TaskStatus.PENDING
            task.metadata["resumed_at"] = now.isoformat()
            self.store.insert_task(task)
            self.store.insert_event(
                EventRecord(
                    type=EventType.TASK_RESUMED,
                    summary=f"Resumed deferred task: {task.title}",
                    target_id=task.target_id,
                    task_id=task.id,
                )
            )
            if self.event_bus is not None:
                self.event_bus.emit(
                    RuntimeSignal.TASK_RESUMED,
                    {"task_id": task.id, "target_id": task.target_id},
                )
            resumed += 1
        return resumed
