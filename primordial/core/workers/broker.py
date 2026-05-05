from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Protocol

from primordial.core.domain.enums import ProviderRoute
from primordial.core.domain.models import ContextSlice, RouteSelection, Task, TaskExecutionResult, utc_now
from primordial.core.events.bus import EventBus, RuntimeSignal


@dataclass(slots=True, frozen=True)
class WorkerOffer:
    offer_id: str
    runner_id: str
    lane: str
    valid_until: datetime
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class BrokerDispatch:
    accepted: bool
    reason: str
    lane: str | None = None
    runner_id: str | None = None
    offer_id: str | None = None
    result: TaskExecutionResult | None = None
    defer_seconds: int = 30
    offer_count: int = 0


class WorkerRunner(Protocol):
    runner_id: str
    lane: str
    supported_routes: set[ProviderRoute]

    def create_offer(self, task: Task, selection: RouteSelection) -> WorkerOffer | None: ...

    def accept_offer(
        self,
        offer_id: str,
        task: Task,
        selection: RouteSelection,
    ) -> bool: ...

    def execute_assignment(
        self,
        offer_id: str,
        task: Task,
        context: ContextSlice | None,
    ) -> TaskExecutionResult: ...


class InProcessWorkerRunner:
    def __init__(
        self,
        runner_id: str,
        lane: str,
        supported_routes: set[ProviderRoute],
        executor_loader: Callable[[], object],
        *,
        max_concurrency: int,
        offer_ttl_seconds: int = 5,
    ) -> None:
        self.runner_id = runner_id
        self.lane = lane
        self.supported_routes = supported_routes
        self._executor_loader = executor_loader
        self.max_concurrency = max(1, max_concurrency)
        self.offer_ttl_seconds = max(1, offer_ttl_seconds)
        self._running = 0
        self._offers: dict[str, WorkerOffer] = {}

    def create_offer(self, task: Task, selection: RouteSelection) -> WorkerOffer | None:
        self._drop_stale_offers()
        if selection.route not in self.supported_routes:
            return None
        if self._running + len(self._offers) >= self.max_concurrency:
            return None
        offer = WorkerOffer(
            offer_id=f"{self.runner_id}:{task.id}:{len(self._offers) + 1}",
            runner_id=self.runner_id,
            lane=self.lane,
            valid_until=utc_now() + timedelta(seconds=self.offer_ttl_seconds),
            metadata={"route": selection.route.value},
        )
        self._offers[offer.offer_id] = offer
        return offer

    def accept_offer(
        self,
        offer_id: str,
        task: Task,
        selection: RouteSelection,
    ) -> bool:
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
            executor = self._executor_loader()
            return executor.execute(task, context)
        finally:
            self._running = max(0, self._running - 1)

    def _drop_stale_offers(self) -> None:
        now = utc_now()
        stale = [offer_id for offer_id, offer in self._offers.items() if offer.valid_until < now]
        for offer_id in stale:
            self._offers.pop(offer_id, None)


class WorkerBroker:
    def __init__(self, event_bus: EventBus | None = None) -> None:
        self._event_bus = event_bus
        self._runners: list[WorkerRunner] = []
        self._accepted_runners: dict[str, WorkerRunner] = {}

    def register_runner(self, runner: WorkerRunner) -> None:
        self._runners.append(runner)

    def dispatch(
        self,
        task: Task,
        selection: RouteSelection,
    ) -> BrokerDispatch:
        offers: list[tuple[WorkerRunner, WorkerOffer]] = []
        for runner in self._runners:
            offer = runner.create_offer(task, selection)
            if offer is not None:
                offers.append((runner, offer))

        if not offers:
            return BrokerDispatch(
                accepted=False,
                reason="no worker runner capacity was available for the selected lane",
                lane=selection.route.value,
                defer_seconds=20,
                offer_count=0,
            )

        runner, offer = offers[0]
        accepted = runner.accept_offer(offer.offer_id, task, selection)
        if not accepted:
            return BrokerDispatch(
                accepted=False,
                reason="selected worker offer expired before execution could begin",
                lane=offer.lane,
                runner_id=offer.runner_id,
                offer_id=offer.offer_id,
                defer_seconds=10,
                offer_count=len(offers),
            )

        self._accepted_runners[offer.offer_id] = runner
        dispatch = BrokerDispatch(
            accepted=True,
            reason="worker accepted brokered task offer",
            lane=offer.lane,
            runner_id=offer.runner_id,
            offer_id=offer.offer_id,
            offer_count=len(offers),
        )
        if self._event_bus is not None:
            self._event_bus.emit(
                RuntimeSignal.WORKER_DISPATCHED,
                {
                    "task_id": task.id,
                    "runner_id": offer.runner_id,
                    "lane": offer.lane,
                    "offer_id": offer.offer_id,
                },
            )
        return dispatch

    def execute(
        self,
        dispatch: BrokerDispatch,
        task: Task,
        context: ContextSlice | None,
    ) -> TaskExecutionResult | None:
        if not dispatch.accepted or not dispatch.offer_id:
            return None
        runner = self._accepted_runners.pop(dispatch.offer_id, None)
        if runner is None:
            return None
        return runner.execute_assignment(dispatch.offer_id, task, context)
