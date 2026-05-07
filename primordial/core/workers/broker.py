from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Protocol

from primordial.core.domain.enums import AgentRole, ProviderRoute, TaskKind
from primordial.core.domain.models import ContextSlice, RouteSelection, Task, TaskExecutionResult, utc_now
from primordial.core.events.bus import EventBus, RuntimeSignal


@dataclass(slots=True, frozen=True)
class WorkerContract:
    name: str
    supported_roles: set[AgentRole] = field(default_factory=set)
    preferred_kinds: set[TaskKind] = field(default_factory=set)
    processor: str = "gpu"
    quality_tier: int = 50


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
    worker_contract: str | None = None
    suitability_score: int = 0


class WorkerRunner(Protocol):
    runner_id: str
    lane: str
    supported_routes: set[ProviderRoute]
    contract: WorkerContract

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
        contract: WorkerContract,
        offer_ttl_seconds: int = 5,
    ) -> None:
        self.runner_id = runner_id
        self.lane = lane
        self.supported_routes = supported_routes
        self.contract = contract
        self._executor_loader = executor_loader
        self.max_concurrency = max(1, max_concurrency)
        self.offer_ttl_seconds = max(1, offer_ttl_seconds)
        self._running = 0
        self._offers: dict[str, WorkerOffer] = {}
        self._recent_target_id: str | None = None

    def create_offer(self, task: Task, selection: RouteSelection) -> WorkerOffer | None:
        self._drop_stale_offers()
        if selection.route not in self.supported_routes:
            return None
        if self.contract.supported_roles and task.role not in self.contract.supported_roles:
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
                "supports_role": task.role in self.contract.supported_roles if self.contract.supported_roles else True,
                "preferred_kind": task.kind in self.contract.preferred_kinds,
                "headroom": max(0, self.max_concurrency - (self._running + len(self._offers))),
                "target_affinity": bool(task.target_id and task.target_id == self._recent_target_id),
            },
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
            self._recent_target_id = task.target_id
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
        offers: list[tuple[WorkerRunner, WorkerOffer, int]] = []
        for runner in self._runners:
            offer = runner.create_offer(task, selection)
            if offer is not None:
                offers.append((runner, offer, self._score_offer(task, selection, runner, offer)))

        if not offers:
            return BrokerDispatch(
                accepted=False,
                reason="no worker runner capacity was available for the selected lane",
                lane=selection.route.value,
                defer_seconds=20,
                offer_count=0,
            )

        offers.sort(key=lambda item: item[2], reverse=True)
        for runner, offer, score in offers:
            accepted = runner.accept_offer(offer.offer_id, task, selection)
            if not accepted:
                continue
            self._accepted_runners[offer.offer_id] = runner
            dispatch = BrokerDispatch(
                accepted=True,
                reason="worker accepted brokered task offer",
                lane=offer.lane,
                runner_id=offer.runner_id,
                offer_id=offer.offer_id,
                offer_count=len(offers),
                worker_contract=runner.contract.name,
                suitability_score=score,
            )
            if self._event_bus is not None:
                self._event_bus.emit(
                    RuntimeSignal.WORKER_DISPATCHED,
                    {
                        "task_id": task.id,
                        "runner_id": offer.runner_id,
                        "lane": offer.lane,
                        "offer_id": offer.offer_id,
                        "worker_contract": runner.contract.name,
                        "suitability_score": score,
                    },
                )
            return dispatch

        return BrokerDispatch(
            accepted=False,
            reason="all candidate worker offers expired before execution could begin",
            lane=selection.route.value,
            defer_seconds=10,
            offer_count=len(offers),
        )

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
        try:
            result = runner.execute_assignment(dispatch.offer_id, task, context)
        except Exception as exc:
            if self._event_bus is not None:
                self._event_bus.emit(
                    RuntimeSignal.WORKER_FAILED,
                    {"task_id": task.id, "runner_id": dispatch.runner_id, "error": str(exc)},
                )
            raise
        if self._event_bus is not None:
            self._event_bus.emit(
                RuntimeSignal.WORKER_COMPLETED,
                {
                    "task_id": task.id,
                    "runner_id": dispatch.runner_id,
                    "success": result.success if result else False,
                },
            )
        return result

    def _score_offer(
        self,
        task: Task,
        selection: RouteSelection,
        runner: WorkerRunner,
        offer: WorkerOffer,
    ) -> int:
        score = int(offer.metadata.get("quality_tier", 0))
        if offer.metadata.get("supports_role"):
            score += 25
        if offer.metadata.get("preferred_kind"):
            score += 15
        if selection.cold_path and offer.lane in {"cold-path", "remote-premium"}:
            score += 10
        elif not selection.cold_path and offer.lane == "hot-path":
            score += 8
        expected_processor = self._expected_processor(selection.route)
        if offer.metadata.get("processor") == expected_processor:
            score += 6
        if offer.metadata.get("target_affinity"):
            score += 4
        score += min(5, int(offer.metadata.get("headroom", 0) or 0))
        if task.kind in runner.contract.preferred_kinds:
            score += 6
        return score

    def _expected_processor(self, route: ProviderRoute) -> str:
        # LOCAL_COMPACT runs on CPU (phi4-mini / compact models).
        # LOCAL_CODE is GPU-accelerated cold path per CLAUDE.md model topology.
        # COLD_REVIEW is GPU-accelerated offline review.
        if route in {ProviderRoute.LOCAL_COMPACT}:
            return "cpu"
        return "gpu"
