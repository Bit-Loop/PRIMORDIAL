from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from primordial.core.config import AutonomySettings
from primordial.core.domain.enums import ProviderRoute, RiskTier, TaskRunStatus
from primordial.core.domain.models import RouteSelection, Task, TaskRun


@dataclass(slots=True)
class LeaseDecision:
    granted: bool
    reason: str
    hot_path: bool
    lane: str
    defer_seconds: int = 20


class ModelScheduler:
    def __init__(self, settings: AutonomySettings) -> None:
        self.settings = settings

    def evaluate(
        self,
        task: Task,
        selection: RouteSelection,
        active_runs: list[TaskRun] | None = None,
    ) -> LeaseDecision:
        running = [
            run
            for run in (active_runs or [])
            if run.status == TaskRunStatus.RUNNING
        ]
        lane_counts = Counter(self._lane_config(run.provider_route)[0] for run in running)
        high_risk_active = sum(
            1
            for run in running
            if run.metadata.get("risk_tier") in {RiskTier.HIGH.value, RiskTier.CRITICAL.value}
        )

        lane, limit, hot_path = self._lane_config(selection.route)
        active_in_lane = lane_counts.get(lane, 0)
        if limit > 0 and active_in_lane >= limit:
            return LeaseDecision(
                granted=False,
                reason=f"{lane} concurrency limit reached",
                hot_path=hot_path,
                lane=lane,
                defer_seconds=self.settings.defer_retry_seconds,
            )
        if task.risk_tier in {RiskTier.HIGH, RiskTier.CRITICAL} and high_risk_active >= self.settings.high_risk_concurrency:
            return LeaseDecision(
                granted=False,
                reason="high-risk execution lane is saturated",
                hot_path=hot_path,
                lane="high-risk",
                defer_seconds=self.settings.defer_retry_seconds,
            )
        return LeaseDecision(
            granted=True,
            reason="route scheduled",
            hot_path=hot_path,
            lane=lane,
            defer_seconds=self.settings.defer_retry_seconds,
        )

    def _lane_config(self, route: ProviderRoute) -> tuple[str, int, bool]:
        if route in {ProviderRoute.LOCAL_FAST, ProviderRoute.LOCAL_DEEP, ProviderRoute.LOCAL_CODE}:
            return ("hot-path", self.settings.hot_path_concurrency, True)
        if route == ProviderRoute.LOCAL_COMPACT:
            return ("compact-path", self.settings.compact_path_concurrency, False)
        if route == ProviderRoute.COLD_REVIEW:
            return ("cold-path", self.settings.cold_path_concurrency, False)
        if route == ProviderRoute.REMOTE_PREMIUM:
            return ("remote-premium", self.settings.remote_premium_concurrency, False)
        return ("generic", 1, False)
