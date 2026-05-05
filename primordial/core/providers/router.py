from __future__ import annotations

from primordial.core.config import ModelTopology
from primordial.core.domain.enums import AgentRole, ProviderRoute, TaskKind
from primordial.core.domain.models import RouteSelection, Task


class ProviderRouter:
    def __init__(self, topology: ModelTopology) -> None:
        self.topology = topology

    def select_route(self, task: Task) -> RouteSelection:
        if task.kind == TaskKind.COMPACT_MEMORY:
            return RouteSelection(
                route=ProviderRoute.LOCAL_COMPACT,
                model_name=self.topology.local_compact,
                rationale="memory compaction is a hot-path background CPU task",
            )
        if task.kind == TaskKind.REVIEW_PREMIUM_ESCALATION or task.role == AgentRole.CLAUDE_REVIEWER:
            return RouteSelection(
                route=ProviderRoute.REMOTE_PREMIUM,
                model_name=self.topology.remote_premium,
                rationale="premium review is reserved for sparse high-value cognition",
                cold_path=True,
            )
        if task.kind == TaskKind.CHAIN_CANDIDATES:
            return RouteSelection(
                route=ProviderRoute.LOCAL_DEEP,
                model_name=self.topology.local_deep,
                rationale="chain reasoning needs a slower deeper reasoning route",
            )
        if task.kind == TaskKind.VERIFY_HYPOTHESIS:
            return RouteSelection(
                route=ProviderRoute.LOCAL_DEEP,
                model_name=self.topology.local_deep,
                rationale="bounded exploit verification should prefer the deeper reasoning lane",
            )
        if task.kind == TaskKind.VERIFY_AGENT_BEHAVIOR:
            return RouteSelection(
                route=ProviderRoute.LOCAL_COMPACT,
                model_name=self.topology.local_compact,
                rationale="cheap verifier checks should stay off the main GPU path",
            )
        if task.kind in {TaskKind.EXPLOIT_RESEARCH, TaskKind.POC_APPLICABILITY_VALIDATION} or task.role == AgentRole.CODE_WORKER:
            return RouteSelection(
                route=ProviderRoute.COLD_REVIEW,
                model_name=self.topology.local_code,
                rationale=(
                    "mission-critical code and exploit-oriented work should use the slower cold CPU lane "
                    "so it does not compete with the GPU hot-path orchestrator"
                ),
                cold_path=True,
            )
        return RouteSelection(
            route=ProviderRoute.LOCAL_FAST,
            model_name=self.topology.local_fast,
            rationale="default orchestration and broad analysis stay on the hot path",
        )
