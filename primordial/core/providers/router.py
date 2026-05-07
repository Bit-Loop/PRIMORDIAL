from __future__ import annotations

from primordial.core.config import ModelTopology
from primordial.core.domain.enums import AgentRole, ProviderRoute, TaskKind
from primordial.core.domain.models import RouteSelection, Task


class ProviderRouter:
    def __init__(self, topology: ModelTopology) -> None:
        self.topology = topology
        # Optional eval-driven overrides: route_key → model_name.
        # Set via apply_eval_recommendations(); consulted in select_route().
        self._eval_overrides: dict[str, str] = {}

    def apply_eval_recommendations(self, recommendations: dict[str, str]) -> dict[str, str]:
        """Update routing with model eval results.

        Accepts the recommendations dict from ModelEvalSummary. Returns a dict
        of {route_key: old_model → new_model} changes that were applied.
        Operator must pass apply=True explicitly to activate; this lets callers
        inspect proposed changes before committing.
        """
        applied: dict[str, str] = {}
        route_map = {
            "local_code": "local_code",
            "poc_generation": "local_code",
            "code_generation": "local_code",
            "local_fast": "local_fast",
            "local_deep": "local_deep",
            "local_compact": "local_compact",
        }
        for key, model in recommendations.items():
            route_key = route_map.get(key)
            if route_key and model:
                old = self._eval_overrides.get(route_key, "")
                if old != model:
                    self._eval_overrides[route_key] = model
                    applied[route_key] = model
        return applied

    def _resolved_model(self, route_key: str, default: str) -> str:
        return self._eval_overrides.get(route_key, default)

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
                model_name=self._resolved_model("local_code", self.topology.local_code),
                rationale=(
                    "mission-critical code and exploit-oriented work should use the slower cold CPU lane "
                    "so it does not compete with the GPU hot-path orchestrator"
                ),
                cold_path=True,
            )
        return RouteSelection(
            route=ProviderRoute.LOCAL_FAST,
            model_name=self._resolved_model("local_fast", self.topology.local_fast),
            rationale="default orchestration and broad analysis stay on the hot path",
        )
