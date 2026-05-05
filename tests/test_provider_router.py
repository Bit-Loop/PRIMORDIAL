from __future__ import annotations

import unittest

from primordial.config import ModelTopology
from primordial.core.domain.enums import AgentRole, MethodologyPhase, ProviderRoute, TaskKind
from primordial.core.domain.models import Task
from primordial.core.providers.router import ProviderRouter


class ProviderRouterTests(unittest.TestCase):
    def test_exploit_research_uses_cold_cpu_code_lane(self) -> None:
        router = ProviderRouter(ModelTopology())
        task = Task(
            target_id="target-1",
            phase=MethodologyPhase.ANALYSIS,
            kind=TaskKind.EXPLOIT_RESEARCH,
            title="Research public PoCs",
            summary="Search and retain examples for gated review.",
            role=AgentRole.CODE_WORKER,
        )

        route = router.select_route(task)

        self.assertEqual(route.route, ProviderRoute.COLD_REVIEW)
        self.assertEqual(route.model_name, "qwen3-coder-next:q4_K_M")
        self.assertTrue(route.cold_path)

    def test_poc_applicability_validation_uses_cold_cpu_code_lane(self) -> None:
        router = ProviderRouter(ModelTopology())
        task = Task(
            target_id="target-1",
            phase=MethodologyPhase.ANALYSIS,
            kind=TaskKind.POC_APPLICABILITY_VALIDATION,
            title="Validate public PoC applicability",
            summary="Classify retained candidates without execution.",
            role=AgentRole.CODE_WORKER,
        )

        route = router.select_route(task)

        self.assertEqual(route.route, ProviderRoute.COLD_REVIEW)
        self.assertEqual(route.model_name, "qwen3-coder-next:q4_K_M")
        self.assertTrue(route.cold_path)

    def test_general_orchestration_stays_on_hot_path(self) -> None:
        router = ProviderRouter(ModelTopology())
        task = Task(
            target_id="target-1",
            phase=MethodologyPhase.RECON,
            kind=TaskKind.RECON_SCAN,
            title="Probe HTTP surface",
            summary="Collect basic recon evidence.",
            role=AgentRole.RECON_WORKER,
        )

        route = router.select_route(task)

        self.assertEqual(route.route, ProviderRoute.LOCAL_FAST)
        self.assertFalse(route.cold_path)


if __name__ == "__main__":
    unittest.main()
