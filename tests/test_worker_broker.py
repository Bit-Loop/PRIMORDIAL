from __future__ import annotations

import unittest

from primordial.core.domain.enums import AgentRole, MethodologyPhase, ProviderRoute, RiskTier, TaskKind
from primordial.core.domain.models import RouteSelection, Task, TaskExecutionResult
from primordial.core.workers import InProcessWorkerRunner, WorkerBroker, WorkerContract


class _Executor:
    def execute(self, task, context):
        return TaskExecutionResult(summary=f"ran {task.kind.value}")


class WorkerBrokerTests(unittest.TestCase):
    def test_dispatch_prefers_role_and_kind_specialized_worker_contract(self) -> None:
        broker = WorkerBroker()
        broker.register_runner(
            InProcessWorkerRunner(
                runner_id="generic-hot",
                lane="hot-path",
                supported_routes={ProviderRoute.COLD_REVIEW},
                executor_loader=lambda: _Executor(),
                max_concurrency=1,
                contract=WorkerContract(
                    name="generic_contract",
                    supported_roles={AgentRole.ANALYSIS_WORKER, AgentRole.CODE_WORKER},
                    preferred_kinds=set(),
                    processor="cpu",
                    quality_tier=50,
                ),
            )
        )
        broker.register_runner(
            InProcessWorkerRunner(
                runner_id="code-cold",
                lane="cold-path",
                supported_routes={ProviderRoute.COLD_REVIEW},
                executor_loader=lambda: _Executor(),
                max_concurrency=1,
                contract=WorkerContract(
                    name="code_contract",
                    supported_roles={AgentRole.CODE_WORKER},
                    preferred_kinds={TaskKind.EXPLOIT_RESEARCH},
                    processor="cpu",
                    quality_tier=90,
                ),
            )
        )
        task = Task(
            target_id="target-1",
            phase=MethodologyPhase.ANALYSIS,
            kind=TaskKind.EXPLOIT_RESEARCH,
            title="Exploit research",
            summary="Research public PoCs",
            role=AgentRole.CODE_WORKER,
            risk_tier=RiskTier.MODERATE,
        )
        selection = RouteSelection(
            route=ProviderRoute.COLD_REVIEW,
            model_name="qwen3-coder-next:q4_K_M",
            rationale="cpu code lane",
            cold_path=True,
        )

        dispatch = broker.dispatch(task, selection)

        self.assertTrue(dispatch.accepted)
        self.assertEqual(dispatch.runner_id, "code-cold")
        self.assertEqual(dispatch.worker_contract, "code_contract")
        self.assertGreater(dispatch.suitability_score, 90)


if __name__ == "__main__":
    unittest.main()
