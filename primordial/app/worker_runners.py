from __future__ import annotations

from typing import Callable

from primordial.core.domain.enums import AgentRole, ProviderRoute, TaskKind
from primordial.core.providers.agent_chat import AgentChatPremiumReviewRunner
from primordial.core.workers import InProcessWorkerRunner, WorkerBroker, WorkerContract


def register_default_worker_runners(
    *,
    worker_broker: WorkerBroker,
    executor_loader: Callable[[], object],
    agent_chat: object,
    target_loader: Callable[[str | None], object],
    remote_cost_recorder: Callable[..., object],
    hot_path_concurrency: int,
    high_risk_concurrency: int,
    cold_path_concurrency: int,
    compact_path_concurrency: int,
    remote_premium_concurrency: int,
) -> None:
    for runner in _security_runners(
        executor_loader=executor_loader,
        hot_path_concurrency=hot_path_concurrency,
        high_risk_concurrency=high_risk_concurrency,
        cold_path_concurrency=cold_path_concurrency,
        compact_path_concurrency=compact_path_concurrency,
    ):
        worker_broker.register_runner(runner)
    worker_broker.register_runner(
        AgentChatPremiumReviewRunner(
            agent_chat,
            target_loader=target_loader,
            remote_cost_recorder=remote_cost_recorder,
            max_concurrency=remote_premium_concurrency,
        )
    )


def _security_runners(
    *,
    executor_loader: Callable[[], object],
    hot_path_concurrency: int,
    high_risk_concurrency: int,
    cold_path_concurrency: int,
    compact_path_concurrency: int,
) -> list[InProcessWorkerRunner]:
    return [
        InProcessWorkerRunner(
            runner_id="security-analysis-runner",
            lane="hot-path",
            supported_routes={ProviderRoute.LOCAL_FAST},
            executor_loader=executor_loader,
            max_concurrency=hot_path_concurrency,
            contract=_analysis_hot_contract(),
        ),
        InProcessWorkerRunner(
            runner_id="security-deep-runner",
            lane="hot-path",
            supported_routes={ProviderRoute.LOCAL_DEEP},
            executor_loader=executor_loader,
            max_concurrency=high_risk_concurrency,
            contract=_deep_reasoning_contract(),
        ),
        InProcessWorkerRunner(
            runner_id="security-code-runner",
            lane="cold-path",
            supported_routes={ProviderRoute.LOCAL_CODE, ProviderRoute.COLD_REVIEW},
            executor_loader=executor_loader,
            max_concurrency=cold_path_concurrency,
            contract=_code_cpu_contract(),
        ),
        InProcessWorkerRunner(
            runner_id="security-compact-runner",
            lane="compact-path",
            supported_routes={ProviderRoute.LOCAL_COMPACT},
            executor_loader=executor_loader,
            max_concurrency=compact_path_concurrency,
            contract=_compact_verifier_contract(),
        ),
    ]


def _analysis_hot_contract() -> WorkerContract:
    return WorkerContract(
        name="analysis_hot_contract",
        supported_roles={AgentRole.ORCHESTRATOR, AgentRole.RECON_WORKER, AgentRole.ANALYSIS_WORKER},
        preferred_kinds={
            TaskKind.RECON_SCAN,
            TaskKind.SERVICE_DISCOVERY,
            TaskKind.DNS_ENUMERATION,
            TaskKind.WEB_CONTENT_DISCOVERY,
            TaskKind.CTF_FLAG_CAPTURE,
            TaskKind.AD_ENUMERATION,
            TaskKind.KERBEROS_USER_DISCOVERY,
            TaskKind.ANALYZE_EVIDENCE,
        },
        processor="gpu",
        quality_tier=82,
    )


def _deep_reasoning_contract() -> WorkerContract:
    return WorkerContract(
        name="deep_reasoning_contract",
        supported_roles={AgentRole.EXPLOITATION_WORKER, AgentRole.CHAINING_WORKER},
        preferred_kinds={
            TaskKind.KERBEROS_ATTACK_CHECK,
            TaskKind.CREDENTIALED_ACCESS_CHECK,
            TaskKind.VERIFY_HYPOTHESIS,
            TaskKind.CHAIN_CANDIDATES,
        },
        processor="gpu",
        quality_tier=88,
    )


def _code_cpu_contract() -> WorkerContract:
    return WorkerContract(
        name="code_cpu_contract",
        supported_roles={AgentRole.CODE_WORKER},
        preferred_kinds={TaskKind.EXPLOIT_RESEARCH, TaskKind.POC_APPLICABILITY_VALIDATION},
        processor="cpu",
        quality_tier=91,
    )


def _compact_verifier_contract() -> WorkerContract:
    return WorkerContract(
        name="compact_verifier_contract",
        supported_roles={AgentRole.MEMORY_WORKER, AgentRole.BEHAVIOR_VERIFIER},
        preferred_kinds={TaskKind.VERIFY_AGENT_BEHAVIOR, TaskKind.COMPACT_MEMORY},
        processor="cpu",
        quality_tier=84,
    )
