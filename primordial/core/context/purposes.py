from __future__ import annotations

from primordial.core.context.normalization import normalized_context_key


OPERATIONAL_CONTEXT_PURPOSES = frozenset(
    {
        "planner",
        "planner_review",
        "planner_uncertainty_review",
        "operator_answer",
        "methodology_hint",
        "vuln_hint",
        "task_generation",
        "task_metadata",
        "patch_planning",
        "action_selection",
        "next_action",
        "tool_execution",
        "exploit_selection",
        "evidence",
        "evidence_review",
        "finding",
        "finding_generation",
        "target_state_answer",
        "current_target_summary",
        "vuln_hint_for_target",
        "notion_export",
        "export",
        "notification",
        "discord_notification",
        "report",
        "report_generation",
        "policy_gate",
        "ctf_solver_context",
        "ctf_benchmark",
        "benchmark_scoring",
        "cleanup",
    }
)


def is_operational_context_purpose(purpose: str) -> bool:
    return normalized_context_key(purpose) in OPERATIONAL_CONTEXT_PURPOSES
