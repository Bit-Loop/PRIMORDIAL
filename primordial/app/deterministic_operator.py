from __future__ import annotations

import json
from typing import Iterable

from primordial.core.domain.models import EvidenceRecord, Target, Task


TARGET_STATE_TERMS = (
    "summarize",
    "summary",
    "next 3",
    "next three",
    "scoped recon",
    "recon steps",
    "latest task fail",
    "last task fail",
    "open port",
    "login portal",
    "port 80",
    "escalate",
    "gpt",
)
OPEN_PORT_TERMS = ("open port", "open ports", "only 2 open", "only two open")
AUTH_SURFACE_TERMS = ("login portal", "login portals", "port 80", "auth surface", "auth surfaces")
PROBLEM_TASK_TERMS = ("latest task fail", "last task fail", "why did the latest task", "failed task", "blocked task")
SCOPED_RECON_TERMS = ("next 3", "next three", "scoped recon", "recon steps")


def operator_question_has_any(lowered_question: str, terms: Iterable[str]) -> bool:
    return any(term in lowered_question for term in terms)


def operator_capability_sets(primitives: Iterable[object]) -> tuple[set[str], set[str]]:
    primitive_names: set[str] = set()
    capabilities: set[str] = set()
    for primitive in primitives:
        name = str(getattr(primitive, "name", "")).strip()
        if name:
            primitive_names.add(name)
            capabilities.add(name)
        capabilities.update(str(tag) for tag in getattr(primitive, "capability_tags", []) if tag)
    return primitive_names, capabilities


def evidence_kind_set(current_evidence: Iterable[EvidenceRecord]) -> set[str]:
    return {
        str(item.metadata.get("kind"))
        for item in current_evidence
        if item.metadata.get("kind")
    }


def flag_evidence_hits(current_evidence: Iterable[EvidenceRecord]) -> list[EvidenceRecord]:
    return [
        item
        for item in current_evidence
        if any(token in json.dumps(item.as_payload()).lower() for token in ("user.txt", "root.txt", "flag{", "htb{"))
    ]


def merge_methodology_next_actions(methodology_state: object, next_actions: Iterable[str]) -> list[str]:
    derived_next_actions = list(next_actions)
    if not isinstance(methodology_state, dict):
        return derived_next_actions
    planned_actions = methodology_state.get("candidate_actions", [])
    if not isinstance(planned_actions, list) or not planned_actions:
        return derived_next_actions
    merged_actions: list[str] = []
    seen_actions: set[str] = set()
    for item in planned_actions[:5]:
        if not isinstance(item, dict):
            continue
        normalized = _methodology_action_line(item)
        lowered = normalized.lower()
        if lowered not in seen_actions:
            merged_actions.append(normalized)
            seen_actions.add(lowered)
    for action in derived_next_actions:
        lowered = action.lower()
        if lowered in seen_actions:
            continue
        merged_actions.append(action)
        seen_actions.add(lowered)
    return merged_actions[:6]


def deterministic_operator_facts(
    *,
    target: Target | None,
    methodology_state: object,
    stale_evidence_count: int,
    current_evidence: list[EvidenceRecord],
    freshness_line: str,
) -> list[str]:
    facts: list[str] = []
    if target:
        facts.append(f"Target `{target.handle}` is `{target.profile.value}` and in_scope={target.in_scope}.")
        active_ip = str(target.metadata.get("active_ip") or "").strip()
        if active_ip:
            facts.append(f"Active operator-confirmed IP is `{active_ip}`.")
        if isinstance(methodology_state, dict) and methodology_state:
            facts.append(
                f"Methodology phase is `{methodology_state.get('phase')}` / `{methodology_state.get('subphase')}` "
                f"with completion state `{methodology_state.get('completion')}`."
            )
        if stale_evidence_count:
            facts.append(f"{stale_evidence_count} recent evidence record(s) are historical for an older active-IP generation.")
    if freshness_line:
        facts.append(freshness_line)
    for item in current_evidence[:6]:
        facts.append(f"`{item.title}`: {item.summary}")
    return facts or ["No target-specific evidence is currently stored."]


def render_deterministic_operator_answer(
    *,
    direct_answers: list[str],
    facts: list[str],
    tasks: list[Task],
    primitive_names: set[str],
    potential_paths: list[str],
    blockers: list[str],
    methodology_state: object,
    next_actions: list[str],
    capability_gaps: list[str],
) -> str:
    task_summary = ", ".join(f"{task.kind.value}:{task.status.value}" for task in tasks[:8]) or "none"
    sections = []
    if direct_answers:
        sections.append("**Direct Answer**\n" + "\n".join(f"- {line}" for line in direct_answers))
    sections.append(
        "**Facts**\n"
        + "\n".join(f"- {fact}" for fact in facts)
        + f"\n- Recent task states: {task_summary}"
        + f"\n- Registered primitives: {', '.join(sorted(primitive_names)) or 'none'}"
    )
    if potential_paths:
        sections.append("**Potential Paths**\n" + "\n".join(f"- {path}" for path in potential_paths))
    sections.append("**Blockers**\n" + "\n".join(f"- {blocker}" for blocker in (blockers or ["No current blockers derived from stored state."])))
    if isinstance(methodology_state, dict) and methodology_state.get("no_progress_reason"):
        sections.append(_planner_state_section(methodology_state))
    sections.append(
        "**Next Actions**\n"
        + "\n".join(f"- {action}" for action in (next_actions or ["No runnable next action is derivable from current evidence."]))
    )
    if capability_gaps:
        sections.append("**Capability Gaps**\n" + "\n".join(f"- {gap}" for gap in capability_gaps))
    return "\n\n".join(sections)


def _methodology_action_line(item: dict[object, object]) -> str:
    line = str(item.get("title") or "Untitled action")
    prerequisite = str(item.get("prerequisite") or "").strip()
    reason = str(item.get("transition_reason") or "").strip()
    confidence = item.get("confidence")
    if prerequisite:
        line += f" Prerequisite: {prerequisite}."
    if confidence not in {None, ""}:
        line += f" Confidence: {float(confidence):.2f}."
    if reason:
        line += f" Reason: {reason}"
    return line.strip()


def _planner_state_section(methodology_state: dict[object, object]) -> str:
    return (
        "**Planner State**\n"
        + "\n".join(
            [
                f"- No progress reason: {methodology_state.get('no_progress_reason')}",
                f"- Next unblock action: {methodology_state.get('next_unblock_action') or 'none'}",
            ]
        )
    )
