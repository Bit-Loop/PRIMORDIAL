from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any, Mapping

from primordial.labs.ctf.hidden_material import reject_hidden_flag_material


CTF_SOLVE_INTENTS = frozenset({"ctf_solve_assisted", "ctf_solve_autonomous_local"})
SOLVED_STATUSES = frozenset({"solved", "complete", "completed"})


@dataclass(frozen=True, slots=True)
class SolveSession:
    id: str
    target_id: str
    engagement_profile: str
    active_intent: str
    policy_version: str
    code_version: str
    model_versions: Mapping[str, str] = field(default_factory=dict)
    started_at: str = ""
    ended_at: str = ""
    actions: tuple[dict[str, Any], ...] = ()
    evidence_ids: tuple[str, ...] = ()
    findings: tuple[str, ...] = ()
    blocked_actions: tuple[dict[str, Any], ...] = ()
    policy_decisions: tuple[dict[str, Any], ...] = ()
    result: str = ""
    solve_status: str = "in_progress"
    report_ref: str = ""

    @classmethod
    def start(
        cls,
        *,
        id: str,
        target_id: str,
        engagement_profile: str,
        active_intent: str,
        policy_version: str,
        code_version: str,
        model_versions: Mapping[str, str],
    ) -> SolveSession:
        payload = {
            "id": id,
            "target_id": target_id,
            "engagement_profile": engagement_profile,
            "active_intent": active_intent,
            "policy_version": policy_version,
            "code_version": code_version,
            "model_versions": dict(model_versions),
        }
        reject_hidden_flag_material(payload, path="solve_session", label="SolveSession")
        return cls(
            id=_required(id, "id"),
            target_id=_required(target_id, "target_id"),
            engagement_profile=_required(engagement_profile, "engagement_profile"),
            active_intent=_required(active_intent, "active_intent"),
            policy_version=_required(policy_version, "policy_version"),
            code_version=_required(code_version, "code_version"),
            model_versions=dict(model_versions),
            started_at=_now_iso(),
        )

    def record_action(
        self,
        *,
        action_id: str,
        action_type: str,
        status: str,
        evidence_ids: list[str] | tuple[str, ...] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> SolveSession:
        action = {
            "action_id": _required(action_id, "action_id"),
            "action_type": _required(action_type, "action_type"),
            "status": _required(status, "status"),
            "evidence_ids": _evidence_ref_tuple(evidence_ids),
            "metadata": dict(metadata or {}),
        }
        reject_hidden_flag_material(action, path="solve_session.action", label="SolveSession")
        return replace(
            self,
            actions=self.actions + (action,),
            evidence_ids=_merge_refs(self.evidence_ids, action["evidence_ids"]),
        )

    def record_blocked_action(
        self,
        *,
        action_id: str,
        reason: str,
        policy_decision_id: str,
    ) -> SolveSession:
        blocked = {
            "action_id": _required(action_id, "action_id"),
            "reason": _required(reason, "reason"),
            "policy_decision_id": _policy_ref(policy_decision_id, "policy_decision_id"),
        }
        reject_hidden_flag_material(blocked, path="solve_session.blocked_action", label="SolveSession")
        return replace(self, blocked_actions=self.blocked_actions + (blocked,))

    def record_policy_decision(
        self,
        *,
        decision_id: str,
        action: str,
        decision: str,
    ) -> SolveSession:
        policy_decision = {
            "decision_id": _policy_ref(decision_id, "decision_id"),
            "action": _required(action, "action"),
            "decision": _required(decision, "decision"),
        }
        reject_hidden_flag_material(policy_decision, path="solve_session.policy_decision", label="SolveSession")
        return replace(self, policy_decisions=self.policy_decisions + (policy_decision,))

    def record_flag_submission(
        self,
        *,
        challenge_id: str,
        captured_flag_ref: str,
        policy_decision_id: str,
    ) -> SolveSession:
        submission = {
            "challenge_id": _required(challenge_id, "challenge_id"),
            "captured_flag_ref": _required(captured_flag_ref, "captured_flag_ref"),
            "policy_decision_id": _policy_ref(policy_decision_id, "policy_decision_id"),
        }
        reject_hidden_flag_material(submission, path="solve_session.flag_submission", label="SolveSession")
        if self.active_intent not in CTF_SOLVE_INTENTS:
            raise ValueError("flag submission requires active intent that allows CTF solving")
        captured_evidence_ref = _evidence_ref(submission["captured_flag_ref"], "captured_flag_ref")
        return self.record_action(
            action_id=f"ctfd_submit:{submission['challenge_id']}",
            action_type="ctfd_flag_submission",
            status="submitted",
            evidence_ids=[captured_evidence_ref],
            metadata={
                "captured_flag_ref": captured_evidence_ref,
                "policy_decision_id": submission["policy_decision_id"],
            },
        )

    def complete(self, *, result: str, solve_status: str, report_ref: str = "") -> SolveSession:
        if solve_status in SOLVED_STATUSES and not self.evidence_ids:
            raise ValueError("solved SolveSession requires supporting evidence")
        completion = {
            "result": _required(result, "result"),
            "solve_status": _required(solve_status, "solve_status"),
            "report_ref": report_ref.strip(),
        }
        reject_hidden_flag_material(completion, path="solve_session.completion", label="SolveSession")
        return replace(
            self,
            result=completion["result"],
            solve_status=completion["solve_status"],
            report_ref=completion["report_ref"],
            ended_at=_now_iso(),
        )


def _required(value: str, name: str) -> str:
    text = str(value).strip()
    if not text:
        raise ValueError(f"SolveSession requires {name}")
    return text


def _evidence_ref_tuple(value: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError("SolveSession evidence_ids must be a list or tuple")
    refs: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError("SolveSession evidence_ids entry must be a string")
        ref = item.strip()
        if not ref.startswith("evidence:"):
            raise ValueError("SolveSession requires evidence_ids entry to use evidence:<id>")
        if ref in refs:
            raise ValueError("SolveSession duplicate evidence_ids entry")
        refs.append(ref)
    return tuple(refs)


def _evidence_ref(value: str, name: str) -> str:
    text = _required(value, name)
    if not text.startswith("evidence:"):
        raise ValueError(f"SolveSession {name} must use evidence:<id>")
    return text


def _policy_ref(value: str, name: str) -> str:
    text = _required(value, name)
    if not text.startswith("policy:"):
        raise ValueError(f"SolveSession {name} must use policy:<id>")
    return text


def _merge_refs(existing: tuple[str, ...], incoming: tuple[str, ...]) -> tuple[str, ...]:
    refs = list(existing)
    for ref in incoming:
        if ref not in refs:
            refs.append(ref)
    return tuple(refs)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()
