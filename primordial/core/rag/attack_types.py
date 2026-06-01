from __future__ import annotations

from dataclasses import dataclass


ATTCK_ALLOWED_USES = [
    "behavior_classification",
    "evidence_mapping",
    "reporting_vocabulary",
    "detection_mitigation_alignment",
]

ATTCK_PROHIBITED_USES = [
    "scope_decision",
    "aggressive_action_selection",
    "authorization_bypass",
    "post_exploitation_planning_outside_authorized_lab",
]


@dataclass(frozen=True, slots=True)
class AttackIndexSpec:
    domain: str
    index_name: str
    source_candidates: tuple[str, ...]


class AttackPreprocessError(RuntimeError):
    pass
