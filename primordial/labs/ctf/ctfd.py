from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from primordial.labs.ctf.hidden_material import reject_hidden_flag_material
from primordial.labs.ctf.sessions import CTF_SOLVE_INTENTS


@dataclass(frozen=True, slots=True)
class FakeCTFdClient:
    challenges: Mapping[str, dict[str, Any]] = field(default_factory=dict)
    scoreboard: Mapping[str, dict[str, Any]] = field(default_factory=dict)
    submissions: tuple[dict[str, Any], ...] = ()

    @classmethod
    def from_records(
        cls,
        *,
        challenges: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
        scoreboard: Mapping[str, Mapping[str, Any]],
    ) -> FakeCTFdClient:
        normalized_challenges = {}
        for challenge in challenges:
            metadata = _challenge_metadata(challenge)
            normalized_challenges[metadata["id"]] = metadata
        normalized_scoreboard = {
            str(challenge_id).strip(): _scoreboard_metadata(challenge_id, record)
            for challenge_id, record in scoreboard.items()
        }
        return cls(challenges=normalized_challenges, scoreboard=normalized_scoreboard)

    def get_challenge(self, challenge_id: str) -> dict[str, Any]:
        key = _required(challenge_id, "challenge_id")
        if key not in self.challenges:
            raise KeyError(key)
        return dict(self.challenges[key])

    def get_scoreboard(self, challenge_id: str) -> dict[str, Any]:
        key = _required(challenge_id, "challenge_id")
        record = dict(self.scoreboard.get(key, {}))
        record.setdefault("challenge_id", key)
        record.setdefault("solved", False)
        return record

    def submit_flag(
        self,
        *,
        challenge_id: str,
        captured_flag_ref: str,
        active_intent: str,
    ) -> FakeCTFdClient:
        if _required(active_intent, "active_intent") not in CTF_SOLVE_INTENTS:
            raise ValueError("CTFd submission requires active intent that allows CTF solving")
        submission = {
            "challenge_id": _required(challenge_id, "challenge_id"),
            "captured_flag_ref": _evidence_ref(captured_flag_ref, "captured_flag_ref"),
            "status": "submitted",
        }
        return FakeCTFdClient(
            challenges=self.challenges,
            scoreboard=self.scoreboard,
            submissions=self.submissions + (submission,),
        )


def _challenge_metadata(value: Mapping[str, Any]) -> dict[str, Any]:
    reject_hidden_flag_material(value, path="ctfd", label="FakeCTFdClient")
    metadata = {
        "id": _required(str(value.get("id", "")), "id"),
        "title": _required(str(value.get("title", "")), "title"),
        "category": str(value.get("category", "")).strip(),
    }
    for key in ("value", "target_url"):
        if key in value:
            metadata[key] = value[key]
    tags = value.get("tags")
    if tags is not None:
        metadata["tags"] = _text_tuple(tags)
    return metadata


def _scoreboard_metadata(challenge_id: object, value: Mapping[str, Any]) -> dict[str, Any]:
    reject_hidden_flag_material(value, path="ctfd", label="FakeCTFdClient")
    metadata = dict(value)
    metadata["challenge_id"] = _required(str(challenge_id), "challenge_id")
    return metadata


def _required(value: str, name: str) -> str:
    text = str(value).strip()
    if not text:
        raise ValueError(f"FakeCTFdClient requires {name}")
    return text


def _evidence_ref(value: str, name: str) -> str:
    text = _required(value, name)
    if not text.startswith("evidence:"):
        raise ValueError(f"FakeCTFdClient {name} must use evidence:<id>")
    return text


def _text_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list | tuple):
        raise ValueError("FakeCTFdClient tags must be a list")
    return tuple(str(item).strip() for item in value if str(item).strip())
