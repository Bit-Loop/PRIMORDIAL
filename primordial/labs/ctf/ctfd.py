from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from primordial.labs.ctf.hidden_material import reject_hidden_flag_material
from primordial.labs.ctf.sessions import CTF_SOLVE_INTENTS
from primordial.labs.ctf.targets import CTFTarget


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
        for challenge in _record_sequence(challenges, label="challenges"):
            metadata = _challenge_metadata(challenge)
            normalized_challenges[metadata["id"]] = metadata
        raw_scoreboard = _record_mapping(scoreboard, label="scoreboard")
        normalized_scoreboard = {
            str(challenge_id).strip(): _scoreboard_metadata(challenge_id, record)
            for challenge_id, record in raw_scoreboard.items()
        }
        return cls(challenges=normalized_challenges, scoreboard=normalized_scoreboard)

    @classmethod
    def from_closed_book_export(
        cls,
        export: Mapping[str, Any],
        *,
        target: CTFTarget | None = None,
    ) -> FakeCTFdClient:
        reject_hidden_flag_material(export, path="ctfd_export", label="FakeCTFdClient")
        challenges = tuple(_export_challenges(export))
        scoreboard = _export_scoreboard(export)
        client = cls.from_records(challenges=challenges, scoreboard=scoreboard)
        if target is not None:
            _validate_target_export(client, target)
        return client

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
    if not isinstance(value, Mapping):
        raise ValueError("FakeCTFdClient challenges entries must be mappings")
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
    if not isinstance(value, Mapping):
        raise ValueError("FakeCTFdClient scoreboard entries must be mappings")
    reject_hidden_flag_material(value, path="ctfd", label="FakeCTFdClient")
    metadata = dict(value)
    metadata["challenge_id"] = _required(str(challenge_id), "challenge_id")
    return metadata


def _record_sequence(value: Any, *, label: str) -> tuple[Any, ...]:
    if not isinstance(value, list | tuple):
        raise ValueError(f"FakeCTFdClient {label} must be a list")
    return tuple(value)


def _record_mapping(value: Any, *, label: str) -> Mapping[Any, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"FakeCTFdClient {label} must be a mapping")
    return value


def _export_challenges(export: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    raw_challenges = _sequence(_export_value(export, "challenges"), label="challenges")
    challenges = []
    for item in raw_challenges:
        if not isinstance(item, Mapping):
            raise ValueError("FakeCTFdClient CTFd export challenges entries must be mappings")
        challenges.append(_export_challenge(item))
    if not challenges:
        raise ValueError("FakeCTFdClient CTFd export requires challenges")
    return tuple(challenges)


def _export_challenge(challenge: Mapping[str, Any]) -> dict[str, Any]:
    metadata = {
        "id": _required(_first_text(challenge, "id", "challenge_id", "name"), "id"),
        "title": _required(_first_text(challenge, "title", "name"), "title"),
        "category": str(challenge.get("category", "")).strip(),
    }
    for key in ("value", "target_url"):
        if key in challenge:
            metadata[key] = challenge[key]
    if "connection_info" in challenge and "target_url" not in metadata:
        metadata["target_url"] = challenge["connection_info"]
    tags = _export_tags(challenge.get("tags", ()))
    if tags:
        metadata["tags"] = tags
    return metadata


def _export_scoreboard(export: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    raw_scoreboard = export.get("scoreboard", {})
    if raw_scoreboard is None:
        return {}
    if not isinstance(raw_scoreboard, Mapping):
        raise ValueError("FakeCTFdClient CTFd export scoreboard must be a mapping")
    return {str(challenge_id).strip(): _mapping(record) for challenge_id, record in raw_scoreboard.items()}


def _validate_target_export(client: FakeCTFdClient, target: CTFTarget) -> None:
    challenge_id = str(target.scoreboard_ref.get("challenge_id", target.id)).strip() or target.id
    if challenge_id not in client.challenges:
        raise ValueError("FakeCTFdClient CTFd export missing target challenge_id")
    challenge = client.get_challenge(challenge_id)
    target_url = str(challenge.get("target_url", "")).strip()
    if target_url and target_url not in set(target.scope.assets):
        raise ValueError("FakeCTFdClient CTFd export target_url must stay inside target scope")


def _export_value(export: Mapping[str, Any], key: str) -> Any:
    if key in export:
        return export[key]
    data = export.get("data")
    if isinstance(data, Mapping) and key in data:
        return data[key]
    return ()


def _sequence(value: Any, *, label: str) -> tuple[Any, ...]:
    if not isinstance(value, list | tuple):
        raise ValueError(f"FakeCTFdClient CTFd export {label} must be a list")
    return tuple(value)


def _mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("FakeCTFdClient CTFd export scoreboard entries must be mappings")
    return dict(value)


def _first_text(value: Mapping[str, Any], *keys: str) -> str:
    for key in keys:
        text = str(value.get(key, "")).strip()
        if text:
            return text
    return ""


def _export_tags(value: Any) -> tuple[str, ...]:
    if value in (None, ""):
        return ()
    tags = _sequence(value, label="tags")
    normalized = []
    for item in tags:
        if isinstance(item, Mapping):
            tag = _first_text(item, "value", "name")
        else:
            tag = str(item).strip()
        if tag:
            normalized.append(tag)
    return tuple(normalized)


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
