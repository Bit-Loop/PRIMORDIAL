from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from primordial.core.catalog.loader import CatalogValidationError, expect_string_list, load_yaml_file, validate_allowed_fields


@dataclass(frozen=True, slots=True)
class ProfileLabelDenial:
    profile: str
    denied_authorizations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AgentRuntimePolicy:
    id: str
    default_operator_intent: str
    authority_sources: tuple[str, ...]
    boundaries: dict[str, str]
    profile_label_denials: tuple[ProfileLabelDenial, ...]
    baseline_forbidden_behaviors: tuple[str, ...]

    def boundary_for(self, source: str) -> str:
        return self.boundaries.get(source, "")

    def profile_label_authorizes(self, profile: str, behavior: str) -> bool:
        for denial in self.profile_label_denials:
            if denial.profile == profile and behavior in denial.denied_authorizations:
                return False
        return True

    def baseline_allows(self, behavior: str) -> bool:
        return behavior not in self.baseline_forbidden_behaviors


class AgentRuntimePolicyCatalog:
    FILENAME = "agent_runtime.yaml"
    FIELDS = {
        "id",
        "default_operator_intent",
        "authority_sources",
        "boundaries",
        "profile_label_denials",
        "baseline_forbidden_behaviors",
    }
    PROFILE_DENIAL_FIELDS = {"profile", "denied_authorizations"}

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def load(self) -> AgentRuntimePolicy:
        path = self.directory / self.FILENAME
        return self._from_payload(load_yaml_file(path), source=str(path))

    def _from_payload(self, payload: dict[str, Any], *, source: str) -> AgentRuntimePolicy:
        validate_allowed_fields(payload, self.FIELDS, source=source)
        return AgentRuntimePolicy(
            id=str(payload.get("id", "")).strip(),
            default_operator_intent=str(payload.get("default_operator_intent", "")).strip(),
            authority_sources=tuple(expect_string_list(payload.get("authority_sources"), source=f"{source}.authority_sources")),
            boundaries=self._boundaries(payload.get("boundaries", {}), source=f"{source}.boundaries"),
            profile_label_denials=tuple(
                self._profile_denial(item, source=f"{source}.profile_label_denials[{index}]")
                for index, item in enumerate(self._list(payload.get("profile_label_denials"), source=f"{source}.profile_label_denials"))
            ),
            baseline_forbidden_behaviors=tuple(
                expect_string_list(payload.get("baseline_forbidden_behaviors"), source=f"{source}.baseline_forbidden_behaviors")
            ),
        )

    def _boundaries(self, payload: Any, *, source: str) -> dict[str, str]:
        if not isinstance(payload, dict):
            raise CatalogValidationError(f"{source} must be an object")
        return {str(key): str(value) for key, value in payload.items()}

    def _profile_denial(self, payload: Any, *, source: str) -> ProfileLabelDenial:
        if not isinstance(payload, dict):
            raise CatalogValidationError(f"{source} must be an object")
        validate_allowed_fields(payload, self.PROFILE_DENIAL_FIELDS, source=source)
        return ProfileLabelDenial(
            profile=str(payload.get("profile", "")).strip(),
            denied_authorizations=tuple(
                expect_string_list(payload.get("denied_authorizations"), source=f"{source}.denied_authorizations")
            ),
        )

    def _list(self, payload: Any, *, source: str) -> list[Any]:
        if payload is None:
            return []
        if not isinstance(payload, list):
            raise CatalogValidationError(f"{source} must be a list")
        return payload
