from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import yaml


SAFE_ENVIRONMENT = "real_world"
SAFE_DEFAULT_INTENT = "recon_only"


@dataclass(frozen=True, slots=True)
class EnvironmentDefinition:
    id: str
    label: str
    default_intent: str
    verified_lab: bool


@dataclass(frozen=True, slots=True)
class ProfileIntentUpgrade:
    profile: str
    environment: str
    default_intent: str
    requires_environment_proof: bool


@dataclass(frozen=True, slots=True)
class EnvironmentClassification:
    profile: str
    environment: str
    default_intent: str
    verified_lab: bool
    upgrade_applied: bool
    requires_environment_proof: bool
    proof_sources: tuple[str, ...]
    reason: str

    def as_payload(self) -> dict[str, object]:
        return {
            "profile": self.profile,
            "environment": self.environment,
            "default_intent": self.default_intent,
            "verified_lab": self.verified_lab,
            "upgrade_applied": self.upgrade_applied,
            "requires_environment_proof": self.requires_environment_proof,
            "proof_sources": list(self.proof_sources),
            "reason": self.reason,
        }


class EnvironmentClassifier:
    def __init__(
        self,
        *,
        environments: Mapping[str, EnvironmentDefinition],
        profile_upgrades: Mapping[str, ProfileIntentUpgrade],
    ) -> None:
        self.environments = dict(environments)
        self.profile_upgrades = dict(profile_upgrades)

    @classmethod
    def from_goal_file(cls, path: Path) -> "EnvironmentClassifier":
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(payload, Mapping):
            raise ValueError(f"environment goal source must be a mapping: {path}")
        environments: dict[str, EnvironmentDefinition] = {}
        for item in _as_list(payload.get("environments")):
            if not isinstance(item, Mapping):
                continue
            environment_id = _token(item.get("id"))
            if not environment_id:
                continue
            environments[environment_id] = EnvironmentDefinition(
                id=environment_id,
                label=str(item.get("label", environment_id)),
                default_intent=_token(item.get("default_intent")) or SAFE_DEFAULT_INTENT,
                verified_lab=bool(item.get("verified_lab")),
            )
        profile_upgrades: dict[str, ProfileIntentUpgrade] = {}
        for item in _as_list(payload.get("profile_intent_upgrades")):
            if not isinstance(item, Mapping):
                continue
            profile = _token(item.get("profile"))
            environment = _token(item.get("environment"))
            if not profile or not environment:
                continue
            profile_upgrades[profile] = ProfileIntentUpgrade(
                profile=profile,
                environment=environment,
                default_intent=_token(item.get("default_intent")) or SAFE_DEFAULT_INTENT,
                requires_environment_proof=bool(item.get("requires_environment_proof")),
            )
        if SAFE_ENVIRONMENT not in environments:
            environments[SAFE_ENVIRONMENT] = EnvironmentDefinition(
                id=SAFE_ENVIRONMENT,
                label="Real-world authorized target",
                default_intent=SAFE_DEFAULT_INTENT,
                verified_lab=False,
            )
        return cls(environments=environments, profile_upgrades=profile_upgrades)

    @classmethod
    def default(cls) -> "EnvironmentClassifier":
        return cls(
            environments={
                SAFE_ENVIRONMENT: EnvironmentDefinition(
                    id=SAFE_ENVIRONMENT,
                    label="Real-world authorized target",
                    default_intent=SAFE_DEFAULT_INTENT,
                    verified_lab=False,
                )
            },
            profile_upgrades={},
        )

    def classify(
        self,
        *,
        profile: str,
        payload: Mapping[str, Any] | None = None,
        resolved_profile: str | None = None,
        target_metadata: Mapping[str, Any] | None = None,
        asset_metadata: list[Mapping[str, Any]] | None = None,
    ) -> EnvironmentClassification:
        profile_id = _token(profile) or SAFE_ENVIRONMENT
        upgrade = self.profile_upgrades.get(profile_id) or self.profile_upgrades.get(_token(resolved_profile))
        if upgrade is None:
            return self._classification(
                profile=profile_id,
                environment=SAFE_ENVIRONMENT,
                upgrade_applied=False,
                requires_environment_proof=False,
                proof_sources=(),
                reason="no_profile_upgrade",
            )

        proof_sources = self._proof_sources_for_environment(
            upgrade.environment,
            payload=payload,
            target_metadata=target_metadata,
            asset_metadata=asset_metadata,
        )
        if upgrade.requires_environment_proof and not proof_sources:
            return self._classification(
                profile=profile_id,
                environment=SAFE_ENVIRONMENT,
                upgrade_applied=False,
                requires_environment_proof=True,
                proof_sources=(),
                reason="environment_proof_required",
            )

        return self._classification(
            profile=profile_id,
            environment=upgrade.environment,
            default_intent=upgrade.default_intent,
            upgrade_applied=True,
            requires_environment_proof=upgrade.requires_environment_proof,
            proof_sources=tuple(proof_sources),
            reason="profile_upgrade_with_environment_proof" if proof_sources else "profile_upgrade",
        )

    def has_profile_upgrade(self, profile: str) -> bool:
        return _token(profile) in self.profile_upgrades

    def _classification(
        self,
        *,
        profile: str,
        environment: str,
        upgrade_applied: bool,
        requires_environment_proof: bool,
        proof_sources: tuple[str, ...],
        reason: str,
        default_intent: str | None = None,
    ) -> EnvironmentClassification:
        definition = self.environments.get(environment) or self.environments[SAFE_ENVIRONMENT]
        return EnvironmentClassification(
            profile=profile,
            environment=definition.id,
            default_intent=default_intent or definition.default_intent,
            verified_lab=definition.verified_lab,
            upgrade_applied=upgrade_applied,
            requires_environment_proof=requires_environment_proof,
            proof_sources=proof_sources,
            reason=reason,
        )

    def _proof_sources_for_environment(
        self,
        environment: str,
        *,
        payload: Mapping[str, Any] | None,
        target_metadata: Mapping[str, Any] | None,
        asset_metadata: list[Mapping[str, Any]] | None,
    ) -> list[str]:
        sources: list[str] = []
        candidates: list[tuple[str, Mapping[str, Any]]] = []
        if payload:
            candidates.extend(_candidate_mappings("scope_payload", payload))
        if target_metadata:
            candidates.append(("target_metadata", target_metadata))
        for index, item in enumerate(asset_metadata or []):
            candidates.append((f"asset_metadata[{index}]", item))
        for label, item in candidates:
            if _mapping_proves_environment(item, environment):
                sources.append(label)
        return sources


def _candidate_mappings(label: str, value: Mapping[str, Any]) -> list[tuple[str, Mapping[str, Any]]]:
    candidates: list[tuple[str, Mapping[str, Any]]] = [(label, value)]
    for key in ("metadata", "environment_proof", "policy", "provisioning", "scope"):
        nested = value.get(key)
        if isinstance(nested, Mapping):
            candidates.append((f"{label}.{key}", nested))
    targets = value.get("targets")
    if isinstance(targets, list):
        for index, item in enumerate(targets):
            if not isinstance(item, Mapping):
                continue
            candidates.append((f"{label}.targets[{index}]", item))
            metadata = item.get("metadata")
            if isinstance(metadata, Mapping):
                candidates.append((f"{label}.targets[{index}].metadata", metadata))
            for asset_index, asset in enumerate(_as_list(item.get("assets"))):
                if isinstance(asset, Mapping) and isinstance(asset.get("metadata"), Mapping):
                    candidates.append((f"{label}.targets[{index}].assets[{asset_index}].metadata", asset["metadata"]))
    return candidates


def _mapping_proves_environment(value: Mapping[str, Any], environment: str) -> bool:
    explicit_environment = _token(
        value.get("environment_class")
        or value.get("environment")
        or value.get("verified_environment")
        or value.get("runtime_environment")
    )
    if explicit_environment == environment and _truthy(value.get("environment_verified") or value.get("verified_lab")):
        return True
    proof = value.get("environment_proof")
    if isinstance(proof, Mapping) and _mapping_proves_environment(proof, environment):
        return True
    if environment == "local_ctf_container":
        return _has_local_ctf_manifest_shape(value)
    return False


def _has_local_ctf_manifest_shape(value: Mapping[str, Any]) -> bool:
    provisioning = value.get("provisioning")
    scope = value.get("scope")
    mode = _token(provisioning.get("mode")) if isinstance(provisioning, Mapping) else _token(value.get("mode"))
    has_scope = isinstance(scope, Mapping) and bool(_as_list(scope.get("assets")))
    return bool(value.get("lab_id")) and mode in {"docker", "podman", "container"} and has_scope


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return _token(value) in {"1", "true", "yes", "verified"}


def _token(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_")


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []
