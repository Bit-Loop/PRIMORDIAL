from __future__ import annotations

import json
from pathlib import Path

from primordial.core.domain.enums import (
    MethodologyPhase,
    PrimitiveRuntime,
    RiskTier,
    SideEffectLevel,
)
from primordial.core.domain.models import PrimitiveManifest
from primordial.core.catalog.loader import CatalogValidationError, validate_allowed_fields


class PrimitiveCatalog:
    MANIFEST_FIELDS = {
        "name",
        "version",
        "description",
        "capability_tags",
        "allowed_phases",
        "runtime",
        "risk_tier",
        "side_effect_level",
        "required_secrets",
        "input_schema",
        "output_schema",
        "timeout_seconds",
        "retry_policy",
        "evidence_adapter",
        "sandbox_profile",
        "healthcheck",
        "metadata",
    }

    def __init__(self) -> None:
        self._manifests: dict[str, PrimitiveManifest] = {}

    def load_directory(self, directory: Path) -> list[PrimitiveManifest]:
        loaded: list[PrimitiveManifest] = []
        if not directory.exists():
            return loaded
        for manifest_path in sorted(directory.glob("*.json")):
            payload = json.loads(manifest_path.read_text())
            manifest = self._manifest_from_payload(payload)
            self._manifests[manifest.name] = manifest
            loaded.append(manifest)
        return loaded

    def all(self) -> list[PrimitiveManifest]:
        return list(self._manifests.values())

    def get(self, name: str) -> PrimitiveManifest | None:
        return self._manifests.get(name)

    def by_capability(self, capability: str) -> list[PrimitiveManifest]:
        return [
            manifest
            for manifest in self._manifests.values()
            if capability in manifest.capability_tags
        ]

    def _manifest_from_payload(self, payload: dict[str, object]) -> PrimitiveManifest:
        validate_allowed_fields(payload, self.MANIFEST_FIELDS, source=str(payload.get("name", "primitive manifest")))
        return PrimitiveManifest(
            name=str(payload["name"]),
            version=str(payload.get("version", "0.1.0")),
            description=str(payload.get("description", "")),
            capability_tags=[str(item) for item in payload.get("capability_tags", [])],
            allowed_phases=[
                MethodologyPhase(str(item))
                for item in payload.get("allowed_phases", [MethodologyPhase.RECON.value])
            ],
            runtime=PrimitiveRuntime(str(payload.get("runtime", PrimitiveRuntime.HOST.value))),
            risk_tier=RiskTier(str(payload.get("risk_tier", RiskTier.LOW.value))),
            side_effect_level=SideEffectLevel(
                str(payload.get("side_effect_level", SideEffectLevel.NONE.value))
            ),
            required_secrets=[str(item) for item in payload.get("required_secrets", [])],
            input_schema=dict(payload.get("input_schema", {})),
            output_schema=dict(payload.get("output_schema", {})),
            timeout_seconds=int(payload.get("timeout_seconds", 120)),
            retry_policy=dict(payload.get("retry_policy", {})),
            evidence_adapter=payload.get("evidence_adapter") and str(payload["evidence_adapter"]),
            sandbox_profile=payload.get("sandbox_profile") and str(payload["sandbox_profile"]),
            healthcheck=payload.get("healthcheck") and str(payload["healthcheck"]),
            metadata=dict(payload.get("metadata", {})),
        )
