from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from primordial.core.catalog.loader import CatalogValidationError, expect_string_list, load_yaml_file, validate_allowed_fields


@dataclass(slots=True, frozen=True)
class CapabilitySemantic:
    id: str
    category: str
    description: str
    approved_tools: list[str] = field(default_factory=list)
    safe_substitutions: list[str] = field(default_factory=list)
    required_intent_permissions: list[str] = field(default_factory=list)


class CapabilityCatalog:
    FIELDS = {"capabilities"}
    CAPABILITY_FIELDS = {"id", "category", "description", "approved_tools", "safe_substitutions", "required_intent_permissions"}

    def __init__(self, path: Path) -> None:
        self.path = path
        self._capabilities: dict[str, CapabilitySemantic] = {}

    def load(self) -> list[CapabilitySemantic]:
        payload = load_yaml_file(self.path)
        validate_allowed_fields(payload, self.FIELDS, source=str(self.path))
        raw = payload.get("capabilities", [])
        if not isinstance(raw, list):
            raise CatalogValidationError("capabilities must be a list")
        loaded = []
        for index, item in enumerate(raw):
            if not isinstance(item, dict):
                raise CatalogValidationError(f"capabilities[{index}] must be an object")
            validate_allowed_fields(item, self.CAPABILITY_FIELDS, source=f"{self.path}:capabilities[{index}]")
            semantic = CapabilitySemantic(
                id=str(item["id"]),
                category=str(item["category"]),
                description=str(item.get("description", "")),
                approved_tools=expect_string_list(item.get("approved_tools", []), source=f"{item['id']}.approved_tools"),
                safe_substitutions=expect_string_list(item.get("safe_substitutions", []), source=f"{item['id']}.safe_substitutions"),
                required_intent_permissions=expect_string_list(
                    item.get("required_intent_permissions", []),
                    source=f"{item['id']}.required_intent_permissions",
                ),
            )
            self._capabilities[semantic.id] = semantic
            loaded.append(semantic)
        return loaded

    def get(self, capability_id: str) -> CapabilitySemantic | None:
        return self._capabilities.get(capability_id)
