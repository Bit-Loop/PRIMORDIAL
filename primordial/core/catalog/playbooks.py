from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from primordial.core.catalog.interpolation import interpolate_argv
from primordial.core.catalog.loader import CatalogValidationError, expect_string_list, load_yaml_file, validate_allowed_fields


@dataclass(slots=True, frozen=True)
class PlaybookCommand:
    id: str
    capability: str
    tool: str
    argv: list[str]
    timeout_seconds: int = 60
    parser: str | None = None
    required_intents: list[str] = field(default_factory=list)

    def render_argv(self, resolved_tool: str, context: dict[str, Any]) -> list[str]:
        if self.argv and Path(self.argv[0]).name == self.tool:
            raise CatalogValidationError(f"{self.id} argv must not include executable name")
        return [resolved_tool, *interpolate_argv(self.argv, context)]


@dataclass(slots=True, frozen=True)
class PlaybookManifest:
    id: str
    description: str
    commands: list[PlaybookCommand]


class PlaybookCatalog:
    MANIFEST_FIELDS = {"id", "description", "commands"}
    COMMAND_FIELDS = {"id", "capability", "tool", "argv", "timeout_seconds", "parser", "required_intents"}

    def __init__(self, root: Path) -> None:
        self.root = root
        self._playbooks: dict[str, PlaybookManifest] = {}

    def load(self) -> list[PlaybookManifest]:
        loaded = []
        if not self.root.exists():
            return loaded
        for path in sorted(self.root.rglob("*.yaml")):
            manifest = self._from_payload(load_yaml_file(path), source=str(path))
            self._playbooks[manifest.id] = manifest
            loaded.append(manifest)
        return loaded

    def get(self, playbook_id: str) -> PlaybookManifest | None:
        return self._playbooks.get(playbook_id)

    def all(self) -> list[PlaybookManifest]:
        return list(self._playbooks.values())

    def _from_payload(self, payload: dict[str, Any], *, source: str) -> PlaybookManifest:
        validate_allowed_fields(payload, self.MANIFEST_FIELDS, source=source)
        raw_commands = payload.get("commands", [])
        if not isinstance(raw_commands, list):
            raise CatalogValidationError(f"{source} commands must be a list")
        commands = [self._command(item, source=f"{source}:commands[{index}]") for index, item in enumerate(raw_commands)]
        return PlaybookManifest(
            id=str(payload["id"]),
            description=str(payload.get("description", "")),
            commands=commands,
        )

    def _command(self, payload: Any, *, source: str) -> PlaybookCommand:
        if not isinstance(payload, dict):
            raise CatalogValidationError(f"{source} must be an object")
        validate_allowed_fields(payload, self.COMMAND_FIELDS, source=source)
        argv = expect_string_list(payload.get("argv", []), source=f"{source}.argv")
        tool = str(payload["tool"])
        if argv and Path(argv[0]).name == tool:
            raise CatalogValidationError(f"{source}.argv must not include executable name")
        return PlaybookCommand(
            id=str(payload["id"]),
            capability=str(payload["capability"]),
            tool=tool,
            argv=argv,
            timeout_seconds=int(payload.get("timeout_seconds", 60)),
            parser=payload.get("parser") and str(payload["parser"]),
            required_intents=expect_string_list(payload.get("required_intents", []), source=f"{source}.required_intents"),
        )
