from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from primordial.core.domain.models import PrimitiveManifest, Target, Task
from primordial.core.storage.runtime import RuntimeStore


class ValidationStage(StrEnum):
    TASK_REGISTRATION = "task_registration"
    EXECUTION_PREFLIGHT = "execution_preflight"


class ValidationSeverity(StrEnum):
    WARNING = "warning"
    ERROR = "error"


@dataclass(slots=True, frozen=True)
class ValidationIssue:
    code: str
    message: str
    severity: ValidationSeverity
    metadata: dict[str, object] = field(default_factory=dict)

    @property
    def blocks_progress(self) -> bool:
        return self.severity == ValidationSeverity.ERROR


@dataclass(slots=True)
class ValidationContext:
    task: Task
    target: Target | None
    store: RuntimeStore
    primitives: list[PrimitiveManifest] = field(default_factory=list)


class ValidatorPlugin(Protocol):
    plugin_id: str
    priority: int
    stages: tuple[ValidationStage, ...]

    def validate(self, context: ValidationContext) -> list[ValidationIssue]: ...


class ValidationRegistry:
    def __init__(self) -> None:
        self._plugins: list[ValidatorPlugin] = []

    def register(self, plugin: ValidatorPlugin) -> None:
        self._plugins.append(plugin)
        self._plugins.sort(key=lambda item: item.priority)

    def validate(self, stage: ValidationStage, context: ValidationContext) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []
        for plugin in self._plugins:
            if stage not in plugin.stages:
                continue
            issues.extend(plugin.validate(context))
        return issues
