from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from primordial.core.events.bus import EventBus, RuntimeSignal


class SupportsLifecycle(Protocol):
    def initialize(self) -> None: ...

    def shutdown(self) -> None: ...


ModuleLoader = Callable[[], Any]


@dataclass(slots=True)
class RegisteredModule:
    name: str
    loader: ModuleLoader
    enabled: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)
    instance: Any | None = None


class ModuleRegistry:
    def __init__(self, event_bus: EventBus | None = None) -> None:
        self._event_bus = event_bus
        self._modules: dict[str, RegisteredModule] = {}
        self._active: list[str] = []

    def register(
        self,
        name: str,
        loader: ModuleLoader,
        *,
        enabled: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self._modules[name] = RegisteredModule(
            name=name,
            loader=loader,
            enabled=enabled,
            metadata=metadata or {},
        )
        if self._event_bus is not None:
            self._event_bus.emit(
                RuntimeSignal.MODULE_REGISTERED,
                {"module": name, "enabled": enabled, "metadata": metadata or {}},
            )

    def get(self, name: str) -> Any:
        module = self._modules[name]
        if not module.enabled:
            raise RuntimeError(f"Module '{name}' is disabled")
        if module.instance is None:
            module.instance = module.loader()
            if hasattr(module.instance, "initialize"):
                module.instance.initialize()
            if name not in self._active:
                self._active.append(name)
            if self._event_bus is not None:
                self._event_bus.emit(
                    RuntimeSignal.MODULE_INITIALIZED,
                    {"module": name, "metadata": module.metadata},
                )
        return module.instance

    def active_modules(self) -> list[str]:
        return list(self._active)

    def shutdown_all(self) -> None:
        for name in reversed(self._active):
            module = self._modules[name]
            if module.instance is not None and hasattr(module.instance, "shutdown"):
                module.instance.shutdown()
            if self._event_bus is not None:
                self._event_bus.emit(
                    RuntimeSignal.MODULE_SHUTDOWN,
                    {"module": name, "metadata": module.metadata},
                )
        self._active.clear()
