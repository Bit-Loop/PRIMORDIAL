from __future__ import annotations

import unittest

from primordial.core.events.bus import EventBus, RuntimeSignal
from primordial.core.modules.registry import ModuleRegistry


class _DummyModule:
    def __init__(self) -> None:
        self.initialized = False
        self.shutdowns = 0

    def initialize(self) -> None:
        self.initialized = True

    def shutdown(self) -> None:
        self.shutdowns += 1


class ModuleRegistryTests(unittest.TestCase):
    def test_registry_loads_lazily_and_emits_lifecycle_signals(self) -> None:
        bus = EventBus()
        registry = ModuleRegistry(bus)
        seen: list[tuple[str, str]] = []
        bus.on(
            RuntimeSignal.MODULE_INITIALIZED,
            lambda event: seen.append((event.signal.value, str(event.payload["module"]))),
        )

        loads = {"count": 0}

        def loader() -> _DummyModule:
            loads["count"] += 1
            return _DummyModule()

        registry.register("dummy", loader, metadata={"kind": "test"})

        self.assertEqual(loads["count"], 0)

        instance = registry.get("dummy")

        self.assertTrue(instance.initialized)
        self.assertEqual(loads["count"], 1)
        self.assertEqual(registry.active_modules(), ["dummy"])
        self.assertEqual(seen, [("module_initialized", "dummy")])

        registry.shutdown_all()

        self.assertEqual(instance.shutdowns, 1)
