from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Callable

from primordial.core.config import AppConfig
from primordial.core.credentials import CredentialStore
from primordial.core.primitives.catalog import PrimitiveCatalog
from primordial.core.storage.runtime import RuntimeStore
from primordial.modes.security.execution import AiGenerateCallable, PrimitiveExecutor
from primordial.modes.security.memory import MemoryService


@dataclass(slots=True)
class SecurityModeServices:
    memory_service: MemoryService
    primitive_executor: PrimitiveExecutor


def build_security_mode_services(
    store: RuntimeStore,
    catalog: PrimitiveCatalog,
    config: AppConfig,
    credentials: CredentialStore,
    ai_generate: AiGenerateCallable | None = None,
    active_intent_policy_loader: Callable | None = None,
    active_intent_id_loader: Callable | None = None,
) -> SecurityModeServices:
    return SecurityModeServices(
        memory_service=MemoryService(store),
        primitive_executor=PrimitiveExecutor(
            store,
            catalog,
            config,
            credentials,
            ai_generate=ai_generate,
            active_intent_policy_loader=active_intent_policy_loader,
            active_intent_id_loader=active_intent_id_loader,
        ),
    )
