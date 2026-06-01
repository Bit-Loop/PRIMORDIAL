from __future__ import annotations

from primordial.app.runtime_deps import (
    EventRecord,
    EventType,
    ProviderRoute,
)

class RuntimeModelRolesMixin:
    def _current_model_roles(self) -> dict[str, str]:
        stored = self.store.get_setting("model_roles", {})
        roles = {
            role: str(getattr(self.config.topology, str(config["topology_field"])))
            for role, config in self.MODEL_ROLE_CONFIG.items()
        }
        if isinstance(stored, dict):
            for role, model in stored.items():
                if role in roles and isinstance(model, str) and model.strip():
                    roles[role] = model.strip()
        return roles

    def _current_model_role_processors(self) -> dict[str, str]:
        stored = self.store.get_setting("model_role_processors", {})
        processors = {
            role: str(config["processor"])
            for role, config in self.MODEL_ROLE_CONFIG.items()
        }
        if isinstance(stored, dict):
            for role, processor in stored.items():
                if role in processors and isinstance(processor, str):
                    normalized = processor.strip().lower()
                    if normalized in {"gpu", "cpu"}:
                        processors[role] = normalized
        return processors

    def _role_num_gpu(self, role: str) -> int | None:
        return self._processor_num_gpu(self._current_model_role_processors().get(role, "gpu"))

    def _processor_num_gpu(self, processor: str) -> int | None:
        return 0 if processor == "cpu" else None

    def _ollama_timeout_seconds_for_processor(self, processor: str) -> int:
        tuning = self.runtime_tuning_payload()
        if processor == "cpu":
            return int(tuning["cpu_ai_timeout_seconds"])
        return int(tuning["gpu_ai_timeout_seconds"])

    def _model_role_for_route(self, route: ProviderRoute | None) -> str | None:
        if route == ProviderRoute.LOCAL_FAST:
            return "local_fast"
        if route == ProviderRoute.LOCAL_DEEP:
            return "local_deep"
        if route == ProviderRoute.LOCAL_COMPACT:
            return "local_compact"
        if route in {ProviderRoute.LOCAL_CODE, ProviderRoute.COLD_REVIEW}:
            return "local_code"
        return None

    def _apply_persisted_model_roles(self) -> None:
        self._apply_model_roles(self._current_model_roles())

    def _apply_model_roles(self, roles: dict[str, str]) -> None:
        for role, model in roles.items():
            config = self.MODEL_ROLE_CONFIG.get(role)
            if not config:
                continue
            setattr(self.config.topology, str(config["topology_field"]), model)

    def _validate_topology_models(self) -> None:
        """Check that configured topology model names exist in Ollama; emit warnings for missing models."""
        if self._use_only_wrapper_mode():
            self.store.insert_event(
                EventRecord(
                    type=EventType.BOOTSTRAP,
                    summary="Topology model validation skipped for use-only-wrapper mode",
                    metadata={"wrapper_mode": self.model_wrapper_mode_payload()},
                )
            )
            return
        import logging
        result = self.ollama.list_models()
        if not result.ok:
            logging.getLogger(__name__).warning(
                "Ollama unreachable at startup — cannot validate topology models: %s", result.error
            )
            return
        installed = set(result.models)
        installed.update(model.removesuffix(":latest") for model in result.models if model.endswith(":latest"))
        topology = self.config.topology
        role_model_map = {
            "local_fast": topology.local_fast,
            "local_deep": topology.local_deep,
            "local_code": topology.local_code,
            "local_compact": topology.local_compact,
        }
        missing = [role for role, model in role_model_map.items() if model and model not in installed]
        if missing:
            logging.getLogger(__name__).warning(
                "Topology models not found in Ollama: %s — run 'ollama pull <model>' or update MODEL_ROLE_CONFIG.",
                {r: role_model_map[r] for r in missing},
            )
            self.store.insert_event(
                EventRecord(
                    type=EventType.SYNC_FAILED,
                    summary=f"Topology models missing from Ollama: {', '.join(missing)}",
                    metadata={"missing_roles": {r: role_model_map[r] for r in missing}},
                )
            )
