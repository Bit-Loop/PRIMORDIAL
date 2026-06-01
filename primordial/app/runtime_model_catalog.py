from __future__ import annotations

from primordial.app.runtime_deps import (
    EventRecord,
    EventType,
    OllamaModelListResult,
    WRAPPER_ROLE_PERSONALITY_PROMPTS,
)

class RuntimeModelCatalogMixin:
    def models_payload(self) -> dict[str, object]:
        wrapper_mode = self.model_wrapper_mode_payload()
        if wrapper_mode["use_only_wrapper"]:
            installed = OllamaModelListResult(
                ok=False,
                models=[],
                error="Ollama model listing skipped because use-only-wrapper mode is active.",
            )
        else:
            installed = self.ollama.list_models()
        selected = self._current_model_roles()
        processors = self._current_model_role_processors()
        role_metrics = self.store.latest_model_eval_role_metrics()
        available_models = list(installed.models)
        for model in selected.values():
            if model and model not in available_models:
                available_models.append(model)
        available_models = sorted(set(available_models))
        roles = []
        for role, config in self.MODEL_ROLE_CONFIG.items():
            roles.append(
                {
                    "role": role,
                    "label": config["label"],
                    "description": config["description"],
                    "processor": processors[role],
                    "default_model": config["default_model"],
                    "selected_model": selected[role],
                    "num_gpu": self._processor_num_gpu(processors[role]),
                    "default_processor": config["processor"],
                    "processor_options": ["gpu", "cpu"],
                    "metrics": role_metrics.get(role),
                    "wrapper_personality": WRAPPER_ROLE_PERSONALITY_PROMPTS.get(role, ""),
                }
            )
        return {
            "ollama": {
                "ok": installed.ok,
                "base_url": self.ollama.base_url,
                "error": installed.error,
                "disabled_by_wrapper_mode": bool(wrapper_mode["use_only_wrapper"]),
            },
            "wrapper_mode": wrapper_mode,
            "available_models": available_models,
            "roles": roles,
            "role_metrics": role_metrics,
            "eval_history": self.store.list_model_eval_history(limit=10),
        }

    def update_model_roles(
        self,
        selections: dict[str, str],
        processors: dict[str, str] | None = None,
        wrapper_mode: dict[str, object] | None = None,
    ) -> dict[str, object]:
        current = self._current_model_roles()
        current_processors = self._current_model_role_processors()
        current_wrapper_mode = self._current_model_wrapper_mode()
        if wrapper_mode is not None:
            current_wrapper_mode = self._normalize_model_wrapper_mode(wrapper_mode, current=current_wrapper_mode)
        installed = (
            OllamaModelListResult(ok=False, models=[], error="validation skipped in use-only-wrapper mode")
            if current_wrapper_mode.get("use_only_wrapper")
            else self.ollama.list_models()
        )
        installed_models = set(installed.models)
        changed: dict[str, str] = {}
        for role, model in selections.items():
            if role not in self.MODEL_ROLE_CONFIG:
                raise ValueError(f"unsupported model role: {role}")
            selected = str(model).strip()
            if not selected:
                continue
            if not current_wrapper_mode.get("use_only_wrapper") and installed.ok and selected not in installed_models:
                raise ValueError(f"model is not installed in Ollama: {selected}")
            current[role] = selected
            changed[role] = selected
        processor_changes: dict[str, str] = {}
        for role, processor in (processors or {}).items():
            if role not in self.MODEL_ROLE_CONFIG:
                raise ValueError(f"unsupported model role: {role}")
            selected_processor = str(processor).strip().lower()
            if selected_processor not in {"gpu", "cpu"}:
                raise ValueError(f"unsupported processor for {role}: {processor}")
            current_processors[role] = selected_processor
            processor_changes[role] = selected_processor
        self.store.set_setting("model_roles", current)
        self.store.set_setting("model_role_processors", current_processors)
        self.store.set_setting(self.MODEL_WRAPPER_MODE_SETTING, current_wrapper_mode)
        self._apply_model_roles(current)
        if current_wrapper_mode.get("use_only_wrapper"):
            self._ensure_agent_chat_api_available()
        self.store.insert_event(
            EventRecord(
                type=EventType.BOOTSTRAP,
                summary="Model role mapping updated",
                metadata={
                    "changed": changed,
                    "processor_changes": processor_changes,
                    "wrapper_mode": current_wrapper_mode,
                },
            )
        )
        return self.models_payload()

    def warm_model_routes(self, *, keep_alive: str = "8h") -> dict[str, object]:
        if self._use_only_wrapper_mode():
            result = {
                "keep_alive": keep_alive,
                "results": [],
                "skipped": True,
                "reason": "use-only-wrapper mode is active; Ollama warmup is bypassed",
                "wrapper_mode": self.model_wrapper_mode_payload(),
            }
            self.store.insert_event(
                EventRecord(
                    type=EventType.BOOTSTRAP,
                    summary="Model warmup skipped for use-only-wrapper mode",
                    metadata=result,
                )
            )
            return result
        route_models = {
            "local_fast": ("local_fast", self.config.topology.local_fast),
            "local_compact": ("local_compact", self.config.topology.local_compact),
            "local_deep": ("local_deep", self.config.topology.local_deep),
            "local_code_cold": ("local_code", self.config.topology.local_code),
        }
        results = []
        for route, (role, model) in route_models.items():
            num_gpu = self._role_num_gpu(role)
            preload = self.ollama.preload(model=model, keep_alive=keep_alive, num_gpu=num_gpu)
            results.append(
                {
                    "route": route,
                    "model": preload.model,
                    "num_gpu": num_gpu,
                    "processor_hint": "cpu" if num_gpu == 0 else "default",
                    "ok": preload.ok,
                    "error": preload.error,
                    "elapsed_seconds": preload.elapsed_seconds,
                }
            )
        self.store.insert_event(
            EventRecord(
                type=EventType.BOOTSTRAP,
                summary="Model warmup completed",
                metadata={"keep_alive": keep_alive, "results": results},
            )
        )
        return {"keep_alive": keep_alive, "results": results}

    def clear_model_routes(self) -> dict[str, object]:
        if self._use_only_wrapper_mode():
            result = {
                "results": [],
                "skipped": True,
                "reason": "use-only-wrapper mode is active; Ollama unload is bypassed",
                "wrapper_mode": self.model_wrapper_mode_payload(),
            }
            self.store.insert_event(
                EventRecord(
                    type=EventType.BOOTSTRAP,
                    summary="Model clear/unload skipped for use-only-wrapper mode",
                    metadata=result,
                )
            )
            return result
        route_models = {
            "local_fast": ("local_fast", self.config.topology.local_fast),
            "local_compact": ("local_compact", self.config.topology.local_compact),
            "local_deep": ("local_deep", self.config.topology.local_deep),
            "local_code_cold": ("local_code", self.config.topology.local_code),
        }
        seen: set[tuple[str, int | None]] = set()
        results = []
        for route, (role, model) in route_models.items():
            num_gpu = self._role_num_gpu(role)
            key = (model, num_gpu)
            if key in seen:
                continue
            seen.add(key)
            unload = self.ollama.unload(model=model, num_gpu=num_gpu)
            results.append(
                {
                    "route": route,
                    "model": unload.model,
                    "num_gpu": num_gpu,
                    "processor_hint": "cpu" if num_gpu == 0 else "default",
                    "ok": unload.ok,
                    "error": unload.error,
                    "elapsed_seconds": unload.elapsed_seconds,
                }
            )
        self.store.insert_event(
            EventRecord(
                type=EventType.BOOTSTRAP,
                summary="Model clear/unload requested",
                metadata={"results": results},
            )
        )
        return {"results": results}

    def stop_active_work(self) -> dict[str, object]:
        self.store.set_setting(self.EXECUTION_MODE_SETTING, "tick")
        paused = self.store.pause_active_sessions()
        self.store.insert_event(
            EventRecord(
                type=EventType.BOOTSTRAP,
                summary="Operator requested stop for active GUI work",
                metadata={"paused_sessions": paused, "execution_mode": "tick"},
            )
        )
        return {"paused_sessions": paused, "execution_mode": self.execution_mode_payload()}
