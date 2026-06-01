from __future__ import annotations

from primordial.app.runtime_deps import (
    WRAPPER_ROLE_PERSONALITY_PROMPTS,
)

class RuntimeWrapperModesMixin:
    def model_wrapper_mode_payload(self) -> dict[str, object]:
        mode = self._current_model_wrapper_mode()
        provider = str(mode.get("provider") or self.config.agent_chat_provider or "claude")
        model = mode.get("model")
        effort = mode.get("effort")
        preset = str(mode.get("preset") or self.DEFAULT_WRAPPER_PRESET)
        return {
            "use_only_wrapper": bool(mode.get("use_only_wrapper")),
            "local_chat_wrapper": "agent_chat_api",
            "preset": preset,
            "preset_label": self._wrapper_preset_label(preset),
            "provider": provider,
            "model": str(model) if model else None,
            "effort": str(effort) if effort else None,
            "model_label": self._wrapper_model_label(),
            "display_label": self._wrapper_display_label(mode),
            "presets": self._wrapper_preset_options(),
            "api": self.agent_chat_status_payload(timeout_seconds=0.5),
            "safe_guard": self.config.agent_chat_safe_guard,
            "personality_prompts": dict(WRAPPER_ROLE_PERSONALITY_PROMPTS),
            "detail": (
                "All runtime AI generation uses agent_chat_api role wrappers; direct Ollama generate, "
                "warmup, unload, and startup topology validation are bypassed."
                if mode.get("use_only_wrapper")
                else "Runtime AI generation uses local model routes unless an explicit premium wrapper task is created."
            ),
        }

    def _current_model_wrapper_mode(self) -> dict[str, object]:
        stored = self.store.get_setting(self.MODEL_WRAPPER_MODE_SETTING, {})
        default = self._default_model_wrapper_mode()
        if isinstance(stored, dict):
            mode = self._normalize_model_wrapper_mode(stored, current=default)
            if self.config.use_only_wrapper_mode:
                mode["use_only_wrapper"] = True
            return mode
        return default

    def _default_model_wrapper_mode(self) -> dict[str, object]:
        preset = dict(self.WRAPPER_PRESETS[self.DEFAULT_WRAPPER_PRESET])
        mode: dict[str, object] = {
            "use_only_wrapper": bool(self.config.use_only_wrapper_mode),
            "preset": self.DEFAULT_WRAPPER_PRESET,
            "provider": preset["provider"],
            "model": preset["model"],
            "effort": preset["effort"],
        }
        configured_provider = str(self.config.agent_chat_provider or "").strip().lower()
        if configured_provider in {"claude", "codex"}:
            mode["provider"] = configured_provider
            if configured_provider == "codex" and not self.config.agent_chat_model:
                mode["model"] = self.WRAPPER_PRESETS["codex_gpt55_high"]["model"]
                mode["effort"] = self.WRAPPER_PRESETS["codex_gpt55_high"]["effort"]
        if self.config.agent_chat_model:
            mode["model"] = self.config.agent_chat_model
        mode["preset"] = self._wrapper_preset_for(
            str(mode["provider"]),
            str(mode["model"]),
            str(mode["effort"]) if mode.get("effort") else None,
        )
        return mode

    def _normalize_model_wrapper_mode(
        self,
        payload: dict[str, object],
        *,
        current: dict[str, object] | None = None,
    ) -> dict[str, object]:
        normalized = dict(
            current
            or self._default_model_wrapper_mode()
        )
        if "use_only_wrapper" in payload:
            normalized["use_only_wrapper"] = self._coerce_bool(payload.get("use_only_wrapper"))
        preset_id = str(payload.get("preset") or "").strip().lower()
        if preset_id:
            if preset_id not in self.WRAPPER_PRESETS:
                raise ValueError(f"unsupported wrapper preset: {preset_id}")
            preset = self.WRAPPER_PRESETS[preset_id]
            normalized["preset"] = preset_id
            normalized["provider"] = preset["provider"]
            normalized["model"] = preset["model"]
            normalized["effort"] = preset["effort"]
        if "provider" in payload:
            provider = str(payload.get("provider") or "").strip().lower()
            if provider:
                if provider not in {"claude", "codex"}:
                    raise ValueError(f"unsupported wrapper provider: {provider}")
                normalized["provider"] = provider
                if "model" not in payload and not preset_id:
                    provider_preset = "codex_gpt55_high" if provider == "codex" else "claude_sonnet"
                    preset = self.WRAPPER_PRESETS[provider_preset]
                    normalized["preset"] = provider_preset
                    normalized["model"] = preset["model"]
                    normalized["effort"] = preset["effort"]
        if "model" in payload:
            raw_model = payload.get("model")
            model = str(raw_model).strip() if raw_model is not None else ""
            normalized["model"] = model or None
        if "effort" in payload:
            raw_effort = payload.get("effort")
            effort = str(raw_effort).strip().lower() if raw_effort is not None else ""
            if effort and effort not in self.WRAPPER_EFFORTS:
                raise ValueError(f"unsupported wrapper effort: {effort}")
            normalized["effort"] = effort or None
        provider = str(normalized.get("provider") or "").strip().lower()
        model = str(normalized.get("model") or "").strip()
        effort = str(normalized.get("effort") or "").strip().lower() or None
        if not model:
            provider_preset = "codex_gpt55_high" if provider == "codex" else "claude_sonnet"
            preset = self.WRAPPER_PRESETS[provider_preset]
            model = str(preset["model"])
            effort = str(preset["effort"]) if preset.get("effort") else None
        elif provider == "codex" and model == self.WRAPPER_PRESETS["codex_gpt55_high"]["model"] and not effort:
            effort = str(self.WRAPPER_PRESETS["codex_gpt55_high"]["effort"])
        inferred_preset = self._wrapper_preset_for(provider, model, effort)
        if not inferred_preset:
            raise ValueError(f"unsupported wrapper model for provider {provider}: {model or 'provider-default'}")
        normalized["preset"] = inferred_preset
        normalized["provider"] = provider
        normalized["model"] = model
        normalized["effort"] = effort
        return normalized

    def _wrapper_preset_for(self, provider: str, model: str, effort: str | None) -> str | None:
        for preset_id, preset in self.WRAPPER_PRESETS.items():
            if (
                provider == preset["provider"]
                and model == preset["model"]
                and (effort or None) == preset["effort"]
            ):
                return preset_id
        return None

    def _wrapper_preset_label(self, preset_id: str) -> str:
        preset = self.WRAPPER_PRESETS.get(preset_id)
        return str(preset.get("label")) if preset else preset_id

    def _wrapper_preset_options(self) -> list[dict[str, object]]:
        return [
            {
                "id": preset_id,
                "label": str(preset["label"]),
                "provider": str(preset["provider"]),
                "model": str(preset["model"]),
                "effort": str(preset["effort"]) if preset.get("effort") else None,
            }
            for preset_id, preset in self.WRAPPER_PRESETS.items()
        ]

    def _wrapper_display_label(self, mode: dict[str, object] | None = None) -> str:
        selected = mode or self._current_model_wrapper_mode()
        preset_id = str(selected.get("preset") or "")
        return self._wrapper_preset_label(preset_id) if preset_id else self._wrapper_model_label(selected)

    def _coerce_bool(self, value: object) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, int | float):
            return bool(value)
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on", "enabled"}
        return bool(value)

    def _use_only_wrapper_mode(self) -> bool:
        return bool(self._current_model_wrapper_mode().get("use_only_wrapper"))

    def _wrapper_model_label(self, mode: dict[str, object] | None = None) -> str:
        mode = mode or self._current_model_wrapper_mode()
        provider = str(mode.get("provider") or self.config.agent_chat_provider or "claude")
        model = mode.get("model") or self.config.agent_chat_model or "provider-default"
        effort = mode.get("effort")
        suffix = f":{effort}" if effort else ""
        return f"agent_chat_api:{provider}:{model}{suffix}"
