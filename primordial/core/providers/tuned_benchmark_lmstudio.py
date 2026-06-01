from __future__ import annotations

import time

from primordial.core.providers.lmstudio import LMStudioClient
from primordial.core.providers.tuned_benchmark_common import EventSink, is_timeout


class ProgressLMStudio:
    def __init__(self, base: LMStudioClient, *, events: EventSink, timeout_seconds: int) -> None:
        self.base = base
        self.events = events
        self.timeout_seconds = timeout_seconds
        self.disabled: dict[str, str] = {}
        self.call_index = 0

    def list_models(self):
        return self.base.list_models()

    def load_model(self, *, model: str, context_length: int, timeout_seconds: int | None = None):
        print(f"[lmstudio load] {model} ctx={context_length}", flush=True)
        result = self.base.load_model(
            model=model,
            context_length=context_length,
            timeout_seconds=timeout_seconds or self.timeout_seconds,
        )
        self.events.append(
            {
                "provider": "lmstudio",
                "event": "load",
                "model": model,
                "context_length": context_length,
                "ok": result.ok,
                "error": result.error,
                "elapsed_seconds": result.elapsed_seconds,
            }
        )
        if not result.ok and result.error and is_timeout(result.error):
            self.disabled[model] = result.error
        return result

    def unload_model(self, *, model: str, timeout_seconds: int | None = None):
        result = self.base.unload_model(model=model, timeout_seconds=min(timeout_seconds or 60, 120))
        self.events.append(
            {
                "provider": "lmstudio",
                "event": "unload",
                "model": model,
                "ok": result.ok,
                "error": result.error,
                "elapsed_seconds": result.elapsed_seconds,
            }
        )
        print(f"[lmstudio unload] {model} ok={result.ok}", flush=True)
        return result

    def chat(
        self,
        *,
        model: str,
        system: str,
        prompt: str,
        temperature: float = 0.0,
        num_ctx: int | None = None,
        timeout_seconds: int | None = None,
    ):
        if model in self.disabled:
            raise RuntimeError(f"model disabled after prior timeout/load failure: {self.disabled[model]}")
        self.call_index += 1
        started = time.perf_counter()
        try:
            response = self.base.chat(
                model=model,
                system=system,
                prompt=prompt,
                temperature=temperature,
                num_ctx=num_ctx,
                timeout_seconds=timeout_seconds or self.timeout_seconds,
            )
        except Exception as exc:
            wall = time.perf_counter() - started
            message = str(exc)
            if is_timeout(message):
                self.disabled[model] = message
            self.events.append(
                {
                    "provider": "lmstudio",
                    "event": "chat",
                    "status": "error",
                    "model": model,
                    "context_length": num_ctx,
                    "temperature": temperature,
                    "wall_seconds": round(wall, 3),
                    "error": message,
                }
            )
            print(f"[lmstudio error] {self.call_index} {model} ctx={num_ctx} temp={temperature} wall={wall:.1f}s", flush=True)
            raise
        wall = time.perf_counter() - started
        self.events.append(
            {
                "provider": "lmstudio",
                "event": "chat",
                "status": "ok",
                "model": model,
                "context_length": num_ctx,
                "temperature": temperature,
                "wall_seconds": round(wall, 3),
                "tokens_per_second": response.tokens_per_second,
                "completion_tokens": response.completion_tokens,
            }
        )
        print(f"[lmstudio ok] {self.call_index} {model} ctx={num_ctx} temp={temperature} wall={wall:.1f}s", flush=True)
        return response
