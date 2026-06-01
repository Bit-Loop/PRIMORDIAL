from __future__ import annotations

import json
import time
from typing import Any
from urllib import error, request

from primordial.core.providers.ollama import OllamaClient, OllamaResponse
from primordial.core.providers.tuned_benchmark_common import (
    EventSink,
    fallback_candidates,
    is_offload_or_load_failure,
    is_timeout,
    shell,
)


class TunedOllama(OllamaClient):
    def __init__(
        self,
        *,
        policy: dict[str, int],
        events: EventSink,
        num_predict: int,
        timeout_seconds: int,
    ) -> None:
        super().__init__(timeout_seconds=timeout_seconds)
        self.policy = policy
        self.events = events
        self.num_predict = num_predict
        self.disabled: dict[str, str] = {}
        self.context_failures: dict[tuple[str, int], str] = {}
        self.context_policy: dict[tuple[str, int], int | None] = {}
        self.last_model: str | None = None
        self.call_index = 0
        self.used_num_gpu_counts: dict[str, dict[str, int]] = {}

    def stop(self, model: str) -> None:
        shell(["ollama", "stop", model], timeout=35)

    def generate(
        self,
        *,
        model: str,
        prompt: str,
        system: str,
        temperature: float = 0.0,
        num_ctx: int = 8192,
        num_gpu: int | None = None,
        keep_alive: str | None = None,
        timeout_seconds: int | None = None,
    ) -> OllamaResponse:
        del num_gpu
        timeout = int(timeout_seconds or self.timeout_seconds)
        self.call_index += 1
        context_key = (model, int(num_ctx))
        self._ensure_model_ready(model, context_key)
        selected = self.context_policy.get(context_key, self.policy.get(model))
        last_error = ""
        for attempt, candidate_gpu in enumerate(fallback_candidates(selected), start=1):
            event = self._event(model, num_ctx, temperature, selected, candidate_gpu, attempt)
            payload = self._payload(model, prompt, system, temperature, num_ctx, candidate_gpu, keep_alive)
            started = time.perf_counter()
            try:
                data = self._post_generate_with_body(payload, timeout_seconds=timeout)
                wall = time.perf_counter() - started
                response = self._response_from_data(model=model, data=data, wall_seconds=wall)
            except Exception as exc:
                last_error = str(exc)
                if self._handle_error(exc, event, model, num_ctx, temperature, candidate_gpu, attempt, selected, started):
                    continue
                raise
            return self._record_success(event, model, context_key, candidate_gpu, response, data, wall)
        raise RuntimeError(last_error or "no Ollama offload candidate succeeded")

    def _ensure_model_ready(self, model: str, context_key: tuple[str, int]) -> None:
        if model in self.disabled:
            raise RuntimeError(f"model disabled after prior timeout: {self.disabled[model]}")
        if context_key in self.context_failures:
            raise RuntimeError(self.context_failures[context_key])
        if self.last_model and self.last_model != model:
            self.stop(self.last_model)
        self.last_model = model

    def _event(
        self,
        model: str,
        num_ctx: int,
        temperature: float,
        selected: int | None,
        candidate_gpu: int | None,
        attempt: int,
    ) -> dict[str, object]:
        return {
            "provider": "ollama",
            "call_index": self.call_index,
            "model": model,
            "context_length": num_ctx,
            "temperature": temperature,
            "selected_num_gpu": selected,
            "used_num_gpu": candidate_gpu,
            "attempt": attempt,
        }

    def _payload(
        self,
        model: str,
        prompt: str,
        system: str,
        temperature: float,
        num_ctx: int,
        candidate_gpu: int | None,
        keep_alive: str | None,
    ) -> dict[str, object]:
        payload: dict[str, object] = {
            "model": model,
            "prompt": prompt,
            "system": system,
            "stream": False,
            "keep_alive": keep_alive or "30m",
            "options": {"temperature": temperature, "num_ctx": num_ctx, "num_predict": self.num_predict},
        }
        if candidate_gpu is not None:
            payload["options"]["num_gpu"] = candidate_gpu  # type: ignore[index]
        return payload

    def _handle_error(
        self,
        exc: Exception,
        event: dict[str, object],
        model: str,
        num_ctx: int,
        temperature: float,
        candidate_gpu: int | None,
        attempt: int,
        selected: int | None,
        started: float,
    ) -> bool:
        last_error = str(exc)
        event.update({"status": "error", "wall_seconds": round(time.perf_counter() - started, 3), "error": last_error})
        self.events.append(event)
        if is_timeout(last_error):
            reason = f"timeout at num_gpu={candidate_gpu} ctx={num_ctx} temp={temperature}: {last_error}"
            self.disabled[model] = reason
            self.stop(model)
            print(f"[ollama timeout-disable] {model} ctx={num_ctx} temp={temperature} num_gpu={candidate_gpu}", flush=True)
            raise RuntimeError(reason) from exc
        candidates = fallback_candidates(selected)
        if is_offload_or_load_failure(last_error) and attempt < len(candidates):
            print(f"[ollama fallback] {model} ctx={num_ctx} num_gpu={candidate_gpu} failed: {last_error[:140]}", flush=True)
            self.stop(model)
            return True
        if is_offload_or_load_failure(last_error):
            reason = f"context failed after offload fallback ctx={num_ctx}: {last_error}"
            self.context_failures[(model, int(num_ctx))] = reason
            print(f"[ollama context-failed] {model} ctx={num_ctx} reason={last_error[:140]}", flush=True)
            raise RuntimeError(reason) from exc
        print(f"[ollama error] {self.call_index} {model} ctx={num_ctx} temp={temperature} num_gpu={candidate_gpu} error={last_error[:140]}", flush=True)
        return False

    def _record_success(
        self,
        event: dict[str, object],
        model: str,
        context_key: tuple[str, int],
        candidate_gpu: int | None,
        response: OllamaResponse,
        data: dict[str, object],
        wall: float,
    ) -> OllamaResponse:
        eval_tps = self._eval_tokens_per_second(data)
        event.update(
            {
                "status": "ok",
                "wall_seconds": round(wall, 3),
                "prompt_eval_count": response.prompt_tokens,
                "eval_count": response.completion_tokens,
                "eval_tokens_per_second": round(eval_tps, 4) if eval_tps else None,
                "total_duration_ns": data.get("total_duration"),
            }
        )
        self.events.append(event)
        self.context_policy[context_key] = candidate_gpu
        key = str(candidate_gpu)
        self.used_num_gpu_counts.setdefault(model, {}).setdefault(key, 0)
        self.used_num_gpu_counts[model][key] += 1
        print(f"[ollama ok] {self.call_index} {model} ctx={context_key[1]} num_gpu={candidate_gpu} wall={wall:.1f}s", flush=True)
        return response

    def _post_generate_with_body(self, payload: dict[str, object], *, timeout_seconds: int) -> dict[str, object]:
        body = json.dumps(payload).encode("utf-8")
        req = request.Request(
            f"{self.base_url}/api/generate",
            data=body,
            method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with request.urlopen(req, timeout=timeout_seconds) as response:
                data = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            detail = f"HTTP {exc.code} {exc.reason}"
            body_text = exc.read().decode("utf-8", errors="replace").strip()
            if body_text:
                detail = f"{detail}: {body_text}"
            raise RuntimeError(f"Ollama request failed at {self.base_url}: {detail}") from exc
        except error.URLError as exc:
            raise RuntimeError(f"Ollama is not reachable at {self.base_url}: {exc}") from exc
        if not isinstance(data, dict):
            raise RuntimeError("Ollama returned a non-object JSON payload")
        return data

    def _response_from_data(self, *, model: str, data: dict[str, object], wall_seconds: float) -> OllamaResponse:
        text = str(data.get("response") or "").strip()
        if not text:
            raise RuntimeError("Ollama returned an empty response")
        elapsed = data.get("total_duration")
        elapsed_seconds = float(elapsed) / 1_000_000_000 if isinstance(elapsed, (int, float)) else round(wall_seconds, 3)
        prompt_tokens = int(data["prompt_eval_count"]) if isinstance(data.get("prompt_eval_count"), int) else None
        completion_tokens = int(data["eval_count"]) if isinstance(data.get("eval_count"), int) else None
        return OllamaResponse(
            model=str(data.get("model", model)),
            text=text,
            elapsed_seconds=elapsed_seconds,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )

    def _eval_tokens_per_second(self, data: dict[str, object]) -> float | None:
        eval_count = data.get("eval_count")
        eval_duration = data.get("eval_duration")
        if not isinstance(eval_count, int) or not isinstance(eval_duration, (int, float)) or not eval_duration:
            return None
        return float(eval_count) / (float(eval_duration) / 1_000_000_000)
