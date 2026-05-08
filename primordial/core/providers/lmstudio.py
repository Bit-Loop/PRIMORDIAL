from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
import time
from urllib import error, request


@dataclass(slots=True)
class LMStudioModelInfo:
    id: str
    loaded: bool = False
    architecture: str | None = None
    quantization: str | None = None
    params: str | None = None
    size: int | None = None
    max_context_length: int | None = None
    raw: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class LMStudioModelListResult:
    ok: bool
    models: list[LMStudioModelInfo]
    error: str | None = None
    endpoint: str | None = None


@dataclass(slots=True)
class LMStudioResponse:
    model: str
    text: str
    elapsed_seconds: float | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    tokens_per_second: float | None = None
    ttft_seconds: float | None = None


@dataclass(slots=True)
class LMStudioLoadResult:
    model: str
    ok: bool
    error: str | None = None
    elapsed_seconds: float | None = None


class LMStudioClient:
    def __init__(self, base_url: str | None = None, timeout_seconds: int = 90, api_token: str | None = None) -> None:
        self.base_url = (base_url or os.getenv("LMSTUDIO_BASE_URL", "http://127.0.0.1:1234")).rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.api_token = api_token if api_token is not None else os.getenv("LMSTUDIO_API_TOKEN", "")

    def list_models(self) -> LMStudioModelListResult:
        errors: list[str] = []
        for endpoint in ("/api/v1/models", "/api/v0/models"):
            try:
                data = self._request_json("GET", endpoint, timeout_seconds=min(10, self.timeout_seconds))
            except Exception as exc:  # noqa: BLE001 - v1 to v0 fallback is intentional
                errors.append(f"{endpoint}: {exc}")
                continue
            models = self._parse_models(data)
            return LMStudioModelListResult(ok=True, models=models, endpoint=endpoint)
        return LMStudioModelListResult(ok=False, models=[], error="; ".join(errors) or "LM Studio is unavailable")

    def chat(
        self,
        *,
        model: str,
        system: str,
        prompt: str,
        temperature: float = 0.0,
        num_ctx: int | None = None,
        timeout_seconds: int | None = None,
    ) -> LMStudioResponse:
        payload: dict[str, object] = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "temperature": temperature,
            "stream": False,
        }
        if num_ctx is not None:
            payload["max_tokens"] = max(128, min(2048, num_ctx // 8))
        started = time.monotonic()
        data = self._request_json("POST", "/v1/chat/completions", payload, timeout_seconds=timeout_seconds)
        elapsed_seconds = time.monotonic() - started
        text = self._extract_chat_text(data)
        if not text:
            raise RuntimeError("LM Studio returned an empty response")
        usage = data.get("usage") if isinstance(data, dict) else {}
        stats = data.get("stats") if isinstance(data, dict) else {}
        if not isinstance(usage, dict):
            usage = {}
        if not isinstance(stats, dict):
            stats = {}
        completion_tokens = self._optional_int(usage.get("completion_tokens"))
        prompt_tokens = self._optional_int(usage.get("prompt_tokens"))
        tokens_per_second = self._optional_float(
            stats.get("tokens_per_second")
            or stats.get("tokensPerSecond")
            or data.get("tokens_per_second")
            or data.get("tokensPerSecond")
        )
        ttft_seconds = self._optional_float(
            stats.get("ttft_seconds")
            or stats.get("time_to_first_token")
            or stats.get("timeToFirstTokenSec")
            or data.get("ttft_seconds")
        )
        if tokens_per_second is None and completion_tokens and elapsed_seconds > 0:
            tokens_per_second = float(completion_tokens) / elapsed_seconds
        return LMStudioResponse(
            model=str(data.get("model", model)) if isinstance(data, dict) else model,
            text=text,
            elapsed_seconds=elapsed_seconds,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            tokens_per_second=tokens_per_second,
            ttft_seconds=ttft_seconds,
        )

    def load_model(self, *, model: str, context_length: int, timeout_seconds: int | None = None) -> LMStudioLoadResult:
        payload = {
            "model": model,
            "context_length": context_length,
            "contextLength": context_length,
            "eval_batch_size": 512,
            "evalBatchSize": 512,
            "flash_attention": True,
            "flashAttention": True,
            "kv_cache_offload": True,
            "kvCacheOffload": True,
            "num_experts": 8,
            "numExperts": 8,
        }
        started = time.monotonic()
        try:
            self._request_json("POST", "/api/v1/models/load", payload, timeout_seconds=timeout_seconds)
            return LMStudioLoadResult(model=model, ok=True, elapsed_seconds=time.monotonic() - started)
        except Exception as exc:  # noqa: BLE001 - caller records failed rows and continues
            return LMStudioLoadResult(model=model, ok=False, error=str(exc), elapsed_seconds=time.monotonic() - started)

    def unload_model(self, *, model: str, timeout_seconds: int | None = None) -> LMStudioLoadResult:
        started = time.monotonic()
        try:
            self._request_json("POST", "/api/v1/models/unload", {"model": model}, timeout_seconds=timeout_seconds)
            return LMStudioLoadResult(model=model, ok=True, elapsed_seconds=time.monotonic() - started)
        except Exception as exc:  # noqa: BLE001 - benchmark cleanup should be best-effort
            return LMStudioLoadResult(model=model, ok=False, error=str(exc), elapsed_seconds=time.monotonic() - started)

    def _request_json(
        self,
        method: str,
        endpoint: str,
        payload: dict[str, object] | None = None,
        *,
        timeout_seconds: int | None = None,
    ) -> dict[str, object] | list[object]:
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Accept": "application/json"}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"
        req = request.Request(f"{self.base_url}{endpoint}", data=data, method=method, headers=headers)
        try:
            with request.urlopen(req, timeout=timeout_seconds or self.timeout_seconds) as response:
                decoded = json.loads(response.read().decode("utf-8") or "{}")
        except error.URLError as exc:
            raise RuntimeError(f"LM Studio is not reachable at {self.base_url}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise RuntimeError("LM Studio returned invalid JSON") from exc
        if not isinstance(decoded, (dict, list)):
            raise RuntimeError("LM Studio returned an unsupported JSON payload")
        return decoded

    def _parse_models(self, data: dict[str, object] | list[object]) -> list[LMStudioModelInfo]:
        if isinstance(data, list):
            raw_models = data
        elif isinstance(data.get("data"), list):
            raw_models = data["data"]  # type: ignore[index]
        elif isinstance(data.get("models"), list):
            raw_models = data["models"]  # type: ignore[index]
        else:
            raw_models = []
        models: list[LMStudioModelInfo] = []
        for item in raw_models:
            if not isinstance(item, dict):
                continue
            model_id = str(item.get("id") or item.get("model") or item.get("path") or item.get("name") or "").strip()
            if not model_id:
                continue
            kind = str(item.get("type") or item.get("kind") or item.get("model_type") or "").lower()
            if "embedding" in kind or "embedding" in model_id.lower():
                continue
            loaded = bool(item.get("loaded") or item.get("is_loaded") or item.get("state") == "loaded")
            models.append(
                LMStudioModelInfo(
                    id=model_id,
                    loaded=loaded,
                    architecture=self._optional_str(item.get("architecture") or item.get("arch")),
                    quantization=self._optional_str(item.get("quantization") or item.get("quant")),
                    params=self._optional_str(item.get("params") or item.get("parameter_count") or item.get("parameters")),
                    size=self._optional_int(item.get("size") or item.get("size_bytes")),
                    max_context_length=self._optional_int(
                        item.get("max_context_length")
                        or item.get("context_length")
                        or item.get("contextLength")
                        or item.get("n_ctx_train")
                    ),
                    raw=dict(item),
                )
            )
        return sorted(models, key=lambda item: item.id.lower())

    def _extract_chat_text(self, data: dict[str, object] | list[object]) -> str:
        if not isinstance(data, dict):
            return ""
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices:
            return ""
        first = choices[0]
        if not isinstance(first, dict):
            return ""
        message = first.get("message")
        if isinstance(message, dict):
            return str(message.get("content") or "").strip()
        return str(first.get("text") or "").strip()

    def _optional_str(self, value: object) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    def _optional_int(self, value: object) -> int | None:
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if isinstance(value, str) and value.strip().isdigit():
            return int(value.strip())
        return None

    def _optional_float(self, value: object) -> float | None:
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value.strip())
            except ValueError:
                return None
        return None
