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
    reasoning_content: str = ""
    finish_reason: str | None = None


@dataclass(slots=True)
class LMStudioLoadResult:
    model: str
    ok: bool
    error: str | None = None
    elapsed_seconds: float | None = None
    instance_id: str | None = None
    load_config: dict[str, object] = field(default_factory=dict)


class LMStudioClient:
    def __init__(self, base_url: str | None = None, timeout_seconds: int = 90, api_token: str | None = None) -> None:
        self.base_url = (base_url or os.getenv("LMSTUDIO_BASE_URL", "http://127.0.0.1:1234")).rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.api_token = api_token if api_token is not None else os.getenv("LMSTUDIO_API_TOKEN", "")

    def list_models(self) -> LMStudioModelListResult:
        errors: list[str] = []
        for endpoint in ("/api/v1/models", "/api/v0/models", "/v1/models"):
            try:
                data = self._request_json("GET", endpoint, timeout_seconds=min(10, self.timeout_seconds))
            except Exception as exc:  # noqa: BLE001 - v1 to v0 fallback is intentional
                errors.append(f"{endpoint}: {exc}")
                continue
            models = _parse_models(data)
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
        max_tokens: int | None = None,
        timeout_seconds: int | None = None,
    ) -> LMStudioResponse:
        def payload_with(messages: list[dict[str, str]]) -> dict[str, object]:
            payload: dict[str, object] = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "stream": False,
            }
            if max_tokens is not None:
                payload["max_tokens"] = max(1, int(max_tokens))
            elif num_ctx is not None:
                payload["max_tokens"] = max(128, min(2048, num_ctx // 8))
            return payload

        payload = payload_with(
            [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ]
        )
        fallback_payload = payload_with(
            [{"role": "user", "content": f"{system.strip()}\n\n{prompt.strip()}".strip()}]
        )
        started = time.monotonic()
        try:
            data = self._request_json("POST", "/v1/chat/completions", payload, timeout_seconds=timeout_seconds)
        except RuntimeError as exc:
            if "Only user and assistant roles are supported" not in str(exc):
                raise
            data = self._request_json(
                "POST",
                "/v1/chat/completions",
                fallback_payload,
                timeout_seconds=timeout_seconds,
            )
        elapsed_seconds = time.monotonic() - started
        text, reasoning_content, finish_reason = _extract_chat_message(data)
        if not text and not reasoning_content:
            raise RuntimeError("LM Studio returned an empty response")
        return _chat_response_from_data(
            data,
            model,
            elapsed_seconds,
            text,
            reasoning_content,
            finish_reason,
        )

    def load_model(
        self,
        *,
        model: str,
        context_length: int,
        eval_batch_size: int = 512,
        flash_attention: bool = True,
        offload_kv_cache_to_gpu: bool = True,
        num_experts: int | None = None,
        timeout_seconds: int | None = None,
    ) -> LMStudioLoadResult:
        payload = {
            "model": model,
            "context_length": int(context_length),
            "eval_batch_size": int(eval_batch_size),
            "flash_attention": bool(flash_attention),
            "offload_kv_cache_to_gpu": bool(offload_kv_cache_to_gpu),
            "echo_load_config": True,
        }
        if num_experts is not None:
            payload["num_experts"] = int(num_experts)
        started = time.monotonic()
        try:
            data = self._request_json("POST", "/api/v1/models/load", payload, timeout_seconds=timeout_seconds)
            instance_id = _extract_instance_id(data) or model
            load_config = _extract_load_config(data) or _load_config_from_payload(payload)
            return LMStudioLoadResult(
                model=model,
                ok=True,
                elapsed_seconds=time.monotonic() - started,
                instance_id=instance_id,
                load_config=load_config,
            )
        except Exception as exc:  # noqa: BLE001 - caller records failed rows and continues
            return LMStudioLoadResult(
                model=model,
                ok=False,
                error=str(exc),
                elapsed_seconds=time.monotonic() - started,
                load_config=_load_config_from_payload(payload),
            )

    def unload_model(
        self,
        *,
        model: str,
        instance_id: str | None = None,
        timeout_seconds: int | None = None,
    ) -> LMStudioLoadResult:
        started = time.monotonic()
        try:
            unload_id = instance_id or model
            self._request_json("POST", "/api/v1/models/unload", {"instance_id": unload_id}, timeout_seconds=timeout_seconds)
            return LMStudioLoadResult(
                model=model,
                ok=True,
                elapsed_seconds=time.monotonic() - started,
                instance_id=unload_id,
            )
        except Exception as exc:  # noqa: BLE001 - benchmark cleanup should be best-effort
            return LMStudioLoadResult(
                model=model,
                ok=False,
                error=str(exc),
                elapsed_seconds=time.monotonic() - started,
                instance_id=instance_id,
            )

    def unload_loaded_models(self, *, timeout_seconds: int | None = None) -> list[LMStudioLoadResult]:
        listed = self.list_models()
        if not listed.ok:
            return [LMStudioLoadResult(model="", ok=False, error=listed.error)]
        results: list[LMStudioLoadResult] = []
        for model in listed.models:
            if not model.loaded:
                continue
            instance_ids = _loaded_instance_ids(model)
            if not instance_ids:
                instance_ids = [model.id]
            for instance_id in instance_ids:
                results.append(self.unload_model(model=model.id, instance_id=instance_id, timeout_seconds=timeout_seconds))
        return results

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
        except error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace").strip()
            detail = f"{exc.code} {exc.reason}"
            if body:
                detail = f"{detail}: {body}"
            raise RuntimeError(f"LM Studio request to {self.base_url}{endpoint} failed: {detail}") from exc
        except error.URLError as exc:
            raise RuntimeError(f"LM Studio is not reachable at {self.base_url}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise RuntimeError("LM Studio returned invalid JSON") from exc
        if not isinstance(decoded, (dict, list)):
            raise RuntimeError("LM Studio returned an unsupported JSON payload")
        return decoded

def _parse_models(data: dict[str, object] | list[object]) -> list[LMStudioModelInfo]:
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
        model_id = _model_id(item)
        if not model_id or _is_embedding_model(item, model_id):
            continue
        quantization = item.get("quantization")
        quantization_name = quantization.get("name") if isinstance(quantization, dict) else quantization
        models.append(
            LMStudioModelInfo(
                id=model_id,
                loaded=_is_loaded_model(item),
                architecture=_optional_str(item.get("architecture") or item.get("arch")),
                quantization=_optional_str(quantization_name or item.get("quant")),
                params=_optional_str(
                    item.get("params")
                    or item.get("params_string")
                    or item.get("parameter_count")
                    or item.get("parameters")
                ),
                size=_optional_int(item.get("size") or item.get("size_bytes")),
                max_context_length=_optional_int(
                    item.get("max_context_length")
                    or item.get("context_length")
                    or item.get("contextLength")
                    or item.get("n_ctx_train")
                ),
                raw=dict(item),
            )
        )
    return sorted(models, key=lambda item: item.id.lower())


def _model_id(item: dict[str, object]) -> str:
    return str(
        item.get("id")
        or item.get("model")
        or item.get("key")
        or item.get("path")
        or item.get("name")
        or item.get("display_name")
        or ""
    ).strip()


def _is_embedding_model(item: dict[str, object], model_id: str) -> bool:
    kind = str(item.get("type") or item.get("kind") or item.get("model_type") or "").lower()
    return "embedding" in kind or "embedding" in model_id.lower()


def _is_loaded_model(item: dict[str, object]) -> bool:
    loaded_instances = item.get("loaded_instances")
    return bool(
        item.get("loaded")
        or item.get("is_loaded")
        or item.get("state") == "loaded"
        or (isinstance(loaded_instances, list) and loaded_instances)
    )


def _extract_chat_message(data: dict[str, object] | list[object]) -> tuple[str, str, str | None]:
    if not isinstance(data, dict):
        return "", "", None
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        return "", "", None
    first = choices[0]
    if not isinstance(first, dict):
        return "", "", None
    finish_reason = _optional_str(first.get("finish_reason") or first.get("finishReason"))
    message = first.get("message")
    if isinstance(message, dict):
        text = str(message.get("content") or "").strip()
        reasoning = str(
            message.get("reasoning_content")
            or message.get("reasoning")
            or message.get("thinking")
            or ""
        ).strip()
        return text, reasoning, finish_reason
    return str(first.get("text") or "").strip(), "", finish_reason


def _extract_instance_id(data: dict[str, object] | list[object]) -> str | None:
    if not isinstance(data, dict):
        return None
    for key in ("instance_id", "instanceId", "identifier", "id"):
        value = _optional_str(data.get(key))
        if value:
            return value
    instance = data.get("instance")
    if isinstance(instance, dict):
        for key in ("instance_id", "identifier", "id"):
            value = _optional_str(instance.get(key))
            if value:
                return value
    return None


def _extract_load_config(data: dict[str, object] | list[object]) -> dict[str, object]:
    if not isinstance(data, dict):
        return {}
    load_config = data.get("load_config") or data.get("loadConfig")
    if isinstance(load_config, dict):
        return dict(load_config)
    return {}


def _load_config_from_payload(payload: dict[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in payload.items()
        if key not in {"model", "echo_load_config"} and value is not None
    }


def _loaded_instance_ids(model: LMStudioModelInfo) -> list[str]:
    loaded_instances = model.raw.get("loaded_instances")
    if not isinstance(loaded_instances, list):
        return []
    instance_ids: list[str] = []
    for instance in loaded_instances:
        if not isinstance(instance, dict):
            continue
        instance_id = _optional_str(instance.get("identifier") or instance.get("instance_id") or instance.get("id"))
        if instance_id:
            instance_ids.append(instance_id)
    return instance_ids


def _chat_response_from_data(
    data: dict[str, object] | list[object],
    model: str,
    elapsed_seconds: float,
    text: str,
    reasoning_content: str,
    finish_reason: str | None,
) -> LMStudioResponse:
    payload = data if isinstance(data, dict) else {}
    usage = _mapping_payload(payload.get("usage"))
    stats = _mapping_payload(payload.get("stats"))
    completion_tokens = _optional_int(usage.get("completion_tokens"))
    prompt_tokens = _optional_int(usage.get("prompt_tokens"))
    tokens_per_second = _optional_float(
        stats.get("tokens_per_second")
        or stats.get("tokensPerSecond")
        or payload.get("tokens_per_second")
        or payload.get("tokensPerSecond")
    )
    ttft_seconds = _optional_float(
        stats.get("ttft_seconds")
        or stats.get("time_to_first_token")
        or stats.get("timeToFirstTokenSec")
        or payload.get("ttft_seconds")
    )
    if tokens_per_second is None and completion_tokens and elapsed_seconds > 0:
        tokens_per_second = float(completion_tokens) / elapsed_seconds
    return LMStudioResponse(
        model=str(payload.get("model", model)) if payload else model,
        text=text,
        elapsed_seconds=elapsed_seconds,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        tokens_per_second=tokens_per_second,
        ttft_seconds=ttft_seconds,
        reasoning_content=reasoning_content,
        finish_reason=finish_reason,
    )


def _mapping_payload(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _optional_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _optional_float(value: object) -> float | None:
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
