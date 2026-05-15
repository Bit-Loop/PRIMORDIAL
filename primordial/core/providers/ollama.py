from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from urllib import error, request


@dataclass(slots=True)
class OllamaResponse:
    model: str
    text: str
    elapsed_seconds: float | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None


@dataclass(slots=True)
class OllamaPreloadResult:
    model: str
    ok: bool
    error: str | None = None
    elapsed_seconds: float | None = None


@dataclass(slots=True)
class OllamaModelListResult:
    ok: bool
    models: list[str]
    error: str | None = None


@dataclass(slots=True)
class OllamaModelInfo:
    name: str
    architecture: str | None = None
    quantization: str | None = None
    params: str | None = None
    size: int | None = None
    raw: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class OllamaModelInfoListResult:
    ok: bool
    models: list[OllamaModelInfo]
    error: str | None = None


@dataclass(slots=True)
class OllamaEmbeddingResponse:
    model: str
    embeddings: list[list[float]]


class OllamaClient:
    MAX_EMBEDDING_CHARS = 2048

    def __init__(self, base_url: str | None = None, timeout_seconds: int = 90) -> None:
        self.base_url = (base_url or os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")).rstrip("/")
        self.timeout_seconds = timeout_seconds

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
        payload = {
            "model": model,
            "prompt": prompt,
            "system": system,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_ctx": num_ctx,
            },
        }
        if num_gpu is not None:
            payload["options"]["num_gpu"] = num_gpu
        if keep_alive:
            payload["keep_alive"] = keep_alive
        data = self._post_generate(payload, timeout_seconds=timeout_seconds)
        text = str(data.get("response", "")).strip()
        if not text:
            raise RuntimeError("Ollama returned an empty response")
        elapsed = data.get("total_duration")
        elapsed_seconds = float(elapsed) / 1_000_000_000 if isinstance(elapsed, (int, float)) else None
        prompt_tokens = int(data["prompt_eval_count"]) if isinstance(data.get("prompt_eval_count"), int) else None
        completion_tokens = int(data["eval_count"]) if isinstance(data.get("eval_count"), int) else None
        return OllamaResponse(
            model=str(data.get("model", model)),
            text=text,
            elapsed_seconds=elapsed_seconds,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )

    def preload(
        self,
        *,
        model: str,
        keep_alive: str = "8h",
        num_ctx: int = 512,
        num_gpu: int | None = None,
    ) -> OllamaPreloadResult:
        payload = {
            "model": model,
            "prompt": "",
            "stream": False,
            "keep_alive": keep_alive,
            "options": {
                "num_ctx": num_ctx,
                "temperature": 0,
            },
        }
        if num_gpu is not None:
            payload["options"]["num_gpu"] = num_gpu
        try:
            data = self._post_generate(payload)
            elapsed = data.get("total_duration")
            elapsed_seconds = float(elapsed) / 1_000_000_000 if isinstance(elapsed, (int, float)) else None
            return OllamaPreloadResult(model=str(data.get("model", model)), ok=True, elapsed_seconds=elapsed_seconds)
        except Exception as exc:  # noqa: BLE001 - model warmup is operational best-effort
            return OllamaPreloadResult(model=model, ok=False, error=str(exc))

    def unload(self, *, model: str, num_gpu: int | None = None) -> OllamaPreloadResult:
        payload = {
            "model": model,
            "prompt": "",
            "stream": False,
            "keep_alive": 0,
            "options": {
                "num_ctx": 64,
                "temperature": 0,
            },
        }
        if num_gpu is not None:
            payload["options"]["num_gpu"] = num_gpu
        try:
            data = self._post_generate(payload)
            elapsed = data.get("total_duration")
            elapsed_seconds = float(elapsed) / 1_000_000_000 if isinstance(elapsed, (int, float)) else None
            return OllamaPreloadResult(model=str(data.get("model", model)), ok=True, elapsed_seconds=elapsed_seconds)
        except Exception as exc:  # noqa: BLE001 - model unload is operational best-effort
            return OllamaPreloadResult(model=model, ok=False, error=str(exc))

    def list_models(self) -> OllamaModelListResult:
        result = self.list_model_infos()
        return OllamaModelListResult(ok=result.ok, models=[item.name for item in result.models], error=result.error)

    def embed(
        self,
        *,
        model: str,
        inputs: str | list[str],
        timeout_seconds: int | None = None,
    ) -> OllamaEmbeddingResponse:
        normalized_inputs = [inputs] if isinstance(inputs, str) else list(inputs)
        normalized_inputs = [self._normalize_embedding_input(item) for item in normalized_inputs]
        if not normalized_inputs:
            return OllamaEmbeddingResponse(model=model, embeddings=[])
        try:
            data = self._post_json(
                "/api/embed",
                {"model": model, "input": normalized_inputs},
                timeout_seconds=timeout_seconds,
            )
            embeddings = data.get("embeddings")
            if isinstance(embeddings, list):
                return OllamaEmbeddingResponse(model=str(data.get("model", model)), embeddings=self._parse_embeddings(embeddings))
        except RuntimeError:
            if len(normalized_inputs) != 1:
                raise
        if len(normalized_inputs) != 1:
            raise RuntimeError("Ollama embedding batch endpoint returned no embeddings")
        data = self._post_json(
            "/api/embeddings",
            {"model": model, "prompt": normalized_inputs[0]},
            timeout_seconds=timeout_seconds,
        )
        embedding = data.get("embedding")
        if not isinstance(embedding, list):
            raise RuntimeError("Ollama embedding endpoint returned no embedding vector")
        return OllamaEmbeddingResponse(model=str(data.get("model", model)), embeddings=[self._parse_embedding(embedding)])

    def running_models(self) -> dict[str, object]:
        req = request.Request(
            f"{self.base_url}/api/ps",
            method="GET",
            headers={"Accept": "application/json"},
        )
        try:
            with request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode("utf-8"))
        except error.URLError as exc:
            return {"ok": False, "base_url": self.base_url, "models": [], "error": str(exc)}
        except json.JSONDecodeError:
            return {"ok": False, "base_url": self.base_url, "models": [], "error": "Ollama returned invalid JSON"}
        if not isinstance(data, dict):
            return {"ok": False, "base_url": self.base_url, "models": [], "error": "Ollama returned a non-object JSON payload"}
        models = data.get("models", [])
        return {
            "ok": True,
            "base_url": self.base_url,
            "models": models if isinstance(models, list) else [],
            "error": None,
        }

    def list_model_infos(self) -> OllamaModelInfoListResult:
        req = request.Request(
            f"{self.base_url}/api/tags",
            method="GET",
            headers={"Accept": "application/json"},
        )
        try:
            with request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode("utf-8"))
        except error.URLError as exc:
            return OllamaModelInfoListResult(ok=False, models=[], error=f"Ollama is not reachable at {self.base_url}: {exc}")
        except json.JSONDecodeError:
            return OllamaModelInfoListResult(ok=False, models=[], error="Ollama returned invalid JSON")
        if not isinstance(data, dict):
            return OllamaModelInfoListResult(ok=False, models=[], error="Ollama returned a non-object JSON payload")
        models: list[OllamaModelInfo] = []
        for item in data.get("models", []):
            if isinstance(item, dict) and item.get("name"):
                name = str(item["name"])
                if name.endswith(":cloud"):
                    continue
                details = item.get("details") if isinstance(item.get("details"), dict) else {}
                models.append(
                    OllamaModelInfo(
                        name=name,
                        architecture=self._optional_str(details.get("family") or details.get("families")),
                        quantization=self._optional_str(details.get("quantization_level")),
                        params=self._optional_str(details.get("parameter_size")),
                        size=self._optional_int(item.get("size")),
                        raw=dict(item),
                    )
                )
        deduped = {item.name: item for item in models}
        return OllamaModelInfoListResult(ok=True, models=[deduped[name] for name in sorted(deduped)])

    def is_reachable(self, *, timeout_seconds: float = 0.25) -> bool:
        req = request.Request(
            f"{self.base_url}/api/tags",
            method="GET",
            headers={"Accept": "application/json"},
        )
        try:
            with request.urlopen(req, timeout=timeout_seconds) as response:
                return 200 <= int(response.status) < 500
        except Exception:
            return False

    def _post_generate(self, payload: dict[str, object], *, timeout_seconds: int | None = None) -> dict[str, object]:
        return self._post_json("/api/generate", payload, timeout_seconds=timeout_seconds)

    def _post_json(
        self,
        endpoint: str,
        payload: dict[str, object],
        *,
        timeout_seconds: int | None = None,
    ) -> dict[str, object]:
        body = json.dumps(payload).encode("utf-8")
        req = request.Request(
            f"{self.base_url}{endpoint}",
            data=body,
            method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with request.urlopen(req, timeout=timeout_seconds or self.timeout_seconds) as response:
                data = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace") if hasattr(exc, "read") else ""
            detail = f"{exc}"
            if body.strip():
                detail = f"{detail}: {body.strip()[:500]}"
            raise RuntimeError(f"Ollama request failed at {self.base_url}{endpoint}: {detail}") from exc
        except error.URLError as exc:
            raise RuntimeError(f"Ollama is not reachable at {self.base_url}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise RuntimeError("Ollama returned invalid JSON") from exc
        if not isinstance(data, dict):
            raise RuntimeError("Ollama returned a non-object JSON payload")
        return data

    def _normalize_embedding_input(self, value: str) -> str:
        normalized = " ".join(str(value or "").replace("\r", "\n").split())
        return (normalized or " ")[: self.MAX_EMBEDDING_CHARS]

    def _parse_embeddings(self, values: list[object]) -> list[list[float]]:
        return [self._parse_embedding(value) for value in values]

    def _parse_embedding(self, value: object) -> list[float]:
        if not isinstance(value, list):
            raise RuntimeError("Ollama returned a non-list embedding vector")
        vector = [float(item) for item in value if isinstance(item, int | float)]
        if not vector:
            raise RuntimeError("Ollama returned an empty embedding vector")
        return vector

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
