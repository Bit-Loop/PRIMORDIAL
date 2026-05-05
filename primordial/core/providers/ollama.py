from __future__ import annotations

from dataclasses import dataclass
import json
import os
from urllib import error, request


@dataclass(slots=True)
class OllamaResponse:
    model: str
    text: str
    elapsed_seconds: float | None = None


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


class OllamaClient:
    def __init__(self, base_url: str | None = None, timeout_seconds: int = 90) -> None:
        self.base_url = (base_url or os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")).rstrip("/")
        self.timeout_seconds = timeout_seconds

    def generate(
        self,
        *,
        model: str,
        prompt: str,
        system: str,
        temperature: float = 0.2,
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
        return OllamaResponse(model=str(data.get("model", model)), text=text, elapsed_seconds=elapsed_seconds)

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
        req = request.Request(
            f"{self.base_url}/api/tags",
            method="GET",
            headers={"Accept": "application/json"},
        )
        try:
            with request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode("utf-8"))
        except error.URLError as exc:
            return OllamaModelListResult(ok=False, models=[], error=f"Ollama is not reachable at {self.base_url}: {exc}")
        except json.JSONDecodeError as exc:
            return OllamaModelListResult(ok=False, models=[], error="Ollama returned invalid JSON")
        if not isinstance(data, dict):
            return OllamaModelListResult(ok=False, models=[], error="Ollama returned a non-object JSON payload")
        models = []
        for item in data.get("models", []):
            if isinstance(item, dict) and item.get("name"):
                name = str(item["name"])
                if name.endswith(":cloud"):
                    continue
                models.append(name)
        return OllamaModelListResult(ok=True, models=sorted(set(models)))

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
        body = json.dumps(payload).encode("utf-8")
        req = request.Request(
            f"{self.base_url}/api/generate",
            data=body,
            method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with request.urlopen(req, timeout=timeout_seconds or self.timeout_seconds) as response:
                data = json.loads(response.read().decode("utf-8"))
        except error.URLError as exc:
            raise RuntimeError(f"Ollama is not reachable at {self.base_url}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise RuntimeError("Ollama returned invalid JSON") from exc
        if not isinstance(data, dict):
            raise RuntimeError("Ollama returned a non-object JSON payload")
        return data
