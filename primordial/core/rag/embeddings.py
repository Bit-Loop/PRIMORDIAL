from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import math
import re
from typing import Protocol
from urllib import error, request

from primordial.core.config import RagEmbeddingSettings
from primordial.core.providers.ollama import OllamaClient


class EmbeddingProvider(Protocol):
    provider_name: str
    model_name: str
    dimension: int | None

    def embed(self, text: str) -> list[float]:
        ...

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        ...

    def assert_ready(self) -> None:
        ...


class EmbeddingProviderError(RuntimeError):
    pass


@dataclass(slots=True)
class DeterministicHashEmbeddingProvider:
    """Small local embedding provider used when no model-backed embedder is configured.

    This is intentionally not a chat-model fallback. It gives the control plane a
    deterministic vector path for indexing, tests, and lexical-ish retrieval until
    a real embedding model is wired in.
    """

    model_name: str = "local-hash-embedding-v1"
    dimension: int = 64
    provider_name: str = "deterministic_hash"

    def embed(self, text: str) -> list[float]:
        vector = [0.0 for _ in range(self.dimension)]
        for token in self._tokens(text):
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            index = int.from_bytes(digest[:4], "big") % self.dimension
            sign = 1.0 if digest[4] % 2 == 0 else -1.0
            weight = 1.0 + (len(token) % 7) / 10.0
            vector[index] += sign * weight
        norm = math.sqrt(sum(value * value for value in vector))
        if norm <= 0:
            return vector
        return [round(value / norm, 8) for value in vector]

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        return [self.embed(text) for text in texts]

    def assert_ready(self) -> None:
        return None

    def _tokens(self, text: str) -> list[str]:
        return [
            token
            for token in re.findall(r"[A-Za-z0-9_.:/-]+", text.lower())
            if len(token) > 2
        ][:2048]


@dataclass(slots=True)
class OllamaEmbeddingProvider:
    base_url: str = "http://127.0.0.1:11434"
    model_name: str = "nomic-embed-text:v1.5"
    timeout_seconds: int = 90
    provider_name: str = "ollama"
    canonical_model_family: str = "text-embedding-nomic-embed-text-v1.5"
    dimension: int | None = None
    client: OllamaClient = field(init=False)

    def __post_init__(self) -> None:
        self.client = OllamaClient(base_url=self.base_url, timeout_seconds=self.timeout_seconds)

    def assert_ready(self) -> None:
        result = self.client.list_models()
        if not result.ok:
            raise EmbeddingProviderError(result.error or f"Ollama is not reachable at {self.base_url}")
        installed = set(result.models)
        if self.model_name not in installed:
            aliases = {name.split(":", 1)[0] for name in installed if ":" in name}
            if self.model_name.split(":", 1)[0] not in aliases:
                raise EmbeddingProviderError(
                    f"Ollama embedding model {self.model_name!r} is not installed; "
                    f"run `ollama pull {self.model_name}`"
                )

    def embed(self, text: str) -> list[float]:
        return self.embed_batch([text])[0]

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        try:
            response = self.client.embed(model=self.model_name, inputs=texts, timeout_seconds=self.timeout_seconds)
        except Exception as exc:  # noqa: BLE001 - normalize provider failures for importer/runtime callers
            raise EmbeddingProviderError(f"Ollama embedding failed for {self.model_name}: {exc}") from exc
        vectors = response.embeddings
        if len(vectors) != len(texts):
            raise EmbeddingProviderError(
                f"Ollama returned {len(vectors)} embedding(s) for {len(texts)} input(s)"
            )
        if vectors:
            self.dimension = len(vectors[0])
        return vectors


@dataclass(slots=True)
class OpenAICompatibleEmbeddingProvider:
    MAX_EMBEDDING_CHARS = 2048

    base_url: str = "http://127.0.0.1:1234/v1"
    model_name: str = "text-embedding-nomic-embed-text-v1.5"
    timeout_seconds: int = 90
    api_key: str | None = None
    provider_name: str = "openai_compatible"
    dimension: int | None = None

    def assert_ready(self) -> None:
        try:
            data = self._request_json("GET", "/models")
        except Exception as exc:  # noqa: BLE001 - present a stable operator-facing error
            raise EmbeddingProviderError(f"OpenAI-compatible embeddings endpoint is unavailable: {exc}") from exc
        model_ids = {
            str(item.get("id") or item.get("name"))
            for item in data.get("data", [])
            if isinstance(item, dict) and (item.get("id") or item.get("name"))
        }
        if model_ids and self.model_name not in model_ids:
            raise EmbeddingProviderError(f"embedding model {self.model_name!r} is not listed by {self.base_url}/models")

    def embed(self, text: str) -> list[float]:
        return self.embed_batch([text])[0]

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        payload = {"model": self.model_name, "input": [self._normalize_text(text) for text in texts]}
        try:
            data = self._request_json("POST", "/embeddings", payload)
        except Exception as exc:  # noqa: BLE001
            raise EmbeddingProviderError(f"OpenAI-compatible embedding failed for {self.model_name}: {exc}") from exc
        rows = data.get("data", [])
        if not isinstance(rows, list):
            raise EmbeddingProviderError("OpenAI-compatible embeddings response has no data array")
        ordered = sorted(
            [row for row in rows if isinstance(row, dict)],
            key=lambda row: int(row.get("index", 0)) if not isinstance(row.get("index"), bool) else 0,
        )
        vectors = [self._parse_embedding(row.get("embedding")) for row in ordered]
        if len(vectors) != len(texts):
            raise EmbeddingProviderError(f"provider returned {len(vectors)} embedding(s) for {len(texts)} input(s)")
        if vectors:
            self.dimension = len(vectors[0])
        return vectors

    def _request_json(self, method: str, endpoint: str, payload: dict[str, object] | None = None) -> dict[str, object]:
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        req = request.Request(
            f"{self._normalized_base_url()}{endpoint}",
            data=body,
            method=method,
            headers=self._headers(),
        )
        try:
            with request.urlopen(req, timeout=self.timeout_seconds) as response:
                data = json.loads(response.read().decode("utf-8"))
        except error.URLError as exc:
            raise RuntimeError(exc) from exc
        except json.JSONDecodeError as exc:
            raise RuntimeError("provider returned invalid JSON") from exc
        if not isinstance(data, dict):
            raise RuntimeError("provider returned a non-object JSON payload")
        return data

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _normalized_base_url(self) -> str:
        base = self.base_url.rstrip("/")
        return base if base.endswith("/v1") else f"{base}/v1"

    def _normalize_text(self, text: str) -> str:
        normalized = " ".join(str(text or "").replace("\r", "\n").split())
        return (normalized or " ")[: self.MAX_EMBEDDING_CHARS]

    def _parse_embedding(self, value: object) -> list[float]:
        if not isinstance(value, list):
            raise EmbeddingProviderError("embedding row does not contain a vector")
        vector = [float(item) for item in value if isinstance(item, int | float)]
        if not vector:
            raise EmbeddingProviderError("embedding row contains an empty vector")
        return vector


def embedding_provider_from_config(settings: RagEmbeddingSettings) -> EmbeddingProvider:
    provider = settings.provider.strip().lower().replace("-", "_")
    if provider == "ollama":
        return OllamaEmbeddingProvider(
            base_url=settings.base_url,
            model_name=settings.model,
            timeout_seconds=settings.timeout_seconds,
            canonical_model_family=settings.canonical_model_family,
        )
    if provider in {"openai_compatible", "lmstudio_openai_compatible", "lmstudio"}:
        return OpenAICompatibleEmbeddingProvider(
            base_url=settings.base_url,
            model_name=settings.model,
            timeout_seconds=settings.timeout_seconds,
            provider_name=provider,
        )
    if provider in {"deterministic_hash", "hash"}:
        return DeterministicHashEmbeddingProvider()
    raise EmbeddingProviderError(f"unsupported RAG embedding provider: {settings.provider}")
