from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
import re


@dataclass(frozen=True, slots=True)
class DeterministicHashEmbeddingProvider:
    """Small local embedding provider used when no model-backed embedder is configured.

    This is intentionally not a chat-model fallback. It gives the control plane a
    deterministic vector path for indexing, tests, and lexical-ish retrieval until
    a real embedding model is wired in.
    """

    model_name: str = "local-hash-embedding-v1"
    dimension: int = 64

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

    def _tokens(self, text: str) -> list[str]:
        return [
            token
            for token in re.findall(r"[A-Za-z0-9_.:/-]+", text.lower())
            if len(token) > 2
        ][:2048]
