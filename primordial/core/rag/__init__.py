"""RAG ingestion and retrieval services."""

from primordial.core.rag.attack import AttackIndexPreprocessor, AttackPreprocessError
from primordial.core.rag.documents import DocumentIngestionError, DocumentIngestionService
from primordial.core.rag.embeddings import (
    DeterministicHashEmbeddingProvider,
    EmbeddingProviderError,
    OllamaEmbeddingProvider,
    OpenAICompatibleEmbeddingProvider,
)

__all__ = [
    "AttackIndexPreprocessor",
    "AttackPreprocessError",
    "DeterministicHashEmbeddingProvider",
    "DocumentIngestionError",
    "DocumentIngestionService",
    "EmbeddingProviderError",
    "OllamaEmbeddingProvider",
    "OpenAICompatibleEmbeddingProvider",
]
