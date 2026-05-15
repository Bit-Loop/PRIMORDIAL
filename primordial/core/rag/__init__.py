"""RAG ingestion and retrieval services."""

from primordial.core.rag.attack import AttackIndexPreprocessor, AttackPreprocessError
from primordial.core.rag.context import RagContextBroker, RagContextPack
from primordial.core.rag.documents import DocumentIngestionError, DocumentIngestionService
from primordial.core.rag.embeddings import (
    DeterministicHashEmbeddingProvider,
    EmbeddingProviderError,
    OllamaEmbeddingProvider,
    OpenAICompatibleEmbeddingProvider,
)
from primordial.core.rag.vuln_hints import vulnerability_hints_from_results

__all__ = [
    "AttackIndexPreprocessor",
    "AttackPreprocessError",
    "DeterministicHashEmbeddingProvider",
    "DocumentIngestionError",
    "DocumentIngestionService",
    "EmbeddingProviderError",
    "OllamaEmbeddingProvider",
    "OpenAICompatibleEmbeddingProvider",
    "RagContextBroker",
    "RagContextPack",
    "vulnerability_hints_from_results",
]
