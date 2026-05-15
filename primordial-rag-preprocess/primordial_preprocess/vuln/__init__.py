"""Vulnerability-intelligence preprocessing for PRIMORDIAL RAG."""

from .cards import cards_for_record, card_to_rag_chunk
from .merge import merge_records
from .models import (
    AdvisoryDocRecord,
    AdvisoryExtractedFacts,
    VulnEvent,
    VulnerabilityIntelCard,
    VulnerabilityRecord,
    VulnSourceCursor,
)

__all__ = [
    "AdvisoryDocRecord",
    "AdvisoryExtractedFacts",
    "VulnEvent",
    "VulnerabilityIntelCard",
    "VulnerabilityRecord",
    "VulnSourceCursor",
    "card_to_rag_chunk",
    "cards_for_record",
    "merge_records",
]
