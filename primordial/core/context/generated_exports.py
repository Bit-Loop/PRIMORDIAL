from __future__ import annotations

from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.normalization import normalized_metadata_value


GENERATED_EXPORT_KINDS = frozenset({"generated_export", "export_archive"})
GENERATED_EXPORT_SOURCE_TYPES = frozenset({"generated_export", "export_archive"})
GENERATED_EXPORT_ORIGINS = frozenset({"generated_export", "export_archive"})


def is_generated_export_context(envelope: ContextEnvelope) -> bool:
    return is_generated_export_record(envelope) or has_generated_export_origin(envelope)


def is_generated_export_record(envelope: ContextEnvelope) -> bool:
    return (
        envelope.kind in GENERATED_EXPORT_KINDS
        or envelope.source_type in GENERATED_EXPORT_SOURCE_TYPES
    )


def has_generated_export_origin(envelope: ContextEnvelope) -> bool:
    return normalized_metadata_value(envelope.metadata, "origin") in GENERATED_EXPORT_ORIGINS
