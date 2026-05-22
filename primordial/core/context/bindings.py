from __future__ import annotations

from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.normalization import normalized_context_key, normalized_metadata_value
from primordial.core.context.poison import has_context_flag


CURRENT_TARGET_METADATA_KEYS = ("current_target_id", "active_target_id", "target_context_id")
CURRENT_GENERATION_METADATA_KEYS = (
    "current_active_generation_id",
    "target_active_generation_id",
    "current_generation_id",
    "current_active_ip_generation",
)
PROOF_KINDS = frozenset({"evidence", "finding"})
TARGET_FACT_METADATA_KEYS = ("contains_target_fact", "target_factual_claim", "target_fact")


def has_target_fact_marker(envelope: ContextEnvelope) -> bool:
    return has_context_flag(envelope, TARGET_FACT_METADATA_KEYS)


def current_context_binding_error(
    envelope: ContextEnvelope,
    *,
    proof_records: bool = False,
    target_facts: bool = False,
) -> str:
    if not _requires_binding(envelope, proof_records=proof_records, target_facts=target_facts):
        return ""
    current_target = normalized_metadata_value(envelope.metadata, *CURRENT_TARGET_METADATA_KEYS)
    envelope_target = normalized_context_key(envelope.target_id)
    if current_target:
        if not envelope_target:
            return "missing_target_binding"
        if envelope_target != current_target:
            return "wrong_target"
    current_generation = normalized_metadata_value(envelope.metadata, *CURRENT_GENERATION_METADATA_KEYS)
    envelope_generation = normalized_context_key(envelope.active_generation_id)
    if current_generation:
        if not envelope_generation:
            return "missing_generation_binding"
        if envelope_generation != current_generation:
            return "stale_generation"
    return ""


def _requires_binding(envelope: ContextEnvelope, *, proof_records: bool, target_facts: bool) -> bool:
    return (proof_records and envelope.kind in PROOF_KINDS) or (target_facts and has_target_fact_marker(envelope))
