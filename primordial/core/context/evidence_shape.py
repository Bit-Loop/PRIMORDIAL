from __future__ import annotations

from primordial.core.context.envelopes import ContextEnvelope


EVIDENCE_AUTHORITIES = frozenset({"canonical", "authoritative", "observed", "reviewed"})
EVIDENCE_CONTEXT_AUTHORITIES = EVIDENCE_AUTHORITIES | frozenset({"asserted", "confirmed"})
EVIDENCE_REF_PREFIX = "evidence:"
FINDING_REF_PREFIX = "finding:"


def evidence_shape_omission_reason(
    envelope: ContextEnvelope,
    *,
    allowed_authorities: frozenset[str] = EVIDENCE_AUTHORITIES,
) -> str:
    if envelope.kind != "evidence":
        return ""
    if envelope.authority not in allowed_authorities:
        return f"authority={envelope.authority}"
    if not envelope.ref.startswith(EVIDENCE_REF_PREFIX):
        return "ref"
    return ""


def finding_shape_omission_reason(envelope: ContextEnvelope) -> str:
    if envelope.kind != "finding":
        return ""
    if not envelope.ref.startswith(FINDING_REF_PREFIX):
        return "ref"
    return ""
