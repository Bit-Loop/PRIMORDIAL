from __future__ import annotations

from dataclasses import dataclass

from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.normalization import normalized_context_key, normalized_context_keys
from primordial.core.context.poison import has_context_flag
from primordial.core.context.source_types import TRUTH_LIKE_AUTHORITIES


ALLOWED_INBOUND_KINDS = frozenset(
    {
        "operator_note",
        "candidate_task",
        "correction_proposal",
        "finding_draft_delta",
        "hypothesis",
        "manual_tag",
        "external_reference",
    }
)
AUTHORITY_MUTATION_KINDS = frozenset({"approval", "evidence", "operator_intent", "scope"})
AUTHORITY_MUTATION_FLAGS = {
    "creates_evidence": "evidence",
    "creates_approval": "approval",
    "expands_scope": "scope",
    "changes_scope": "scope",
    "changes_operator_intent": "Operator Intent",
    "confirms_finding": "confirmed finding",
    "creates_target_authority": "target authority",
}
OWNERSHIP_METADATA_KEYS = ("block_owner", "owner", "sync_owner", "local_owner")
EDIT_SOURCE_METADATA_KEYS = ("edit_source", "edited_by", "modified_by", "source_actor")
USER_EDIT_SOURCES = frozenset({"external", "human", "operator", "user"})
FINDING_STATUS_METADATA_KEYS = ("finding_status", "status", "review_status")
CONFIRMABLE_FINDING_KINDS = frozenset({"finding", "finding_draft_delta"})
CONFIRMED_FINDING_STATUSES = frozenset({"authoritative", "canonical", "confirmed", "reviewed"})
NOTION_INBOX_SOURCE_TYPE = "notion"


@dataclass(frozen=True, slots=True)
class NotionInboxDecision:
    action: str
    message: str = ""


def validate_notion_inbox_envelope(envelope: ContextEnvelope) -> NotionInboxDecision:
    if normalized_context_key(envelope.source_type) != NOTION_INBOX_SOURCE_TYPE:
        return NotionInboxDecision(
            "reject",
            f"notion_inbox rejects {envelope.ref}: unsupported source_type={envelope.source_type}",
        )
    mutation = _authority_mutation(envelope)
    if mutation:
        return NotionInboxDecision(
            "reject",
            f"notion_inbox rejects {envelope.ref}: Notion edit cannot create or change {mutation}",
        )
    if _requires_manual_review(envelope):
        return NotionInboxDecision(
            "quarantine",
            f"notion_inbox quarantines {envelope.ref}: Primordial-owned block edit requires manual review",
        )
    if _is_confirmed_finding(envelope):
        return NotionInboxDecision(
            "reject",
            f"notion_inbox rejects {envelope.ref}: Notion edit cannot create a confirmed finding",
        )
    if _has_truth_like_authority(envelope):
        return NotionInboxDecision(
            "reject",
            f"notion_inbox rejects {envelope.ref}: Notion proposal cannot carry truth-like authority",
        )
    if envelope.kind not in ALLOWED_INBOUND_KINDS:
        return NotionInboxDecision(
            "reject",
            f"notion_inbox rejects {envelope.ref}: unsupported inbound kind={envelope.kind}",
        )
    return NotionInboxDecision("accept")


def _authority_mutation(envelope: ContextEnvelope) -> str:
    if envelope.kind in AUTHORITY_MUTATION_KINDS:
        return "Operator Intent" if envelope.kind == "operator_intent" else envelope.kind.replace("_", " ")
    for flag, label in AUTHORITY_MUTATION_FLAGS.items():
        if has_context_flag(envelope, (flag,)):
            return label
    return ""


def _requires_manual_review(envelope: ContextEnvelope) -> bool:
    owner = _first_metadata_text(envelope, OWNERSHIP_METADATA_KEYS)
    edit_source = _first_metadata_text(envelope, EDIT_SOURCE_METADATA_KEYS)
    edited_by_user = has_context_flag(envelope, ("edited_by_user", "user_modified"))
    return owner == "primordial" and (edited_by_user or not edit_source or edit_source in USER_EDIT_SOURCES)


def _first_metadata_text(envelope: ContextEnvelope, keys: tuple[str, ...]) -> str:
    normalized_keys = normalized_context_keys(keys)
    for raw_key, value in envelope.metadata.items():
        if normalized_context_key(raw_key) in normalized_keys:
            text = normalized_context_key(value)
            if text:
                return text
    return ""


def _is_confirmed_finding(envelope: ContextEnvelope) -> bool:
    if envelope.kind not in CONFIRMABLE_FINDING_KINDS:
        return False
    status = _first_metadata_text(envelope, FINDING_STATUS_METADATA_KEYS)
    return envelope.authority in CONFIRMED_FINDING_STATUSES or status in CONFIRMED_FINDING_STATUSES


def _has_truth_like_authority(envelope: ContextEnvelope) -> bool:
    return normalized_context_key(envelope.authority) in TRUTH_LIKE_AUTHORITIES
