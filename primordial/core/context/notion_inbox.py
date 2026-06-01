from __future__ import annotations

from dataclasses import dataclass

from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.normalization import normalized_context_key, normalized_context_keys
from primordial.core.context.poison import has_context_flag
from primordial.core.context.source_markdown import is_source_markdown_context
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
    unsupported_source_type = _unsupported_source_type(envelope)
    if unsupported_source_type:
        return NotionInboxDecision(
            "reject",
            f"notion_inbox rejects {envelope.ref}: unsupported source_type={unsupported_source_type}",
        )
    if is_source_markdown_context(envelope):
        return NotionInboxDecision(
            "reject",
            f"notion_inbox rejects {envelope.ref}: source_markdown",
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
    return _first_metadata_text_value(envelope.metadata, keys)


def _first_metadata_text_value(value: object, keys: tuple[str, ...]) -> str:
    normalized_keys = normalized_context_keys(keys)
    if isinstance(value, dict):
        items = value.items()
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            text = _first_metadata_text_value(item, keys)
            if text:
                return text
        return ""
    else:
        return ""
    for raw_key, item_value in items:
        if normalized_context_key(raw_key) in normalized_keys:
            text = normalized_context_key(item_value)
            if text:
                return text
        text = _first_metadata_text_value(item_value, keys)
        if text:
            return text
    return ""


def _metadata_text_values(value: object, keys: tuple[str, ...]) -> set[str]:
    normalized_keys = normalized_context_keys(keys)
    values: set[str] = set()
    if isinstance(value, dict):
        items = value.items()
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            values.update(_metadata_text_values(item, keys))
        return values
    else:
        return values
    for raw_key, item_value in items:
        if normalized_context_key(raw_key) in normalized_keys:
            for item in _metadata_scalar_values(item_value):
                text = normalized_context_key(item)
                if text:
                    values.add(text)
        values.update(_metadata_text_values(item_value, keys))
    return values


def _metadata_scalar_values(value: object) -> list[object]:
    if isinstance(value, dict):
        return []
    if isinstance(value, (list, tuple, set)):
        values: list[object] = []
        for item in value:
            values.extend(_metadata_scalar_values(item))
        return values
    return [value]


def _unsupported_source_type(envelope: ContextEnvelope) -> str:
    source_types = {
        normalized_context_key(envelope.source_type),
        *_metadata_text_values(envelope.metadata, ("source_type", "source_types")),
    }
    return next(iter(sorted(source_type for source_type in source_types if source_type != NOTION_INBOX_SOURCE_TYPE)), "")


def _is_confirmed_finding(envelope: ContextEnvelope) -> bool:
    if envelope.kind not in CONFIRMABLE_FINDING_KINDS:
        return False
    statuses = _metadata_text_values(envelope.metadata, FINDING_STATUS_METADATA_KEYS)
    return envelope.authority in CONFIRMED_FINDING_STATUSES or bool(statuses & CONFIRMED_FINDING_STATUSES)


def _has_truth_like_authority(envelope: ContextEnvelope) -> bool:
    return (
        normalized_context_key(envelope.authority) in TRUTH_LIKE_AUTHORITIES
        or bool(_metadata_text_values(envelope.metadata, ("authority", "authorities")) & TRUTH_LIKE_AUTHORITIES)
    )
