from __future__ import annotations

from dataclasses import dataclass

from primordial.core.context.bindings import TARGET_FACT_METADATA_KEYS
from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.normalization import normalized_context_key, normalized_context_keys
from primordial.core.context.poison import has_context_flag
from primordial.core.context.source_types import TRUTH_LIKE_AUTHORITIES


ALLOWED_GITHUB_KINDS = frozenset(
    {
        "github_ref",
        "engineering_context",
        "failure_analysis",
        "patch_proposal",
        "test_status",
    }
)
ALLOWED_CONTEXT_TYPES = frozenset(
    {
        "engineering_context",
        "failure_analysis",
        "patch_history",
        "patch_proposal",
        "parser_failure",
        "regression_failure",
        "test_status",
    }
)
AUTHORITY_MUTATION_KINDS = frozenset({"approval", "evidence", "operator_intent", "scope"})
AUTHORITY_MUTATION_FLAGS = {
    "creates_evidence": "evidence",
    "creates_approval": "approval",
    "changes_scope": "scope",
    "expands_scope": "scope",
    "changes_operator_intent": "Operator Intent",
    "authorizes_target_action": "target action",
    "confirms_finding": "confirmed finding",
    "creates_target_authority": "target authority",
    "mutates_target_truth": "target truth",
}
SENSITIVE_FLAGS = (
    "contains_sensitive_raw_target_evidence",
    "contains_raw_flag",
    "contains_secret",
    "contains_credential",
    "hidden_solution_material",
)
REDACTION_FLAGS = ("redacted", "evidence_refs_redacted")
EVIDENCE_REF_METADATA_KEYS = ("evidence_refs", "evidence_ids")
FINDING_STATUS_METADATA_KEYS = ("finding_status", "target_finding_status")
CONFIRMED_FINDING_STATUSES = frozenset({"authoritative", "canonical", "confirmed", "reviewed"})


@dataclass(frozen=True, slots=True)
class GitHubLedgerDecision:
    action: str
    message: str = ""


def validate_github_ledger_envelope(envelope: ContextEnvelope) -> GitHubLedgerDecision:
    mutation = _authority_mutation(envelope)
    if mutation:
        return GitHubLedgerDecision(
            "reject",
            f"github_ledger rejects {envelope.ref}: GitHub material cannot create or change {mutation}",
        )
    if _is_confirmed_finding(envelope):
        return GitHubLedgerDecision(
            "reject",
            f"github_ledger rejects {envelope.ref}: GitHub material cannot create a confirmed finding",
        )
    if _has_target_fact_marker(envelope):
        return GitHubLedgerDecision(
            "reject",
            f"github_ledger rejects {envelope.ref}: GitHub material cannot create a target fact",
        )
    if _has_truth_like_authority(envelope):
        return GitHubLedgerDecision(
            "reject",
            f"github_ledger rejects {envelope.ref}: GitHub material cannot carry truth-like authority",
        )
    if _has_sensitive_unredacted_material(envelope):
        return GitHubLedgerDecision(
            "reject",
            f"github_ledger rejects {envelope.ref}: sensitive target material requires redaction",
        )
    if _has_evidence_refs(envelope) and not _is_redacted(envelope):
        return GitHubLedgerDecision(
            "reject",
            f"github_ledger rejects {envelope.ref}: evidence refs require redaction",
        )
    if envelope.kind not in ALLOWED_GITHUB_KINDS and _context_type(envelope) not in ALLOWED_CONTEXT_TYPES:
        return GitHubLedgerDecision(
            "reject",
            f"github_ledger rejects {envelope.ref}: unsupported engineering ledger kind={envelope.kind}",
        )
    return GitHubLedgerDecision("accept")


def _authority_mutation(envelope: ContextEnvelope) -> str:
    if envelope.kind in AUTHORITY_MUTATION_KINDS:
        return "Operator Intent" if envelope.kind == "operator_intent" else envelope.kind.replace("_", " ")
    for flag, label in AUTHORITY_MUTATION_FLAGS.items():
        if has_context_flag(envelope, (flag,)):
            return label
    return ""


def _is_confirmed_finding(envelope: ContextEnvelope) -> bool:
    status = _metadata_text(envelope, FINDING_STATUS_METADATA_KEYS)
    if status in CONFIRMED_FINDING_STATUSES:
        return True
    return envelope.kind == "finding" and envelope.authority in CONFIRMED_FINDING_STATUSES


def _has_target_fact_marker(envelope: ContextEnvelope) -> bool:
    return has_context_flag(envelope, TARGET_FACT_METADATA_KEYS)


def _has_truth_like_authority(envelope: ContextEnvelope) -> bool:
    return normalized_context_key(envelope.authority) in TRUTH_LIKE_AUTHORITIES


def _has_sensitive_unredacted_material(envelope: ContextEnvelope) -> bool:
    return has_context_flag(envelope, SENSITIVE_FLAGS) and not _is_redacted(envelope)


def _is_redacted(envelope: ContextEnvelope) -> bool:
    return has_context_flag(envelope, REDACTION_FLAGS)


def _has_evidence_refs(envelope: ContextEnvelope) -> bool:
    refs = _metadata_ref_values(_metadata_value(envelope, EVIDENCE_REF_METADATA_KEYS))
    return any(_ref_text(item).startswith("evidence:") for item in [*refs, *envelope.citations])


def _metadata_ref_values(value: object | None) -> list[object]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list | tuple | set):
        return list(value)
    return []


def _metadata_value(envelope: ContextEnvelope, keys: tuple[str, ...]) -> object | None:
    normalized_keys = normalized_context_keys(keys)
    for raw_key, value in envelope.metadata.items():
        if normalized_context_key(raw_key) in normalized_keys:
            return value
    return None


def _ref_text(value: object) -> str:
    return str(value).strip()


def _context_type(envelope: ContextEnvelope) -> str:
    return str(envelope.metadata.get("context_type") or "").strip().lower()


def _metadata_text(envelope: ContextEnvelope, keys: tuple[str, ...]) -> str:
    normalized_keys = normalized_context_keys(keys)
    for raw_key, value in envelope.metadata.items():
        if normalized_context_key(raw_key) in normalized_keys:
            text = normalized_context_key(value)
            if text:
                return text
    return ""
