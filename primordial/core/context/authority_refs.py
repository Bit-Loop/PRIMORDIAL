from __future__ import annotations

from typing import Iterable

from primordial.core.context.envelopes import ContextEnvelope


POLICY_DECISION_REF_PREFIX = "policy_decision:"


def unresolved_policy_decision_citation_errors(
    envelope: ContextEnvelope,
    *,
    known_policy_decision_refs: Iterable[str] | None = None,
) -> list[str]:
    policy_decision_refs = _citations_with_prefix(envelope, POLICY_DECISION_REF_PREFIX)
    if known_policy_decision_refs is None:
        if policy_decision_refs:
            return [f"task_metadata requires known policy decision refs ref={envelope.ref}"]
        return []
    unresolved = _unresolved_refs(policy_decision_refs, known_policy_decision_refs)
    if not unresolved:
        return []
    refs = ", ".join(unresolved)
    return [f"task_metadata rejects unresolved policy decision refs ref={envelope.ref}: {refs}"]


def _citations_with_prefix(envelope: ContextEnvelope, prefix: str) -> list[str]:
    return [str(citation).strip() for citation in envelope.citations if str(citation).strip().startswith(prefix)]


def _unresolved_refs(refs: list[str], known_refs: Iterable[str]) -> list[str]:
    normalized_known_refs = {str(ref).strip() for ref in known_refs if str(ref).strip()}
    return [ref for ref in refs if ref not in normalized_known_refs]
