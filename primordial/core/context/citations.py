from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.poison import has_context_flag
from primordial.core.context.source_refs import PLACEHOLDER_SOURCE_REFS, placeholder_source_refs


EVIDENCE_CITATION_PREFIX = "evidence:"
RAG_CITATION_PREFIX = "rag:"
CANONICAL_CITATION_PREFIXES = ("evidence:", "note:", "rag:")
NON_EVIDENCE_PROOF_CITATION_PREFIXES = ("rag:", "note:", "model:", "github:", "notion:", "ctfd:", "chat:")
TARGET_FACT_NON_EVIDENCE_CITATION_PREFIXES = ("note:", "model:", "github:", "notion:", "ctfd:", "chat:")
TARGET_FACT_ADVISORY_CITATION_PREFIXES = ("rag:",)
ADVISORY_NON_RAG_CITATION_PREFIXES = ("model:", "github:", "notion:", "ctfd:", "chat:")
PLACEHOLDER_RAG_REFS = frozenset(
    ref for ref in PLACEHOLDER_SOURCE_REFS if ref.startswith(RAG_CITATION_PREFIX)
)
REVIEWED_FINDING_AUTHORITIES = frozenset({"canonical", "authoritative", "confirmed", "observed", "reviewed"})
TARGET_FACT_METADATA_KEYS = frozenset({"contains_target_fact", "target_factual_claim", "target_fact"})
ADVISORY_CLAIM_METADATA_KEYS = frozenset({"advisory_claim", "contains_advisory_claim", "rag_advisory_claim"})


@dataclass(slots=True)
class CitationValidationResult:
    valid: bool
    accepted_refs: list[str] = field(default_factory=list)
    rejected_refs: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def as_payload(self) -> dict[str, object]:
        return {
            "valid": self.valid,
            "accepted_refs": list(self.accepted_refs),
            "rejected_refs": list(self.rejected_refs),
            "errors": list(self.errors),
            "warnings": list(self.warnings),
        }


class CitationValidator:
    def __init__(
        self,
        *,
        known_evidence_refs: Iterable[str] | None = None,
        known_rag_refs: Iterable[str] | None = None,
    ) -> None:
        self.known_evidence_refs = _normalized_ref_set(known_evidence_refs)
        self.known_rag_refs = _normalized_ref_set(known_rag_refs)

    def validate(self, envelopes: Iterable[ContextEnvelope]) -> CitationValidationResult:
        result = CitationValidationResult(valid=True)
        for envelope in envelopes:
            requires_evidence = _requires_evidence_citation(envelope)
            requires_rag = _requires_rag_citation(envelope)
            if not requires_evidence and not requires_rag:
                result.accepted_refs.append(envelope.ref)
                continue
            starting_error_count = len(result.errors)
            if requires_evidence:
                self._validate_evidence_citation(envelope, result)
            if requires_rag:
                self._validate_rag_citation(envelope, result)
            if len(result.errors) == starting_error_count:
                result.accepted_refs.append(envelope.ref)
        result.accepted_refs = sorted(set(result.accepted_refs))
        result.rejected_refs = sorted(set(result.rejected_refs))
        result.valid = not result.errors
        return result

    def _validate_evidence_citation(
        self,
        envelope: ContextEnvelope,
        result: CitationValidationResult,
    ) -> None:
        evidence_citations = _citations_with_prefix(envelope, EVIDENCE_CITATION_PREFIX)
        placeholder_refs = placeholder_source_refs(evidence_citations)
        if placeholder_refs:
            result.rejected_refs.append(envelope.ref)
            result.errors.append(
                f"{envelope.ref} has placeholder evidence citation(s): {', '.join(placeholder_refs)}"
            )
            return
        if evidence_citations:
            unresolved = _unresolved_refs(evidence_citations, self.known_evidence_refs)
            if unresolved:
                self._reject_unresolved(envelope, result, "evidence", unresolved)
                return
            unsupported = _reviewed_finding_unsupported_citations(envelope)
            if unsupported:
                result.rejected_refs.append(envelope.ref)
                result.errors.append(
                    f"{envelope.ref} has non-evidence citation support in reviewed finding: "
                    f"{', '.join(unsupported)}"
                )
                return
            target_fact_unsupported = _target_fact_unsupported_citations(envelope)
            if target_fact_unsupported:
                result.rejected_refs.append(envelope.ref)
                result.errors.append(
                    f"{envelope.ref} has non-evidence citation support in target factual claim: "
                    f"{', '.join(target_fact_unsupported)}"
                )
                return
            return
        supplied = ", ".join(envelope.citations) if envelope.citations else "none"
        result.rejected_refs.append(envelope.ref)
        result.errors.append(
            f"{envelope.ref} requires evidence:<id> citation support; "
            f"supplied citations cannot satisfy evidence requirements: {supplied}"
        )

    def _validate_rag_citation(
        self,
        envelope: ContextEnvelope,
        result: CitationValidationResult,
    ) -> None:
        rag_citations = _citations_with_prefix(envelope, RAG_CITATION_PREFIX)
        placeholder_refs = _placeholder_rag_refs(envelope, rag_citations)
        if placeholder_refs:
            result.rejected_refs.append(envelope.ref)
            result.errors.append(
                f"{envelope.ref} has placeholder rag citation(s): {', '.join(placeholder_refs)}"
            )
            return
        if envelope.ref.startswith(RAG_CITATION_PREFIX) and envelope.ref not in rag_citations:
            supplied = ", ".join(envelope.citations) if envelope.citations else "none"
            result.rejected_refs.append(envelope.ref)
            result.errors.append(
                f"{envelope.ref} must cite its own rag ref; supplied citations: {supplied}"
            )
            return
        if rag_citations:
            unresolved = _unresolved_refs(rag_citations, self.known_rag_refs)
            if unresolved:
                self._reject_unresolved(envelope, result, "rag", unresolved)
                return
            unsupported = _advisory_claim_unsupported_citations(envelope)
            if unsupported:
                result.rejected_refs.append(envelope.ref)
                result.errors.append(
                    f"{envelope.ref} has non-rag citation support in advisory claim: "
                    f"{', '.join(unsupported)}"
                )
                return
            return
        supplied = ", ".join(envelope.citations) if envelope.citations else "none"
        result.rejected_refs.append(envelope.ref)
        result.errors.append(
            f"{envelope.ref} requires rag:<chunk_id> citation support; "
            f"supplied citations cannot satisfy advisory requirements: {supplied}"
        )

    def _reject_unresolved(
        self,
        envelope: ContextEnvelope,
        result: CitationValidationResult,
        citation_type: str,
        unresolved: list[str],
    ) -> None:
        result.rejected_refs.append(envelope.ref)
        result.errors.append(
            f"{envelope.ref} has unresolved {citation_type} citation(s): {', '.join(unresolved)}"
        )


def _requires_evidence_citation(envelope: ContextEnvelope) -> bool:
    return (
        envelope.kind == "finding" and envelope.authority in REVIEWED_FINDING_AUTHORITIES
    ) or _has_target_fact_marker(envelope)


def _requires_rag_citation(envelope: ContextEnvelope) -> bool:
    return (
        envelope.kind == "rag"
        or envelope.ref.startswith(RAG_CITATION_PREFIX)
        or _has_advisory_claim_marker(envelope)
    )


def _citations_with_prefix(envelope: ContextEnvelope, prefix: str) -> list[str]:
    return [citation for citation in envelope.citations if citation.startswith(prefix)]


def _reviewed_finding_unsupported_citations(envelope: ContextEnvelope) -> list[str]:
    if envelope.kind != "finding" or envelope.authority not in REVIEWED_FINDING_AUTHORITIES:
        return []
    return _citations_with_prefixes(envelope, NON_EVIDENCE_PROOF_CITATION_PREFIXES)


def _target_fact_unsupported_citations(envelope: ContextEnvelope) -> list[str]:
    if not _has_target_fact_marker(envelope):
        return []
    unsupported = _citations_with_prefixes(envelope, TARGET_FACT_NON_EVIDENCE_CITATION_PREFIXES)
    if not _has_advisory_claim_marker(envelope):
        unsupported.extend(_citations_with_prefixes(envelope, TARGET_FACT_ADVISORY_CITATION_PREFIXES))
    return unsupported


def _advisory_claim_unsupported_citations(envelope: ContextEnvelope) -> list[str]:
    if not _has_advisory_claim_marker(envelope):
        return []
    return _citations_with_prefixes(envelope, ADVISORY_NON_RAG_CITATION_PREFIXES)


def _citations_with_prefixes(envelope: ContextEnvelope, prefixes: Iterable[str]) -> list[str]:
    normalized_prefixes = tuple(prefix.lower() for prefix in prefixes)
    return [
        citation
        for citation in (str(citation).strip() for citation in envelope.citations)
        if citation.lower().startswith(normalized_prefixes)
    ]


def _placeholder_rag_refs(envelope: ContextEnvelope, rag_citations: list[str]) -> list[str]:
    refs = [envelope.ref, *rag_citations]
    return [ref for ref in placeholder_source_refs(refs) if ref.startswith(RAG_CITATION_PREFIX)]


def _has_target_fact_marker(envelope: ContextEnvelope) -> bool:
    return has_context_flag(envelope, TARGET_FACT_METADATA_KEYS)


def _has_advisory_claim_marker(envelope: ContextEnvelope) -> bool:
    return has_context_flag(envelope, ADVISORY_CLAIM_METADATA_KEYS)


def _normalized_ref_set(refs: Iterable[str] | None) -> set[str] | None:
    if refs is None:
        return None
    return {_canonical_ref(ref) for ref in refs if _canonical_ref(ref)}


def _unresolved_refs(citations: list[str], known_refs: set[str] | None) -> list[str]:
    if known_refs is None:
        return []
    return sorted({_canonical_ref(citation) for citation in citations} - known_refs)


def _canonical_ref(value: object) -> str:
    ref = str(value or "").strip()
    for prefix in CANONICAL_CITATION_PREFIXES:
        if ref.lower().startswith(prefix):
            return f"{prefix}{ref[len(prefix):].strip()}"
    return ref
