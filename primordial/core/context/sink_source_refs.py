from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from primordial.core.context.current_refs import operator_note_source_omission_reason
from primordial.core.context.evidence_shape import evidence_shape_omission_reason
from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.generated_exports import (
    has_generated_export_path,
    is_generated_export_context,
    is_generated_export_path,
)
from primordial.core.context.metadata_flags import metadata_value_is_false, raw_metadata_value
from primordial.core.context.source_refs import (
    canonical_source_ref,
    source_refs_metadata_errors,
    source_refs_metadata_values,
    unresolved_ai_derived_source_ref_errors,
)
from primordial.core.context.writeup_policy import prompt_writeup_omission_reason


CitationPrefixCheck = Callable[[ContextEnvelope, Iterable[str]], list[str]]
NonEvidenceProofCheck = Callable[[ContextEnvelope, frozenset[str]], str]
NonAdvisoryRagCheck = Callable[[ContextEnvelope], str]


@dataclass(frozen=True, slots=True)
class _SourceRefState:
    evidence_refs: set[str] | None
    note_refs: set[str]
    rag_refs: set[str]


def context_known_source_refs(
    envelopes: Iterable[ContextEnvelope],
    *,
    known_evidence_refs: Iterable[str] | None,
    known_note_refs: Iterable[str] | None,
    known_rag_refs: Iterable[str] | None,
    evidence_kinds: frozenset[str],
    evidence_context_authorities: frozenset[str],
    disallowed_evidence_citation_prefixes: Iterable[str],
    citations_with_prefixes: CitationPrefixCheck,
    non_evidence_proof_source_type: NonEvidenceProofCheck,
    non_advisory_rag_source_type: NonAdvisoryRagCheck,
) -> tuple[set[str] | None, set[str], set[str]]:
    envelope_list = list(envelopes)
    state = _initial_source_ref_state(
        envelope_list,
        known_evidence_refs=known_evidence_refs,
        known_note_refs=known_note_refs,
        known_rag_refs=known_rag_refs,
    )
    while True:
        next_state = _pruned_source_ref_state(
            envelope_list,
            state,
            evidence_kinds=evidence_kinds,
            evidence_context_authorities=evidence_context_authorities,
            disallowed_evidence_citation_prefixes=disallowed_evidence_citation_prefixes,
            citations_with_prefixes=citations_with_prefixes,
            non_evidence_proof_source_type=non_evidence_proof_source_type,
            non_advisory_rag_source_type=non_advisory_rag_source_type,
        )
        if next_state == state:
            return state.evidence_refs, state.note_refs, state.rag_refs
        state = next_state


def _initial_source_ref_state(
    envelopes: Iterable[ContextEnvelope],
    *,
    known_evidence_refs: Iterable[str] | None,
    known_note_refs: Iterable[str] | None,
    known_rag_refs: Iterable[str] | None,
) -> _SourceRefState:
    envelope_list = list(envelopes)
    evidence_refs = _canonical_known_refs(known_evidence_refs) if known_evidence_refs is not None else None
    note_refs = _canonical_known_refs(known_note_refs)
    if known_note_refs is None:
        note_refs = {envelope.ref for envelope in envelope_list if _is_note_ref(envelope)}
    rag_refs = _canonical_known_refs(known_rag_refs)
    if known_rag_refs is None:
        rag_refs = {envelope.ref for envelope in envelope_list if _is_rag_ref(envelope)}
    return _SourceRefState(evidence_refs, note_refs, rag_refs)


def _canonical_known_refs(refs: Iterable[str] | None) -> set[str]:
    if refs is None:
        return set()
    return {canonical_ref for ref in refs if (canonical_ref := canonical_source_ref(ref))}


def _is_note_ref(envelope: ContextEnvelope) -> bool:
    return envelope.kind == "operator_note" and envelope.ref.startswith("note:")


def _is_rag_ref(envelope: ContextEnvelope) -> bool:
    return envelope.kind == "rag" and envelope.ref.startswith("rag:")


def _pruned_source_ref_state(
    envelopes: Iterable[ContextEnvelope],
    state: _SourceRefState,
    *,
    evidence_kinds: frozenset[str],
    evidence_context_authorities: frozenset[str],
    disallowed_evidence_citation_prefixes: Iterable[str],
    citations_with_prefixes: CitationPrefixCheck,
    non_evidence_proof_source_type: NonEvidenceProofCheck,
    non_advisory_rag_source_type: NonAdvisoryRagCheck,
) -> _SourceRefState:
    rejected_evidence_refs = _rejected_evidence_refs(
        envelopes,
        state,
        evidence_kinds=evidence_kinds,
        evidence_context_authorities=evidence_context_authorities,
        disallowed_evidence_citation_prefixes=disallowed_evidence_citation_prefixes,
        citations_with_prefixes=citations_with_prefixes,
        non_evidence_proof_source_type=non_evidence_proof_source_type,
    )
    evidence_refs = state.evidence_refs - rejected_evidence_refs if state.evidence_refs is not None else None
    rejected_note_refs = _rejected_note_refs(envelopes, state, evidence_refs=evidence_refs)
    note_refs = state.note_refs - rejected_note_refs
    rejected_rag_refs = _rejected_rag_refs(
        envelopes,
        state,
        evidence_refs=evidence_refs,
        note_refs=note_refs,
        non_advisory_rag_source_type=non_advisory_rag_source_type,
    )
    return _SourceRefState(evidence_refs, note_refs, state.rag_refs - rejected_rag_refs)


def _rejected_evidence_refs(
    envelopes: Iterable[ContextEnvelope],
    state: _SourceRefState,
    *,
    evidence_kinds: frozenset[str],
    evidence_context_authorities: frozenset[str],
    disallowed_evidence_citation_prefixes: Iterable[str],
    citations_with_prefixes: CitationPrefixCheck,
    non_evidence_proof_source_type: NonEvidenceProofCheck,
) -> set[str]:
    if state.evidence_refs is None:
        return set()
    return {
        envelope.ref
        for envelope in envelopes
        if envelope.kind in evidence_kinds
        and envelope.ref in state.evidence_refs
        and _reject_evidence_ref(
            envelope,
            state,
            evidence_kinds=evidence_kinds,
            evidence_context_authorities=evidence_context_authorities,
            disallowed_evidence_citation_prefixes=disallowed_evidence_citation_prefixes,
            citations_with_prefixes=citations_with_prefixes,
            non_evidence_proof_source_type=non_evidence_proof_source_type,
        )
    }


def _reject_evidence_ref(
    envelope: ContextEnvelope,
    state: _SourceRefState,
    *,
    evidence_kinds: frozenset[str],
    evidence_context_authorities: frozenset[str],
    disallowed_evidence_citation_prefixes: Iterable[str],
    citations_with_prefixes: CitationPrefixCheck,
    non_evidence_proof_source_type: NonEvidenceProofCheck,
) -> bool:
    return bool(
        _generated_export_ref(envelope)
        or non_evidence_proof_source_type(envelope, evidence_kinds)
        or evidence_shape_omission_reason(envelope, allowed_authorities=evidence_context_authorities)
        or citations_with_prefixes(envelope, disallowed_evidence_citation_prefixes)
        or source_refs_metadata_errors(envelope)
        or unresolved_ai_derived_source_ref_errors(
            envelope.ref,
            source_refs_metadata_values(envelope),
            known_evidence_refs=state.evidence_refs,
        )
    )


def _rejected_note_refs(
    envelopes: Iterable[ContextEnvelope],
    state: _SourceRefState,
    *,
    evidence_refs: set[str] | None,
) -> set[str]:
    return {
        envelope.ref
        for envelope in envelopes
        if envelope.kind == "operator_note"
        and envelope.ref in state.note_refs
        and _reject_note_ref(envelope, state, evidence_refs=evidence_refs)
    }


def _reject_note_ref(
    envelope: ContextEnvelope,
    state: _SourceRefState,
    *,
    evidence_refs: set[str] | None,
) -> bool:
    return bool(
        _generated_export_ref(envelope)
        or operator_note_source_omission_reason(envelope)
        or source_refs_metadata_errors(envelope)
        or unresolved_ai_derived_source_ref_errors(
            envelope.ref,
            source_refs_metadata_values(envelope),
            known_evidence_refs=evidence_refs,
            known_note_refs=state.note_refs,
            known_rag_refs=state.rag_refs,
        )
    )


def _rejected_rag_refs(
    envelopes: Iterable[ContextEnvelope],
    state: _SourceRefState,
    *,
    evidence_refs: set[str] | None,
    note_refs: set[str],
    non_advisory_rag_source_type: NonAdvisoryRagCheck,
) -> set[str]:
    return {
        envelope.ref
        for envelope in envelopes
        if envelope.kind == "rag"
        and envelope.ref in state.rag_refs
        and _reject_rag_ref(
            envelope,
            state,
            evidence_refs=evidence_refs,
            note_refs=note_refs,
            non_advisory_rag_source_type=non_advisory_rag_source_type,
        )
    }


def _reject_rag_ref(
    envelope: ContextEnvelope,
    state: _SourceRefState,
    *,
    evidence_refs: set[str] | None,
    note_refs: set[str],
    non_advisory_rag_source_type: NonAdvisoryRagCheck,
) -> bool:
    return bool(
        _generated_export_ref(envelope)
        or metadata_value_is_false(envelope, "operational_retrieval_allowed")
        or prompt_writeup_omission_reason(envelope, role="ctf_solver_orchestrator")
        or non_advisory_rag_source_type(envelope)
        or source_refs_metadata_errors(envelope)
        or unresolved_ai_derived_source_ref_errors(
            envelope.ref,
            source_refs_metadata_values(envelope),
            known_evidence_refs=evidence_refs,
            known_note_refs=note_refs,
            known_rag_refs=state.rag_refs,
        )
    )


def _generated_export_ref(envelope: ContextEnvelope) -> bool:
    return (
        is_generated_export_context(envelope)
        or has_generated_export_path(envelope)
        or is_generated_export_path(raw_metadata_value(envelope, "source_url"))
    )
