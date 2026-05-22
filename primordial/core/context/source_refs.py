from __future__ import annotations

from typing import Iterable

from primordial.core.context.normalization import normalized_context_key, normalized_context_keys


AI_DERIVED_SOURCE_REF_PREFIXES = ("evidence:", "note:", "rag:")
AI_DERIVED_SOURCE_REF_REQUIREMENT = "evidence:<id>, note:<id>, or rag:<chunk_id>"
EVIDENCE_REF_PREFIX = "evidence:"
RAG_REF_PREFIX = "rag:"


def has_ai_derived_source_ref(refs: Iterable[object]) -> bool:
    return any(_ref_text(ref).startswith(AI_DERIVED_SOURCE_REF_PREFIXES) for ref in refs)


def unsupported_ai_derived_source_refs(refs: Iterable[object]) -> list[str]:
    return sorted({ref for ref in (_ref_text(item) for item in refs) if ref and not _is_supported_ref(ref)})


def unresolved_ai_derived_source_ref_errors(
    owner_ref: str,
    refs: Iterable[object],
    *,
    known_evidence_refs: Iterable[str] | None = None,
    known_rag_refs: Iterable[str] | None = None,
) -> list[str]:
    evidence_refs = _unresolved_refs(refs, EVIDENCE_REF_PREFIX, known_evidence_refs)
    rag_refs = _unresolved_refs(refs, RAG_REF_PREFIX, known_rag_refs)
    errors: list[str] = []
    if evidence_refs:
        errors.append(f"{owner_ref} has unresolved evidence citation(s): {', '.join(evidence_refs)}")
    if rag_refs:
        errors.append(f"{owner_ref} has unresolved rag citation(s): {', '.join(rag_refs)}")
    return errors


def source_refs_metadata_values(envelope: object) -> list[object]:
    refs = _metadata_value(envelope, "source_refs")
    if isinstance(refs, str):
        return [refs]
    if isinstance(refs, list | tuple | set):
        return list(refs)
    return []


def has_malformed_source_refs_metadata(envelope: object) -> bool:
    refs = _metadata_value(envelope, "source_refs")
    return refs is not None and not isinstance(refs, str | list | tuple | set)


def uncited_source_refs_metadata(envelope: object) -> list[str]:
    citations = {_ref_text(ref) for ref in getattr(envelope, "citations", [])}
    return sorted(
        {
            ref
            for ref in (_ref_text(item) for item in source_refs_metadata_values(envelope))
            if ref and ref not in citations
        }
    )


def source_refs_metadata_errors(envelope: object) -> list[str]:
    if has_malformed_source_refs_metadata(envelope):
        return ["malformed source_refs"]
    unsupported_refs = unsupported_ai_derived_source_refs(source_refs_metadata_values(envelope))
    if unsupported_refs:
        return [f"unsupported source_refs: {', '.join(unsupported_refs)}"]
    uncited_refs = uncited_source_refs_metadata(envelope)
    if uncited_refs:
        return [f"uncited source_refs: {', '.join(uncited_refs)}"]
    return []


def _is_supported_ref(ref: str) -> bool:
    return ref.startswith(AI_DERIVED_SOURCE_REF_PREFIXES)


def _ref_text(value: object) -> str:
    return str(value).strip()


def _unresolved_refs(
    refs: Iterable[object],
    prefix: str,
    known_refs: Iterable[str] | None,
) -> list[str]:
    if known_refs is None:
        return []
    known = {_ref_text(ref) for ref in known_refs if _ref_text(ref)}
    supplied = {_ref_text(ref) for ref in refs if _ref_text(ref).startswith(prefix)}
    return sorted(supplied - known)


def _metadata_value(envelope: object, *names: str) -> object | None:
    normalized_names = normalized_context_keys(names)
    metadata = getattr(envelope, "metadata", {})
    for raw_key, value in metadata.items():
        if normalized_context_key(raw_key) in normalized_names:
            return value
    return None
