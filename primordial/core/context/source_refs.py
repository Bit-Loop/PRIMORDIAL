from __future__ import annotations

from typing import Iterable

from primordial.core.context.normalization import normalized_context_key, normalized_context_keys


AI_DERIVED_SOURCE_REF_PREFIXES = ("evidence:", "note:", "rag:")
AI_DERIVED_SOURCE_REF_REQUIREMENT = "evidence:<id>, note:<id>, or rag:<chunk_id>"
EVIDENCE_REF_PREFIX = "evidence:"
NOTE_REF_PREFIX = "note:"
RAG_REF_PREFIX = "rag:"
PLACEHOLDER_SOURCE_REFS = frozenset(
    {
        "evidence:none",
        "evidence:null",
        "evidence:unknown",
        "note:none",
        "note:null",
        "note:unknown",
        "rag:none",
        "rag:null",
        "rag:unknown",
    }
)
SOURCE_REFS_METADATA_KEYS = ("source_refs", "source_reference", "source_references")
SOURCE_REFS_LIST_TYPES = (frozenset, list, set, tuple)


def is_source_refs_metadata_key(raw_key: object) -> bool:
    return normalized_context_key(raw_key) in SOURCE_REFS_METADATA_KEYS or _is_display_source_ref_alias(raw_key)


def has_ai_derived_source_ref(refs: Iterable[object]) -> bool:
    return any(
        canonical
        for canonical in (_canonical_ref(ref) for ref in refs)
        if canonical.startswith(AI_DERIVED_SOURCE_REF_PREFIXES) and canonical.lower() not in PLACEHOLDER_SOURCE_REFS
    )


def unsupported_ai_derived_source_refs(refs: Iterable[object]) -> list[str]:
    return sorted({ref for ref in (_canonical_ref(item) for item in refs) if ref and not _is_supported_ref(ref)})


def placeholder_source_refs(refs: Iterable[object]) -> list[str]:
    return sorted({ref for ref in (_canonical_ref(item) for item in refs) if ref.lower() in PLACEHOLDER_SOURCE_REFS})


def unresolved_ai_derived_source_ref_errors(
    owner_ref: str,
    refs: Iterable[object],
    *,
    known_evidence_refs: Iterable[str] | None = None,
    known_note_refs: Iterable[str] | None = None,
    known_rag_refs: Iterable[str] | None = None,
) -> list[str]:
    evidence_refs = _unresolved_refs(refs, EVIDENCE_REF_PREFIX, known_evidence_refs)
    note_refs = _unresolved_refs(refs, NOTE_REF_PREFIX, known_note_refs)
    rag_refs = _unresolved_refs(refs, RAG_REF_PREFIX, known_rag_refs)
    errors: list[str] = []
    if evidence_refs:
        errors.append(f"{owner_ref} has unresolved evidence citation(s): {', '.join(evidence_refs)}")
    if note_refs:
        errors.append(f"{owner_ref} has unresolved note citation(s): {', '.join(note_refs)}")
    if rag_refs:
        errors.append(f"{owner_ref} has unresolved rag citation(s): {', '.join(rag_refs)}")
    return errors


def source_refs_metadata_values(envelope: object) -> list[object]:
    values: list[object] = []
    for refs in _metadata_values(envelope, *SOURCE_REFS_METADATA_KEYS):
        if isinstance(refs, str):
            values.append(_canonical_ref(refs))
        elif isinstance(refs, SOURCE_REFS_LIST_TYPES):
            values.extend(_canonical_ref(ref) if isinstance(ref, str) else ref for ref in refs)
    return _deduplicated_metadata_values(values)


def _source_refs_metadata_raw_values(envelope: object) -> list[object]:
    return _metadata_values(envelope, *SOURCE_REFS_METADATA_KEYS)


def has_malformed_source_refs_metadata(envelope: object) -> bool:
    refs_values = _source_refs_metadata_raw_values(envelope)
    if not refs_values:
        return False
    for refs in refs_values:
        if isinstance(refs, str):
            if not refs.strip() or _has_empty_ai_ref_suffix(refs):
                return True
            continue
        if isinstance(refs, SOURCE_REFS_LIST_TYPES):
            if any(not isinstance(ref, str) or not ref.strip() or _has_empty_ai_ref_suffix(ref) for ref in refs):
                return True
            continue
        return True
    return False


def uncited_source_refs_metadata(envelope: object) -> list[str]:
    citations = {_canonical_ref(ref) for ref in getattr(envelope, "citations", [])}
    return sorted(
        {
            ref
            for ref in (_canonical_ref(item) for item in source_refs_metadata_values(envelope))
            if ref and ref not in citations
        }
    )


def source_refs_metadata_errors(envelope: object) -> list[str]:
    if has_malformed_source_refs_metadata(envelope):
        return ["malformed source_refs"]
    unsupported_refs = unsupported_ai_derived_source_refs(source_refs_metadata_values(envelope))
    if unsupported_refs:
        return [f"unsupported source_refs: {', '.join(unsupported_refs)}"]
    placeholder_refs = placeholder_source_refs(source_refs_metadata_values(envelope))
    if placeholder_refs:
        return [f"placeholder source_refs: {', '.join(placeholder_refs)}"]
    uncited_refs = uncited_source_refs_metadata(envelope)
    if uncited_refs:
        return [f"uncited source_refs: {', '.join(uncited_refs)}"]
    return []


def _is_supported_ref(ref: str) -> bool:
    return ref.startswith(AI_DERIVED_SOURCE_REF_PREFIXES)


def _has_empty_ai_ref_suffix(ref: object) -> bool:
    canonical = _canonical_ref(ref)
    return any(canonical == prefix for prefix in AI_DERIVED_SOURCE_REF_PREFIXES)


def _deduplicated_metadata_values(values: list[object]) -> list[object]:
    deduplicated: list[object] = []
    for value in values:
        if value not in deduplicated:
            deduplicated.append(value)
    return deduplicated


def _ref_text(value: object) -> str:
    return str(value).strip()


def canonical_source_ref(value: object) -> str:
    ref = _ref_text(value)
    for prefix in AI_DERIVED_SOURCE_REF_PREFIXES:
        if ref.lower().startswith(prefix):
            return f"{prefix}{ref[len(prefix):].strip()}"
    return ref


def _canonical_ref(value: object) -> str:
    return canonical_source_ref(value)


def _unresolved_refs(
    refs: Iterable[object],
    prefix: str,
    known_refs: Iterable[str] | None,
) -> list[str]:
    if known_refs is None:
        return []
    known = {_canonical_ref(ref) for ref in known_refs if _canonical_ref(ref)}
    supplied = {_canonical_ref(ref) for ref in refs if _canonical_ref(ref).startswith(prefix)}
    return sorted(supplied - known)


def _metadata_value(envelope: object, *names: str) -> object | None:
    values = _metadata_values(envelope, *names)
    return values[0] if values else None


def _metadata_values(envelope: object, *names: str) -> list[object]:
    normalized_names = normalized_context_keys(names)
    metadata = getattr(envelope, "metadata", {})
    values: list[object] = []
    _collect_metadata_values(
        metadata,
        normalized_names,
        values,
        include_display_source_ref_alias=normalized_names == normalized_context_keys(SOURCE_REFS_METADATA_KEYS),
    )
    return values


def _collect_metadata_values(
    value: object,
    normalized_names: set[str],
    values: list[object],
    *,
    include_display_source_ref_alias: bool = False,
) -> None:
    if isinstance(value, dict):
        for raw_key, item in value.items():
            if normalized_context_key(raw_key) in normalized_names or (
                include_display_source_ref_alias and is_source_refs_metadata_key(raw_key)
            ):
                values.append(item)
            if isinstance(item, dict):
                _collect_metadata_values(
                    item,
                    normalized_names,
                    values,
                    include_display_source_ref_alias=include_display_source_ref_alias,
                )
            elif isinstance(item, SOURCE_REFS_LIST_TYPES):
                for child in item:
                    _collect_metadata_values(
                        child,
                        normalized_names,
                        values,
                        include_display_source_ref_alias=include_display_source_ref_alias,
                    )
        return
    if isinstance(value, SOURCE_REFS_LIST_TYPES):
        for item in value:
            _collect_metadata_values(
                item,
                normalized_names,
                values,
                include_display_source_ref_alias=include_display_source_ref_alias,
            )


def _is_display_source_ref_alias(raw_key: object) -> bool:
    return str(raw_key).strip().lower() in {
        "source ref",
        "source-ref",
        "sourceref",
        "sourcereference",
        "sourcereferences",
        "sourcerefs",
    }
