from __future__ import annotations

from typing import Any

from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.normalization import normalized_context_key
from primordial.core.context.sinks import ContextSinkValidator


GENERATED_EXPORT_KINDS = frozenset({"generated_export", "export_archive"})
GENERATED_EXPORT_SOURCE_TYPES = frozenset({"generated_export", "export_archive"})
RAG_INDEX_ALLOWED_AUTHORITIES = frozenset({"advisory", "historical", "unverified"})
FALSE_VALUES = frozenset({"0", "false", "no", "off"})
TRUTHY_VALUES = frozenset({"1", "on", "true", "yes"})
CLOSED_BOOK_MODES = frozenset({"closed_book", "closed_book_mode"})
WRITEUP_FORBIDDEN_POLICIES = frozenset(
    {"forbid", "forbidden", "deny", "denied", "exclude", "excluded", "closed_book_excluded"}
)
FALSE_DENY_KEYS = frozenset({"ingest_allowed", "operational_retrieval_allowed", "writeups_allowed"})
SAFETY_FLAG_METADATA_KEYS = (
    "hidden_solution_material",
    "contains_hidden_solution",
    "contains_solution",
    "contains_raw_expected_flag",
    "contains_sensitive_raw_target_evidence",
    "contains_raw_flag",
    "contains_secret",
    "contains_credential",
)
SAFETY_METADATA_KEYS = (
    "origin",
    "ingest_allowed",
    "operational_retrieval_allowed",
    "benchmark_mode",
    "mode",
    "writeup_access_policy",
    "writeups_allowed",
)


class RagImportRecordValidator:
    def __init__(self, sink_validator: ContextSinkValidator | None = None) -> None:
        self._sink_validator = sink_validator or ContextSinkValidator()

    def validate_rag_index_record(
        self,
        record: dict[str, Any],
        *,
        domain: str,
        metadata: dict[str, Any],
    ) -> None:
        validation_metadata = _validation_metadata(record, metadata)
        chunk_id = str(record.get("chunk_id") or record.get("record_id") or record.get("doc_id") or "unknown").strip()
        source_type = _source_type(record, validation_metadata)
        kind = _kind(record, validation_metadata)
        if not kind:
            kind = source_type if source_type in GENERATED_EXPORT_KINDS else "rag"
        authority = _authority(record, validation_metadata)
        if not authority:
            authority = "derived" if kind in GENERATED_EXPORT_KINDS else "advisory"
        citation = _citation_id(record, validation_metadata, fallback_chunk_id=chunk_id)
        envelope = ContextEnvelope(
            ref=citation,
            kind=kind,
            authority=authority,
            source_type=source_type or str(metadata.get("corpus_type") or "methodology_doc"),
            purpose="rag_import",
            sink="rag_index",
            content=str(record.get("retrieval_text") or record.get("text") or record.get("raw_text") or ""),
            corpus=str(metadata.get("corpus_type") or domain),
            domain=domain,
            citations=[citation] if citation else [],
            poison_flags=_merged_list_field(record, validation_metadata, "poison_flags"),
            valid_for=_restrictive_valid_for_field(record, validation_metadata),
            invalid_for=_merged_list_field(record, validation_metadata, "invalid_for"),
            metadata=validation_metadata,
        )
        validation = self._sink_validator.validate("rag_index", [envelope])
        if not validation.valid:
            raise ValueError("; ".join(validation.errors))


def _validation_metadata(record: dict[str, Any], metadata: dict[str, Any]) -> dict[str, Any]:
    nested = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
    merged = {**nested, **metadata}
    for key in SAFETY_METADATA_KEYS:
        value = _restrictive_safety_value(key, metadata, nested, record)
        if value is not None:
            merged[key] = value
    source_type = _generated_export_classification_value("source_type", metadata, nested, record)
    if source_type is not None:
        merged["source_type"] = source_type
    kind = _generated_export_classification_value("kind", metadata, nested, record)
    if kind is not None:
        merged["kind"] = kind
    authority = _disallowed_authority_value(metadata, nested, record)
    if authority is not None:
        merged["authority"] = authority
    poison_flags = _merged_safety_list_value("poison_flags", metadata, nested, record)
    if poison_flags:
        merged["poison_flags"] = poison_flags
    invalid_for = _merged_safety_list_value("invalid_for", metadata, nested, record)
    if invalid_for:
        merged["invalid_for"] = invalid_for
    valid_for = _restrictive_valid_for_value(metadata, nested, record)
    if valid_for:
        merged["valid_for"] = valid_for
    for key in SAFETY_FLAG_METADATA_KEYS:
        value = _truthy_safety_flag_value(key, metadata, nested, record)
        if value is not None:
            merged[key] = value
    return merged


def _generated_export_classification_value(key: str, *sources: dict[str, Any]) -> Any:
    allowed = GENERATED_EXPORT_SOURCE_TYPES if key == "source_type" else GENERATED_EXPORT_KINDS
    for source in sources:
        if key in source and normalized_context_key(source[key]) in allowed:
            return source[key]
    return None


def _source_type(record: dict[str, Any], metadata: dict[str, Any]) -> str:
    values = [metadata.get("source_type"), record.get("source_type")]
    for value in values:
        source_type = normalized_context_key(value)
        if source_type in GENERATED_EXPORT_SOURCE_TYPES:
            return source_type
    return normalized_context_key(record.get("source_type") or metadata.get("source_type") or "")


def _kind(record: dict[str, Any], metadata: dict[str, Any]) -> str:
    values = [metadata.get("kind"), record.get("kind")]
    for value in values:
        kind = normalized_context_key(value)
        if kind in GENERATED_EXPORT_KINDS:
            return kind
    return normalized_context_key(record.get("kind") or metadata.get("kind") or "")


def _authority(record: dict[str, Any], metadata: dict[str, Any]) -> str:
    values = [metadata.get("authority"), record.get("authority")]
    for value in values:
        authority = normalized_context_key(value)
        if authority and authority not in RAG_INDEX_ALLOWED_AUTHORITIES:
            return authority
    return normalized_context_key(record.get("authority") or metadata.get("authority") or "")


def _disallowed_authority_value(*sources: dict[str, Any]) -> Any:
    for source in sources:
        if "authority" not in source:
            continue
        authority = normalized_context_key(source["authority"])
        if authority and authority not in RAG_INDEX_ALLOWED_AUTHORITIES:
            return source["authority"]
    return None


def _merged_safety_list_value(name: str, *sources: dict[str, Any]) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for source in sources:
        for item in _list_field(source, {}, name):
            if item not in seen:
                values.append(item)
                seen.add(item)
    return values


def _restrictive_safety_value(key: str, *sources: dict[str, Any]) -> Any:
    values = [source[key] for source in sources if key in source]
    if not values:
        return None
    if key == "origin":
        for value in values:
            if normalized_context_key(value) in GENERATED_EXPORT_SOURCE_TYPES:
                return value
    if key in FALSE_DENY_KEYS and any(_metadata_value_is_false(value) for value in values):
        return False
    if key in {"benchmark_mode", "mode"}:
        for value in values:
            if normalized_context_key(value) in CLOSED_BOOK_MODES:
                return value
    if key == "writeup_access_policy":
        for value in values:
            if normalized_context_key(value) in WRITEUP_FORBIDDEN_POLICIES:
                return value
    return values[-1]


def _metadata_value_is_false(value: Any) -> bool:
    return value is False or normalized_context_key(value) in FALSE_VALUES


def _metadata_value_is_true(value: Any) -> bool:
    return value is True or normalized_context_key(value) in TRUTHY_VALUES


def _truthy_safety_flag_value(key: str, *sources: dict[str, Any]) -> bool | None:
    for source in sources:
        for raw_key, value in source.items():
            if normalized_context_key(raw_key) == key and _metadata_value_is_true(value):
                return True
    return None


def _list_field(record: dict[str, Any], metadata: dict[str, Any], name: str) -> list[str]:
    value = record.get(name)
    if value is None:
        value = metadata.get(name)
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    elif isinstance(value, (frozenset, set, tuple)):
        value = list(value)
    elif not isinstance(value, list):
        raise ValueError(f"{name} must be a string or list-like value")
    return [str(item).strip() for item in value if str(item).strip()]


def _merged_list_field(record: dict[str, Any], metadata: dict[str, Any], name: str) -> list[str]:
    return _merged_safety_list_value(name, metadata, record)


def _restrictive_valid_for_field(record: dict[str, Any], metadata: dict[str, Any]) -> list[str]:
    return _restrictive_valid_for_value(metadata, record) or []


def _restrictive_valid_for_value(*sources: dict[str, Any]) -> list[str] | None:
    explicit: list[list[str]] = []
    for source in sources:
        if "valid_for" not in source:
            continue
        values = _list_field(source, {}, "valid_for")
        if values:
            explicit.append(values)
    if not explicit:
        return None
    allowed = set(explicit[0])
    for values in explicit[1:]:
        allowed &= set(values)
    if not allowed:
        raise ValueError("conflicting valid_for restrictions")
    return [item for item in explicit[0] if item in allowed]


def _citation_id(record: dict[str, Any], metadata: dict[str, Any], *, fallback_chunk_id: str) -> str:
    explicit = str(record.get("citation_id") or metadata.get("citation_id") or "").strip()
    if explicit and explicit != "rag:None":
        return explicit if explicit.startswith("rag:") else f"rag:{explicit}"
    fallback = str(fallback_chunk_id or "unknown").strip()
    return fallback if fallback.startswith("rag:") else f"rag:{fallback}"
