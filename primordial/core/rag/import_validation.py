from __future__ import annotations

from typing import Any

from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.generated_exports import GENERATED_EXPORT_PATH_KEYS, is_generated_export_path
from primordial.core.context.normalization import normalized_context_key
from primordial.core.context.sinks import ContextSinkValidator
from primordial.core.context.source_refs import SOURCE_REFS_METADATA_KEYS, is_source_refs_metadata_key
from primordial.core.context.source_types import RAG_ADVISORY_SOURCE_TYPES


GENERATED_EXPORT_KINDS = frozenset({"generated_export", "export_archive"})
GENERATED_EXPORT_SOURCE_TYPES = frozenset({"generated_export", "export_archive"})
RAG_INDEX_ALLOWED_AUTHORITIES = frozenset({"advisory", "historical", "unverified"})
FALSE_VALUES = frozenset({"0", "false", "no", "off"})
TRUTHY_VALUES = frozenset({"1", "on", "true", "yes"})
CLOSED_BOOK_MODES = frozenset({"closed_book", "closed_book_mode"})
WRITEUP_FORBIDDEN_POLICIES = frozenset(
    {
        "closed_book",
        "closed-book",
        "closed_book_excluded",
        "deny",
        "denied",
        "exclude",
        "excluded",
        "forbid",
        "forbidden",
        "postmortem_only",
        "postmortem-only",
    }
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
    "origins",
    "ingest_allowed",
    "operational_retrieval_allowed",
    "benchmark_mode",
    "mode",
    "purpose",
    "corpus_type",
    "writeup_access_policy",
    "writeups_allowed",
)
SOURCE_PATH_METADATA_KEYS = GENERATED_EXPORT_PATH_KEYS
PREPROCESSOR_FORMAT_SOURCE_TYPES = frozenset(
    {
        "csv",
        "docling",
        "html",
        "json",
        "markdown",
        "md",
        "pdf",
        "text",
        "txt",
    }
)
VULN_INTEL_RECORD_SOURCE_TYPES = frozenset({"vulnerability_intel_card", "vuln_intel_card"})
VULN_INTEL_DOMAINS = frozenset({"cve", "cve_advisory", "kev", "nvd", "vuln", "vuln_intel"})
WRITEUP_CORPORA = frozenset({"ctf_writeup", "htb_writeup", "walkthrough", "writeup"})


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
        chunk_id = str(
            _metadata_value(record, "chunk_id")
            or _metadata_value(record, "record_id")
            or _metadata_value(record, "doc_id")
            or _metadata_value(record, "source_id")
            or _nested_record_id_value(record)
            or _nested_record_id_value(validation_metadata)
            or "unknown"
        ).strip()
        source_type = _source_type(record, validation_metadata, domain=domain)
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
            source_type=source_type or str(_metadata_value(metadata, "corpus_type") or "methodology_doc"),
            purpose="rag_import",
            sink="rag_index",
            content=str(
                _metadata_value(record, "retrieval_text")
                or _metadata_value(record, "text")
                or _metadata_value(record, "raw_text")
                or _metadata_value(record, "excerpt")
                or _metadata_value(validation_metadata, "retrieval_text")
                or _metadata_value(validation_metadata, "text")
                or _metadata_value(validation_metadata, "raw_text")
                or _metadata_value(validation_metadata, "excerpt")
                or _nested_content_value(record)
                or _nested_content_value(validation_metadata)
                or ""
            ),
            corpus=str(_metadata_value(validation_metadata, "corpus_type") or domain),
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
    if _has_generated_export_source_path(metadata, nested, record):
        merged["origin"] = "generated_export"
    source_type = _generated_export_classification_value("source_type", metadata, nested, record)
    if source_type is not None:
        merged["source_type"] = source_type
    kind = _generated_export_classification_value("kind", metadata, nested, record)
    if kind is not None:
        merged["kind"] = kind
    authority = _restrictive_authority_value(metadata, nested, record)
    if authority is not None:
        merged["authority"] = authority
    poison_flags = _merged_safety_list_value("poison_flags", metadata, nested, record)
    if poison_flags:
        merged["poison_flags"] = poison_flags
    invalid_for = _merged_safety_list_value("invalid_for", metadata, nested, record)
    if invalid_for:
        merged["invalid_for"] = invalid_for
    source_refs = _merged_source_refs_value(metadata, nested, record)
    if source_refs is not None:
        merged["source_refs"] = source_refs
    valid_for = _restrictive_valid_for_value(metadata, nested, record)
    if valid_for:
        merged["valid_for"] = valid_for
    for key in SAFETY_FLAG_METADATA_KEYS:
        value = _truthy_safety_flag_value(key, metadata, nested, record)
        if value is not None:
            merged[key] = value
    return merged


def _nested_content_value(value: Any) -> Any:
    values: list[Any] = []
    _collect_nested_content_values(value, values)
    return values[0] if values else None


def _collect_nested_content_values(value: Any, values: list[Any]) -> None:
    content_names = {"retrieval_text", "text", "raw_text", "excerpt"}
    if isinstance(value, dict):
        for raw_key, item in value.items():
            if normalized_context_key(raw_key) in content_names:
                values.append(item)
            if isinstance(item, (dict, list, tuple, set)):
                _collect_nested_content_values(item, values)
        return
    if isinstance(value, (list, tuple, set)):
        for item in value:
            _collect_nested_content_values(item, values)


def _nested_record_id_value(value: Any) -> Any:
    values: list[Any] = []
    _collect_nested_record_id_values(value, values)
    return values[0] if values else None


def _collect_nested_record_id_values(value: Any, values: list[Any]) -> None:
    id_names = {"chunk_id", "record_id", "doc_id", "source_id"}
    if isinstance(value, dict):
        for raw_key, item in value.items():
            if normalized_context_key(raw_key) in id_names:
                values.append(item)
            if isinstance(item, (dict, list, tuple, set)):
                _collect_nested_record_id_values(item, values)
        return
    if isinstance(value, (list, tuple, set)):
        for item in value:
            _collect_nested_record_id_values(item, values)


def _generated_export_classification_value(key: str, *sources: dict[str, Any]) -> Any:
    allowed = GENERATED_EXPORT_SOURCE_TYPES if key == "source_type" else GENERATED_EXPORT_KINDS
    aliases = ("source_type", "source_types") if key == "source_type" else ("kind", "kinds")
    for source in sources:
        value = _classification_marker_value(source, aliases, allowed)
        if value is not None:
            return value
    return None


def _classification_marker_value(value: Any, aliases: tuple[str, ...], allowed: frozenset[str]) -> Any:
    if isinstance(value, dict):
        normalized_aliases = {normalized_context_key(alias) for alias in aliases}
        for raw_key, item in value.items():
            if normalized_context_key(raw_key) in normalized_aliases and _contains_marker(item, allowed):
                return item
            if isinstance(item, (dict, list, tuple, set)):
                marker = _classification_marker_value(item, aliases, allowed)
                if marker is not None:
                    return marker
    if isinstance(value, (list, tuple, set)):
        for item in value:
            marker = _classification_marker_value(item, aliases, allowed)
            if marker is not None:
                return marker
    return None


def _has_generated_export_source_path(*sources: dict[str, Any]) -> bool:
    return any(_contains_generated_export_source_path(source) for source in sources)


def _contains_generated_export_source_path(value: Any) -> bool:
    return is_generated_export_path(value)


def _source_type(record: dict[str, Any], metadata: dict[str, Any], *, domain: str) -> str:
    values = [
        _metadata_value(metadata, "source_type", "source_types"),
        _metadata_value(record, "source_type", "source_types"),
    ]
    for value in values:
        source_type = _source_type_value(value)
        if source_type in GENERATED_EXPORT_SOURCE_TYPES:
            return source_type
    source_type = _source_type_value(
        _metadata_value(record, "source_type", "source_types")
        or _metadata_value(metadata, "source_type", "source_types")
        or _nested_source_type_value(record)
        or _nested_source_type_value(metadata)
    )
    if source_type in RAG_ADVISORY_SOURCE_TYPES:
        return source_type
    if source_type in VULN_INTEL_RECORD_SOURCE_TYPES:
        return "vuln_intel"
    if source_type in PREPROCESSOR_FORMAT_SOURCE_TYPES or not source_type:
        return _advisory_source_type_for_record(record, metadata, domain=domain)
    return source_type


def _source_type_value(value: Any) -> str:
    if isinstance(value, (frozenset, list, set, tuple)):
        source_types = _normalized_context_values(value)
        for restricted_types in (GENERATED_EXPORT_SOURCE_TYPES, WRITEUP_CORPORA):
            for source_type in source_types:
                if source_type in restricted_types:
                    return "writeup" if source_type in WRITEUP_CORPORA else source_type
        return source_types[0] if source_types else ""
    return normalized_context_key(value)


def _normalized_context_values(value: Any) -> list[str]:
    if isinstance(value, dict):
        return []
    if isinstance(value, (frozenset, list, set, tuple)):
        values: list[str] = []
        for item in value:
            values.extend(_normalized_context_values(item))
        return values
    normalized = normalized_context_key(value)
    return [normalized] if normalized else []


def _nested_source_type_value(value: Any) -> Any:
    values: list[Any] = []
    _collect_nested_source_type_values(value, values)
    return values[0] if values else None


def _collect_nested_source_type_values(value: Any, values: list[Any]) -> None:
    if isinstance(value, dict):
        for raw_key, item in value.items():
            if normalized_context_key(raw_key) in {"source_type", "source_types"}:
                values.append(item)
            if isinstance(item, (dict, list, tuple, set)):
                _collect_nested_source_type_values(item, values)
        return
    if isinstance(value, (list, tuple, set)):
        for item in value:
            _collect_nested_source_type_values(item, values)


def _advisory_source_type_for_record(record: dict[str, Any], metadata: dict[str, Any], *, domain: str) -> str:
    candidates: list[str] = []
    for value in (
        _metadata_value(metadata, "corpus_type"),
        _metadata_value(record, "corpus_type"),
        _metadata_value(record, "domain"),
        _nested_domain_value(record),
        _nested_domain_value(metadata),
        domain,
    ):
        candidates.extend(_normalized_context_values(value))
    if any(candidate in VULN_INTEL_DOMAINS for candidate in candidates):
        return "vuln_intel"
    if any(candidate in WRITEUP_CORPORA for candidate in candidates):
        return "writeup"
    return "methodology_doc"


def _nested_domain_value(value: Any) -> Any:
    values: list[Any] = []
    _collect_nested_domain_values(value, values)
    return values[0] if values else None


def _collect_nested_domain_values(value: Any, values: list[Any]) -> None:
    if isinstance(value, dict):
        for raw_key, item in value.items():
            if normalized_context_key(raw_key) == "domain":
                values.append(item)
            if isinstance(item, (dict, list, tuple, set)):
                _collect_nested_domain_values(item, values)
        return
    if isinstance(value, (list, tuple, set)):
        for item in value:
            _collect_nested_domain_values(item, values)


def _kind(record: dict[str, Any], metadata: dict[str, Any]) -> str:
    values = [_metadata_value(metadata, "kind"), _metadata_value(record, "kind")]
    for value in values:
        kind = normalized_context_key(value)
        if kind in GENERATED_EXPORT_KINDS:
            return kind
    return normalized_context_key(_metadata_value(record, "kind") or _metadata_value(metadata, "kind") or "")


def _authority(record: dict[str, Any], metadata: dict[str, Any]) -> str:
    values = [_metadata_value(metadata, "authority"), _metadata_value(record, "authority")]
    for value in values:
        authority = normalized_context_key(value)
        if authority and authority not in RAG_INDEX_ALLOWED_AUTHORITIES:
            return authority
    return normalized_context_key(_metadata_value(record, "authority") or _metadata_value(metadata, "authority") or "")


def _restrictive_authority_value(*sources: dict[str, Any]) -> Any:
    allowed_value = None
    for source in sources:
        for value in _authority_metadata_values(source):
            authority = normalized_context_key(value)
            if authority and authority not in RAG_INDEX_ALLOWED_AUTHORITIES:
                return value
            if authority:
                allowed_value = value
    return allowed_value


def _authority_metadata_values(value: Any) -> list[Any]:
    values: list[Any] = []
    _collect_authority_metadata_values(value, values)
    return values


def _collect_authority_metadata_values(value: Any, values: list[Any]) -> None:
    if isinstance(value, dict):
        for raw_key, item in value.items():
            if normalized_context_key(raw_key) == "authority":
                values.append(item)
            if isinstance(item, (dict, list, tuple, set)):
                _collect_authority_metadata_values(item, values)
        return
    if isinstance(value, (list, tuple, set)):
        for item in value:
            _collect_authority_metadata_values(item, values)


def _merged_safety_list_value(name: str, *sources: dict[str, Any]) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for source in sources:
        for value in _list_metadata_values(source, name):
            for item in _list_items(value, name):
                if item not in seen:
                    values.append(item)
                    seen.add(item)
    return values


def _list_metadata_values(value: Any, name: str) -> list[Any]:
    values: list[Any] = []
    _collect_list_metadata_values(value, name, values)
    return values


def _collect_list_metadata_values(value: Any, name: str, values: list[Any]) -> None:
    if isinstance(value, dict):
        for raw_key, item in value.items():
            if normalized_context_key(raw_key) == name:
                values.append(item)
            if isinstance(item, (dict, list, tuple, set)):
                _collect_list_metadata_values(item, name, values)
        return
    if isinstance(value, (list, tuple, set)):
        for item in value:
            _collect_list_metadata_values(item, name, values)


def _list_items(value: Any, name: str) -> list[str]:
    if isinstance(value, str):
        value = [value]
    elif isinstance(value, (frozenset, set, tuple)):
        value = list(value)
    elif not isinstance(value, list):
        raise ValueError(f"{name} must be a string or list-like value")
    return [str(item).strip() for item in value if str(item).strip()]


def _merged_source_refs_value(*sources: dict[str, Any]) -> Any:
    values: list[str] = []
    seen: set[str] = set()
    for source in sources:
        for value in _source_ref_metadata_values(source):
            if isinstance(value, str):
                refs = [value]
            elif isinstance(value, (frozenset, list, set, tuple)):
                if any(not isinstance(ref, str) or not ref.strip() for ref in value):
                    return value
                refs = list(value)
            else:
                return value
            for ref in refs:
                clean = ref.strip()
                if clean and clean not in seen:
                    values.append(clean)
                    seen.add(clean)
    return values or None


def _source_ref_metadata_values(value: Any) -> list[Any]:
    values: list[Any] = []
    _collect_source_ref_metadata_values(value, values)
    return values


def _collect_source_ref_metadata_values(value: Any, values: list[Any]) -> None:
    if isinstance(value, dict):
        normalized_names = {normalized_context_key(name) for name in SOURCE_REFS_METADATA_KEYS}
        for raw_key, item in value.items():
            if normalized_context_key(raw_key) in normalized_names or is_source_refs_metadata_key(raw_key):
                values.append(item)
            if isinstance(item, (dict, list, tuple, set)):
                _collect_source_ref_metadata_values(item, values)
        return
    if isinstance(value, (list, tuple, set)):
        for item in value:
            _collect_source_ref_metadata_values(item, values)


def _restrictive_safety_value(key: str, *sources: dict[str, Any]) -> Any:
    values = []
    for source in sources:
        values.extend(_safety_metadata_values(source, key))
    if not values:
        return None
    if key in {"origin", "origins"}:
        for value in values:
            if _contains_generated_export_marker(value):
                return value
    if key in FALSE_DENY_KEYS and any(_metadata_value_is_false(value) for value in values):
        return False
    if key in {"benchmark_mode", "mode"}:
        for value in values:
            for candidate in _normalized_context_values(value):
                if candidate in CLOSED_BOOK_MODES:
                    return candidate
    if key == "writeup_access_policy":
        for value in values:
            for candidate in _normalized_context_values(value):
                if candidate in WRITEUP_FORBIDDEN_POLICIES:
                    return candidate
    return values[-1]


def _safety_metadata_values(value: Any, key: str) -> list[Any]:
    values: list[Any] = []
    aliases = {"origin", "origins"} if key in {"origin", "origins"} else {key}
    _collect_safety_metadata_values(value, aliases, values)
    return values


def _collect_safety_metadata_values(value: Any, aliases: set[str], values: list[Any]) -> None:
    if isinstance(value, dict):
        for raw_key, item in value.items():
            if normalized_context_key(raw_key) in aliases:
                values.append(item)
            if isinstance(item, (dict, list, tuple, set)):
                _collect_safety_metadata_values(item, aliases, values)
        return
    if isinstance(value, (list, tuple, set)):
        for item in value:
            _collect_safety_metadata_values(item, aliases, values)


def _metadata_value_is_false(value: Any) -> bool:
    if isinstance(value, (frozenset, list, set, tuple)):
        return any(_metadata_value_is_false(item) for item in value)
    return value is False or normalized_context_key(value) in FALSE_VALUES


def _metadata_value_is_true(value: Any) -> bool:
    if isinstance(value, (frozenset, list, set, tuple)):
        return any(_metadata_value_is_true(item) for item in value)
    return value is True or normalized_context_key(value) in TRUTHY_VALUES


def _contains_generated_export_marker(value: Any) -> bool:
    return _contains_marker(value, GENERATED_EXPORT_SOURCE_TYPES)


def _contains_marker(value: Any, allowed: frozenset[str]) -> bool:
    if isinstance(value, (frozenset, list, set, tuple)):
        return any(_contains_marker(item, allowed) for item in value)
    return normalized_context_key(value) in allowed


def _metadata_value(source: dict[str, Any], *names: str) -> Any:
    values = _metadata_values(source, *names)
    return values[0] if values else None


def _metadata_values(source: dict[str, Any], *names: str) -> list[Any]:
    normalized_names = {normalized_context_key(name) for name in names}
    values: list[Any] = []
    for raw_key, value in source.items():
        if normalized_context_key(raw_key) in normalized_names:
            values.append(value)
    return values


def _truthy_safety_flag_value(key: str, *sources: dict[str, Any]) -> bool | None:
    for source in sources:
        if _contains_truthy_safety_flag(source, key):
            return True
    return None


def _contains_truthy_safety_flag(value: Any, key: str) -> bool:
    if isinstance(value, dict):
        for raw_key, item in value.items():
            if normalized_context_key(raw_key) == key and _metadata_value_is_true(item):
                return True
            if isinstance(item, (dict, list, tuple, set)) and _contains_truthy_safety_flag(item, key):
                return True
    if isinstance(value, (list, tuple, set)):
        return any(_contains_truthy_safety_flag(item, key) for item in value)
    return False


def _list_field(record: dict[str, Any], metadata: dict[str, Any], name: str) -> list[str]:
    value = _metadata_value(record, name)
    if value is None:
        value = _metadata_value(metadata, name)
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
        for value in _list_metadata_values(source, "valid_for"):
            values = _list_items(value, "valid_for")
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
    explicit = str(
        _metadata_value(record, "citation_id")
        or _metadata_value(metadata, "citation_id")
        or _nested_citation_id_value(record)
        or _nested_citation_id_value(metadata)
        or ""
    ).strip()
    if explicit and explicit.lower() != "rag:none":
        return _normalized_rag_citation_id(explicit)
    fallback = str(fallback_chunk_id or "unknown").strip()
    return _normalized_rag_citation_id(fallback)


def _nested_citation_id_value(value: Any) -> Any:
    values: list[Any] = []
    _collect_nested_citation_id_values(value, values)
    return values[0] if values else None


def _collect_nested_citation_id_values(value: Any, values: list[Any]) -> None:
    if isinstance(value, dict):
        for raw_key, item in value.items():
            if normalized_context_key(raw_key) == "citation_id":
                values.append(item)
            if isinstance(item, (dict, list, tuple, set)):
                _collect_nested_citation_id_values(item, values)
        return
    if isinstance(value, (list, tuple, set)):
        for item in value:
            _collect_nested_citation_id_values(item, values)


def _normalized_rag_citation_id(value: str) -> str:
    clean = value.strip()
    if clean.lower().startswith("rag:"):
        return f"rag:{clean[4:].strip()}"
    return f"rag:{clean}"
