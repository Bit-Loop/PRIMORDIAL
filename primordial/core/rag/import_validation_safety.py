from __future__ import annotations

from typing import Any

from primordial.core.context.normalization import normalized_context_key


GENERATED_EXPORT_SOURCE_TYPES = frozenset({"generated_export", "export_archive"})
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


def restrictive_safety_value(key: str, *sources: dict[str, Any]) -> Any:
    values = []
    for source in sources:
        values.extend(_safety_metadata_values(source, key))
    if not values:
        return None
    if key in {"origin", "origins"}:
        for value in values:
            if contains_generated_export_marker(value):
                return value
    if key in FALSE_DENY_KEYS and any(metadata_value_is_false(value) for value in values):
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


def truthy_safety_flag_value(key: str, *sources: dict[str, Any]) -> bool | None:
    for source in sources:
        if _contains_truthy_safety_flag(source, key):
            return True
    return None


def restrictive_valid_for_field(record: dict[str, Any], metadata: dict[str, Any]) -> list[str]:
    return restrictive_valid_for_value(metadata, record) or []


def restrictive_valid_for_value(*sources: dict[str, Any]) -> list[str] | None:
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


def list_field(record: dict[str, Any], metadata: dict[str, Any], name: str) -> list[str]:
    value = metadata_value(record, name)
    if value is None:
        value = metadata_value(metadata, name)
    if value is None:
        return []
    return _list_items(value, name)


def citation_id(record: dict[str, Any], metadata: dict[str, Any], *, fallback_chunk_id: str) -> str:
    explicit = str(
        metadata_value(record, "citation_id")
        or metadata_value(metadata, "citation_id")
        or _nested_citation_id_value(record)
        or _nested_citation_id_value(metadata)
        or ""
    ).strip()
    if explicit and explicit.lower() != "rag:none":
        return _normalized_rag_citation_id(explicit)
    fallback = str(fallback_chunk_id or "unknown").strip()
    return _normalized_rag_citation_id(fallback)


def metadata_value(source: dict[str, Any], *names: str) -> Any:
    values = metadata_values(source, *names)
    return values[0] if values else None


def metadata_values(source: dict[str, Any], *names: str) -> list[Any]:
    normalized_names = {normalized_context_key(name) for name in names}
    values: list[Any] = []
    for raw_key, value in source.items():
        if normalized_context_key(raw_key) in normalized_names:
            values.append(value)
    return values


def metadata_value_is_false(value: Any) -> bool:
    if isinstance(value, (frozenset, list, set, tuple)):
        return any(metadata_value_is_false(item) for item in value)
    return value is False or normalized_context_key(value) in FALSE_VALUES


def metadata_value_is_true(value: Any) -> bool:
    if isinstance(value, (frozenset, list, set, tuple)):
        return any(metadata_value_is_true(item) for item in value)
    return value is True or normalized_context_key(value) in TRUTHY_VALUES


def contains_generated_export_marker(value: Any) -> bool:
    return contains_marker(value, GENERATED_EXPORT_SOURCE_TYPES)


def contains_marker(value: Any, allowed: frozenset[str]) -> bool:
    if isinstance(value, (frozenset, list, set, tuple)):
        return any(contains_marker(item, allowed) for item in value)
    return normalized_context_key(value) in allowed


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


def _contains_truthy_safety_flag(value: Any, key: str) -> bool:
    if isinstance(value, dict):
        for raw_key, item in value.items():
            if normalized_context_key(raw_key) == key and metadata_value_is_true(item):
                return True
            if isinstance(item, (dict, list, tuple, set)) and _contains_truthy_safety_flag(item, key):
                return True
    if isinstance(value, (list, tuple, set)):
        return any(_contains_truthy_safety_flag(item, key) for item in value)
    return False


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
