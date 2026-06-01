from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any

from primordial.core.context.normalization import normalized_context_key


ACTION_SELECTION_MODES = {
    "action_selection",
    "task_hint",
    "next_action",
    "exploit_selection",
    "tool_execution",
    "planner",
}


UNSAFE_SCOPE_PATTERNS = {
    "brute_force": re.compile(r"\b(brute force|password spraying|credential spraying)\b", re.IGNORECASE),
    "reverse_shell": re.compile(r"\b(reverse shell|bind shell)\b", re.IGNORECASE),
    "persistence": re.compile(r"\b(persistence|evasion|disable logging)\b", re.IGNORECASE),
    "exfiltration": re.compile(r"\b(exfiltrate|exfiltration)\b", re.IGNORECASE),
    "bypass_authorization": re.compile(r"\b(bypass authorization|bypass auth)\b", re.IGNORECASE),
}


@dataclass(slots=True)
class RagCitationValidationResult:
    valid: bool
    cited_ids: list[str] = field(default_factory=list)
    retrieved_ids: list[str] = field(default_factory=list)
    invented_ids: list[str] = field(default_factory=list)
    missing_citations: list[str] = field(default_factory=list)
    uncited_required_sections: list[str] = field(default_factory=list)
    unsafe_scope_flags: list[str] = field(default_factory=list)
    blocked_source_use: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def as_payload(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "cited_ids": list(self.cited_ids),
            "retrieved_ids": list(self.retrieved_ids),
            "invented_ids": list(self.invented_ids),
            "missing_citations": list(self.missing_citations),
            "uncited_required_sections": list(self.uncited_required_sections),
            "unsafe_scope_flags": list(self.unsafe_scope_flags),
            "blocked_source_use": list(self.blocked_source_use),
            "warnings": list(self.warnings),
        }


def validate_rag_citations(
    answer: str,
    retrieved_chunks: list[dict[str, Any]],
    *,
    mode: str = "grounded_answer",
    require_citations: bool = True,
) -> RagCitationValidationResult:
    retrieved_ids = _retrieved_ids(retrieved_chunks)
    cited_ids = sorted(set(_citation_ids(answer)))
    invented_ids = sorted(set(cited_ids) - set(retrieved_ids))
    missing_citations: list[str] = []
    if require_citations and retrieved_ids and not cited_ids:
        missing_citations.append("answer contains no rag:<chunk_id> citations")
    uncited_required_sections = _uncited_sections(answer) if require_citations else []
    blocked_source_use = _blocked_source_use(retrieved_chunks, mode)
    unsafe_scope_flags = [
        name
        for name, pattern in UNSAFE_SCOPE_PATTERNS.items()
        if pattern.search(answer or "") and "do not" not in answer.lower()
    ]
    warnings = ["deterministic citation validation only; semantic claim support is not LLM-verified"]
    valid = not (invented_ids or missing_citations or uncited_required_sections or blocked_source_use or unsafe_scope_flags)
    return RagCitationValidationResult(
        valid=valid,
        cited_ids=cited_ids,
        retrieved_ids=retrieved_ids,
        invented_ids=invented_ids,
        missing_citations=missing_citations,
        uncited_required_sections=uncited_required_sections,
        unsafe_scope_flags=unsafe_scope_flags,
        blocked_source_use=blocked_source_use,
        warnings=warnings,
    )


def disallowed_rag_synthesis_model(model: str, disallowed: list[str] | tuple[str, ...]) -> str | None:
    lowered = model.lower()
    for item in disallowed:
        needle = str(item).strip().lower()
        if needle and needle in lowered:
            return needle
    return None


def _retrieved_ids(chunks: list[dict[str, Any]]) -> list[str]:
    ids: set[str] = set()
    for item in chunks:
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        chunk_id = str(item.get("chunk_id") or item.get("id") or "").strip()
        citation_id = str(item.get("citation_id") or _metadata_value(metadata, "citation_id") or "").strip()
        if chunk_id:
            ids.add(_rag_id(chunk_id))
        if citation_id:
            ids.add(_rag_id(citation_id))
    return sorted(ids)


def _rag_id(value: object) -> str:
    clean = str(value or "").strip()
    return clean if clean.startswith("rag:") else f"rag:{clean}"


def _metadata_value(metadata: dict[str, Any], name: str) -> Any:
    for raw_key, value in metadata.items():
        if normalized_context_key(raw_key) == name:
            return value
    return None


def _citation_ids(answer: str) -> list[str]:
    return [f"rag:{match}" for match in re.findall(r"\brag:([A-Za-z0-9_.:-]+)", answer or "")]


def _uncited_sections(answer: str) -> list[str]:
    uncited: list[str] = []
    for line in (answer or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.endswith(":"):
            continue
        if len(stripped) < 45:
            continue
        if "rag:" not in stripped:
            uncited.append(stripped[:120])
    return uncited


def _blocked_source_use(chunks: list[dict[str, Any]], mode: str) -> list[str]:
    normalized_mode = (mode or "").strip().lower()
    if normalized_mode not in ACTION_SELECTION_MODES:
        return []
    blocked: list[str] = []
    for item in chunks:
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        domain = str(
            _metadata_value(metadata, "domain")
            or _metadata_value(metadata, "corpus_type")
            or item.get("domain")
            or ""
        )
        visibility = str(_metadata_value(metadata, "planner_visibility") or item.get("planner_visibility") or "")
        if domain == "mitre_attack" or visibility == "taxonomy_only":
            blocked.append(
                _rag_id(
                    item.get("citation_id")
                    or _metadata_value(metadata, "citation_id")
                    or item.get("chunk_id")
                    or item.get("id")
                    or "unknown"
                )
            )
    return sorted(set(blocked))
