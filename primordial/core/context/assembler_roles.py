from __future__ import annotations

from primordial.core.context.citations import CitationValidator
from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.normalization import normalized_metadata_value
from primordial.core.context.poison import has_context_flag
from primordial.core.context.report import has_ai_derived_report_citation, unsupported_ai_derived_report_citations
from primordial.core.context.source_types import (
    COLLABORATION_SOURCE_TYPES,
    RAG_ADVISORY_SOURCE_TYPES,
    TRUTH_LIKE_AUTHORITIES,
)


REPORT_WRITER_FORBIDDEN_SOURCE_TYPES = frozenset({"chat"})
REPORT_WRITER_SENSITIVE_FLAGS = (
    "contains_raw_expected_flag",
    "contains_raw_flag",
    "contains_secret",
    "expected_flag_visible",
    "hidden_solution_material",
    "contains_hidden_solution",
)
CTF_SOLVER_CLOSED_BOOK_SOURCE_TYPES = frozenset({"writeup"})
CTF_SOLVER_CLOSED_BOOK_FLAGS = (
    "prior_solve_trace",
    "generated_postmortem",
    "postmortem_note",
    "target_specific_solution_sequence",
)
CTF_SOLVER_SENSITIVE_FLAGS = (
    "hidden_solution_material",
    "contains_hidden_solution",
    "contains_solution",
    "contains_raw_expected_flag",
    "contains_raw_flag",
    "expected_flag_visible",
)
CTF_SOLVER_CLOSED_BOOK_MODES = frozenset({"closed_book", "closed-book"})
METHODOLOGY_ADVISOR_SENSITIVE_FLAGS = CTF_SOLVER_SENSITIVE_FLAGS + (
    "contains_credential",
    "contains_secret",
    "contains_sensitive_raw_target_evidence",
)
POLICY_GATE_MODEL_DERIVED_KINDS = frozenset({"candidate_task"})
POLICY_GATE_FORBIDDEN_CANDIDATE_SOURCE_TYPES = (
    RAG_ADVISORY_SOURCE_TYPES
    | COLLABORATION_SOURCE_TYPES
    | frozenset({"chat", "ctfd", "export_archive", "generated_export"})
)
POLICY_GATE_DERIVED_CANDIDATE_SOURCE_TYPES = frozenset({"ai_output"})


def role_specific_omission_reason(envelope: ContextEnvelope, *, role: str, section_name: str) -> str:
    if role == "policy_gate" and section_name == "MODEL_DERIVED":
        return _policy_gate_model_derived_omission_reason(envelope)
    if role == "report_writer":
        return _report_writer_omission_reason(envelope, section_name=section_name)
    if role == "ctf_solver_orchestrator":
        return _ctf_solver_omission_reason(envelope)
    if role == "methodology_advisor":
        return _methodology_advisor_omission_reason(envelope)
    return ""


def safety_sensitive_omission_reason(envelope: ContextEnvelope, *, role: str) -> str:
    if role == "report_writer" and has_context_flag(envelope, REPORT_WRITER_SENSITIVE_FLAGS):
        return "sensitive_material"
    if role == "ctf_solver_orchestrator":
        return _ctf_solver_omission_reason(envelope)
    if role == "methodology_advisor":
        return _methodology_advisor_omission_reason(envelope)
    return ""


def _policy_gate_model_derived_omission_reason(envelope: ContextEnvelope) -> str:
    if envelope.kind not in POLICY_GATE_MODEL_DERIVED_KINDS:
        return "role_forbidden"
    if envelope.source_type in POLICY_GATE_FORBIDDEN_CANDIDATE_SOURCE_TYPES:
        return "role_forbidden"
    if (
        envelope.source_type in POLICY_GATE_DERIVED_CANDIDATE_SOURCE_TYPES
        and envelope.authority in TRUTH_LIKE_AUTHORITIES
    ):
        return "role_forbidden"
    return ""


def _report_writer_omission_reason(envelope: ContextEnvelope, *, section_name: str) -> str:
    if has_context_flag(envelope, REPORT_WRITER_SENSITIVE_FLAGS):
        return "sensitive_material"
    if envelope.source_type in REPORT_WRITER_FORBIDDEN_SOURCE_TYPES:
        return "role_forbidden"
    if section_name == "MODEL_DERIVED" and not _has_citations(envelope):
        return "missing_citation"
    if section_name == "MODEL_DERIVED" and not has_ai_derived_report_citation(envelope):
        return "invalid_citation"
    if section_name == "MODEL_DERIVED" and unsupported_ai_derived_report_citations(envelope):
        return "invalid_citation"
    if not CitationValidator().validate([envelope]).valid:
        return "invalid_citation"
    return ""


def _ctf_solver_omission_reason(envelope: ContextEnvelope) -> str:
    if has_context_flag(envelope, CTF_SOLVER_SENSITIVE_FLAGS):
        return "sensitive_material"
    if _is_closed_book(envelope) and (
        envelope.source_type in CTF_SOLVER_CLOSED_BOOK_SOURCE_TYPES
        or has_context_flag(envelope, CTF_SOLVER_CLOSED_BOOK_FLAGS)
    ):
        return "closed_book_forbidden"
    return ""


def _methodology_advisor_omission_reason(envelope: ContextEnvelope) -> str:
    if has_context_flag(envelope, METHODOLOGY_ADVISOR_SENSITIVE_FLAGS):
        return "sensitive_material"
    if _is_closed_book(envelope) and envelope.source_type in CTF_SOLVER_CLOSED_BOOK_SOURCE_TYPES:
        return "closed_book_forbidden"
    return ""


def _has_citations(envelope: ContextEnvelope) -> bool:
    return any(str(citation).strip() for citation in envelope.citations)


def _is_closed_book(envelope: ContextEnvelope) -> bool:
    mode = normalized_metadata_value(envelope.metadata, "benchmark_mode", "mode")
    return mode in CTF_SOLVER_CLOSED_BOOK_MODES
