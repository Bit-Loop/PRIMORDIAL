from __future__ import annotations

from collections import OrderedDict
from typing import Iterable

from primordial.core.context.bindings import has_target_fact_marker
from primordial.core.context.citations import CitationValidator, NON_EVIDENCE_PROOF_CITATION_PREFIXES, PLACEHOLDER_RAG_REFS
from primordial.core.context.evidence_shape import EVIDENCE_CONTEXT_AUTHORITIES, FINDING_REF_PREFIX
from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.generated_exports import is_generated_export_context
from primordial.core.context.metadata_flags import metadata_value_is_false
from primordial.core.context.normalization import normalized_context_key, normalized_context_keys
from primordial.core.context.assembler_roles import role_specific_omission_reason, safety_sensitive_omission_reason
from primordial.core.context.source_types import (
    COLLABORATION_REFERENCE_KINDS,
    COLLABORATION_SOURCE_TYPES,
    EVIDENCE_PROOF_KINDS,
    NON_EVIDENCE_SOURCE_TYPES,
    RAG_ADVISORY_SOURCE_TYPES,
    TRUTH_LIKE_AUTHORITIES,
)
from primordial.core.context.task_metadata import task_metadata_errors

SECTION_ORDER = (
    "AUTHORITATIVE_RUNTIME_STATE",
    "OBSERVED_EVIDENCE",
    "REVIEWED_FINDINGS",
    "RECENT_ACTION_TRACE",
    "OPERATOR_NOTES",
    "RAG_ADVISORY",
    "MODEL_DERIVED",
    "COLLABORATION_REFS",
    "REQUIRED_OUTPUT_CONTRACT",
)

KIND_SECTIONS = {
    "authority": "AUTHORITATIVE_RUNTIME_STATE",
    "approval": "AUTHORITATIVE_RUNTIME_STATE",
    "engagement_profile": "AUTHORITATIVE_RUNTIME_STATE",
    "operator_intent": "AUTHORITATIVE_RUNTIME_STATE",
    "policy_decision": "AUTHORITATIVE_RUNTIME_STATE",
    "scope": "AUTHORITATIVE_RUNTIME_STATE",
    "target_status": "AUTHORITATIVE_RUNTIME_STATE",
    "evidence": "OBSERVED_EVIDENCE",
    "finding": "REVIEWED_FINDINGS",
    "action_trace": "RECENT_ACTION_TRACE",
    "blocked_action": "RECENT_ACTION_TRACE",
    "failure_trace": "RECENT_ACTION_TRACE",
    "operator_note": "OPERATOR_NOTES",
    "primitive_run": "RECENT_ACTION_TRACE",
    "rag": "RAG_ADVISORY",
    "task_outcome": "RECENT_ACTION_TRACE",
    "model_summary": "MODEL_DERIVED",
    "hypothesis": "MODEL_DERIVED",
    "candidate_task": "MODEL_DERIVED",
    "github_ref": "COLLABORATION_REFS",
    "notion_ref": "COLLABORATION_REFS",
    "ctfd_ref": "COLLABORATION_REFS",
    "challenge_metadata": "COLLABORATION_REFS",
    "scoreboard_projection": "COLLABORATION_REFS",
    "solve_status": "COLLABORATION_REFS",
}

ROLE_FORBIDDEN_SECTIONS = {
    "evidence_reviewer": frozenset({"RAG_ADVISORY", "MODEL_DERIVED", "COLLABORATION_REFS"}),
    "policy_gate": frozenset({"RAG_ADVISORY", "COLLABORATION_REFS", "OPERATOR_NOTES"}),
}

OPERATIONAL_PROMPT_FORBIDDEN_SOURCE_TYPES = frozenset({"chat"})
PROMPT_SINK = "prompt"
EVIDENCE_CITATION_PREFIX = "evidence:"
RAG_CITATION_PREFIX = "rag:"
CURRENT_TARGET_BOUND_KINDS = frozenset({"evidence", "finding"})
MODEL_DERIVED_TARGET_BOUND_KINDS = frozenset({"model_summary", "hypothesis", "candidate_task"})
POLICY_GATE_MODEL_DERIVED_KINDS = frozenset({"candidate_task"})
POLICY_GATE_TARGET_BOUND_AUTHORITY_KINDS = frozenset({"approval", "policy_decision", "scope", "target_status"})
POLICY_GATE_CURRENT_TARGET_BOUND_KINDS = POLICY_GATE_MODEL_DERIVED_KINDS | POLICY_GATE_TARGET_BOUND_AUTHORITY_KINDS


class ContextAssembler:
    def assemble(
        self,
        envelopes: Iterable[ContextEnvelope],
        *,
        purpose: str,
        role: str,
        target_id: str | None = None,
        active_generation_id: str | None = None,
        include_historical: bool = False,
    ) -> dict[str, object]:
        sections: OrderedDict[str, list[dict[str, object]]] = OrderedDict((name, []) for name in SECTION_ORDER)
        historical_context: list[dict[str, object]] = []
        omitted: list[dict[str, object]] = []

        envelope_list = list(envelopes)
        known_evidence_refs = self._current_evidence_refs(
            envelope_list,
            target_id=target_id,
            active_generation_id=active_generation_id,
            purpose=purpose,
            role=role,
        )
        known_rag_refs = self._current_rag_refs(
            envelope_list,
            target_id=target_id,
            active_generation_id=active_generation_id,
            purpose=purpose,
            role=role,
        )

        for envelope in envelope_list:
            reason = self._omission_reason(
                envelope,
                target_id=target_id,
                active_generation_id=active_generation_id,
                known_evidence_refs=known_evidence_refs,
                known_rag_refs=known_rag_refs,
                purpose=purpose,
                role=role,
            )
            if reason:
                omitted.append({"ref": envelope.ref, "reason": reason})
                continue
            if self._is_historical(envelope, active_generation_id=active_generation_id):
                item = self._section_item(envelope, authority="historical")
                historical_context.append(item)
                if include_historical:
                    sections[self._section_name(envelope)].append(item)
                continue
            sections[self._section_name(envelope)].append(self._section_item(envelope))

        if target_id or active_generation_id:
            sections["AUTHORITATIVE_RUNTIME_STATE"].insert(
                0,
                {
                    "ref": "runtime_state:target_context",
                    "kind": "authority",
                    "authority": "authoritative",
                    "source_type": "runtime_state",
                    "target_id": target_id,
                    "active_generation_id": active_generation_id,
                    "content": "Runtime target and generation binding for this context packet.",
                    "citations": [],
                },
            )
        sections["REQUIRED_OUTPUT_CONTRACT"].append(
            {
                "ref": "contract:context-boundary",
                "kind": "authority",
                "authority": "authoritative",
                "source_type": "runtime_state",
                "target_id": target_id,
                "active_generation_id": active_generation_id,
                "content": (
                    "Use evidence:<id> for target facts, rag:<chunk_id> for advisory material, "
                    "and do not convert advisory or derived context into evidence."
                ),
                "citations": [],
            }
        )
        rendered = self.render(sections)
        return {
            "purpose": purpose,
            "role": role,
            "target_id": target_id,
            "active_generation_id": active_generation_id,
            "sections": sections,
            "historical_context": historical_context,
            "omitted": omitted,
            "rendered": rendered,
        }

    def render(self, sections: dict[str, list[dict[str, object]]]) -> str:
        lines: list[str] = []
        for name in SECTION_ORDER:
            items = sections.get(name, [])
            if not items:
                continue
            lines.append(f"{name}:")
            for item in items:
                citations = item.get("citations") if isinstance(item.get("citations"), list) else []
                citation_text = f" citations={','.join(str(cite) for cite in citations)}" if citations else ""
                lines.append(
                    "- "
                    f"{item.get('ref')}: "
                    f"kind={item.get('kind')} "
                    f"authority={item.get('authority')} "
                    f"source_type={item.get('source_type')}"
                    f"{citation_text} "
                    f"{item.get('content')}"
                )
        return "\n".join(lines).strip()

    def _section_name(self, envelope: ContextEnvelope) -> str:
        return KIND_SECTIONS.get(envelope.kind, "MODEL_DERIVED")

    def _section_item(
        self,
        envelope: ContextEnvelope,
        *,
        authority: str | None = None,
    ) -> dict[str, object]:
        return {
            "ref": envelope.ref,
            "kind": envelope.kind,
            "authority": authority or envelope.authority,
            "source_type": envelope.source_type,
            "target_id": envelope.target_id,
            "active_generation_id": envelope.active_generation_id,
            "content": envelope.content,
            "citations": list(envelope.citations),
            "content_hash": envelope.content_hash,
        }

    def _omission_reason(
        self,
        envelope: ContextEnvelope,
        *,
        target_id: str | None,
        active_generation_id: str | None,
        known_evidence_refs: set[str],
        known_rag_refs: set[str],
        purpose: str,
        role: str,
    ) -> str:
        role_name = normalized_context_key(role)
        if target_id and envelope.target_id and envelope.target_id != target_id:
            return "wrong_target"
        if self._has_placeholder_rag_ref(envelope):
            return "placeholder_rag_ref"
        safety_reason = safety_sensitive_omission_reason(envelope, role=role_name)
        if safety_reason:
            return safety_reason
        if is_generated_export_context(envelope):
            return "generated_export"
        if metadata_value_is_false(envelope, "operational_retrieval_allowed"):
            return "operational_retrieval_disabled"
        evidence_shape_reason = self._evidence_proof_shape_omission_reason(envelope)
        if evidence_shape_reason:
            return evidence_shape_reason
        if envelope.kind == "rag" and has_target_fact_marker(envelope):
            return "target_fact_rag"
        if not CitationValidator().validate([envelope]).valid:
            return "invalid_citation"
        if self._has_non_evidence_proof_citation_support(envelope):
            return "invalid_citation"
        if self._is_proof_from_non_evidence_source(envelope):
            return "non_evidence_source"
        if self._is_raw_chat_context(envelope):
            return "raw_chat_context"
        if self._is_ctfd_truth_like_authority(envelope):
            return "ctfd_truth_like_authority"
        if self._is_collaboration_truth_like_authority(envelope):
            return "collaboration_truth_like_authority"
        if envelope.kind == "rag" and envelope.source_type not in RAG_ADVISORY_SOURCE_TYPES:
            return "non_advisory_rag_source"
        if target_id and self._requires_current_target_binding(envelope, role=role_name) and not envelope.target_id:
            return "missing_target_binding"
        if active_generation_id and self._requires_current_target_binding(envelope, role=role_name) and not envelope.active_generation_id:
            return "missing_generation_binding"
        if envelope.kind != "rag" and not CitationValidator(
            known_evidence_refs=known_evidence_refs,
            known_rag_refs=known_rag_refs,
        ).validate([envelope]).valid:
            return "invalid_citation"
        if role_name == "policy_gate" and self._is_historical(envelope, active_generation_id=active_generation_id):
            return "stale_generation"
        validity_reason = self._validity_omission_reason(envelope, purpose=purpose, role=role_name)
        if validity_reason:
            return validity_reason
        if self._has_prompt_sink_mismatch(envelope):
            return "sink_mismatch"
        if (
            envelope.kind == "rag"
            and not self._is_historical(envelope, active_generation_id=active_generation_id)
            and not CitationValidator(
                known_evidence_refs=known_evidence_refs,
                known_rag_refs=known_rag_refs,
            ).validate([envelope]).valid
        ):
            return "invalid_citation"
        if (
            role_name != "policy_gate"
            and envelope.kind == "candidate_task"
            and task_metadata_errors(envelope, known_evidence_refs=known_evidence_refs)
        ):
            return "task_metadata_invalid"
        role_specific_reason = role_specific_omission_reason(
            envelope,
            role=role_name,
            section_name=self._section_name(envelope),
        )
        if role_specific_reason:
            return role_specific_reason
        if self._section_name(envelope) in ROLE_FORBIDDEN_SECTIONS.get(role_name, frozenset()):
            return "role_forbidden"
        return ""

    def _validity_omission_reason(self, envelope: ContextEnvelope, *, purpose: str, role: str) -> str:
        context_names = self._context_names(envelope, purpose=purpose, role=role)
        invalid_for = self._normalized_names(envelope.invalid_for)
        if invalid_for & context_names:
            return "invalid_for_context"
        valid_for = self._normalized_names(envelope.valid_for)
        if valid_for and not valid_for & context_names:
            return "not_valid_for_context"
        return ""

    def _context_names(self, envelope: ContextEnvelope, *, purpose: str, role: str) -> set[str]:
        return self._normalized_names((purpose, role, "prompt"))

    def _normalized_names(self, names: Iterable[str]) -> set[str]:
        return normalized_context_keys(names)

    def _current_evidence_refs(
        self,
        envelopes: Iterable[ContextEnvelope],
        *,
        target_id: str | None,
        active_generation_id: str | None,
        purpose: str,
        role: str,
    ) -> set[str]:
        role_name = normalized_context_key(role)
        refs: set[str] = set()
        for envelope in envelopes:
            if envelope.kind != "evidence":
                continue
            if not envelope.ref.startswith(EVIDENCE_CITATION_PREFIX):
                continue
            if envelope.source_type in NON_EVIDENCE_SOURCE_TYPES:
                continue
            if is_generated_export_context(envelope):
                continue
            if metadata_value_is_false(envelope, "operational_retrieval_allowed"):
                continue
            if self._evidence_proof_shape_omission_reason(envelope):
                continue
            if self._has_prompt_sink_mismatch(envelope):
                continue
            if self._has_non_evidence_proof_citation_support(envelope):
                continue
            if self._validity_omission_reason(envelope, purpose=purpose, role=role_name):
                continue
            if target_id and envelope.target_id != target_id:
                continue
            if active_generation_id and envelope.active_generation_id != active_generation_id:
                continue
            refs.add(envelope.ref)
        return refs

    def _current_rag_refs(
        self,
        envelopes: Iterable[ContextEnvelope],
        *,
        target_id: str | None,
        active_generation_id: str | None,
        purpose: str,
        role: str,
    ) -> set[str]:
        role_name = normalized_context_key(role)
        refs: set[str] = set()
        for envelope in envelopes:
            if envelope.kind != "rag":
                continue
            if not envelope.ref.startswith(RAG_CITATION_PREFIX):
                continue
            if envelope.source_type not in RAG_ADVISORY_SOURCE_TYPES:
                continue
            if safety_sensitive_omission_reason(envelope, role=role_name):
                continue
            if target_id and envelope.target_id and envelope.target_id != target_id:
                continue
            if active_generation_id and envelope.active_generation_id and envelope.active_generation_id != active_generation_id:
                continue
            if self._has_placeholder_rag_ref(envelope):
                continue
            if not CitationValidator().validate([envelope]).valid:
                continue
            if is_generated_export_context(envelope):
                continue
            if metadata_value_is_false(envelope, "operational_retrieval_allowed"):
                continue
            if self._is_raw_chat_context(envelope):
                continue
            if self._has_prompt_sink_mismatch(envelope):
                continue
            if self._validity_omission_reason(envelope, purpose=purpose, role=role_name):
                continue
            refs.add(envelope.ref)
        return refs

    def _requires_current_target_binding(self, envelope: ContextEnvelope, *, role: str) -> bool:
        return envelope.kind in CURRENT_TARGET_BOUND_KINDS or (
            role == "policy_gate" and envelope.kind in POLICY_GATE_CURRENT_TARGET_BOUND_KINDS
        ) or (
            envelope.kind in MODEL_DERIVED_TARGET_BOUND_KINDS
            and any(str(citation).strip().startswith(EVIDENCE_CITATION_PREFIX) for citation in envelope.citations)
        )

    def _has_placeholder_rag_ref(self, envelope: ContextEnvelope) -> bool:
        refs = [envelope.ref, *envelope.citations]
        return any(str(ref).strip().lower() in PLACEHOLDER_RAG_REFS for ref in refs)

    def _is_proof_from_non_evidence_source(self, envelope: ContextEnvelope) -> bool:
        return envelope.kind in EVIDENCE_PROOF_KINDS and envelope.source_type in NON_EVIDENCE_SOURCE_TYPES

    def _evidence_proof_shape_omission_reason(self, envelope: ContextEnvelope) -> str:
        if envelope.kind != "evidence":
            if envelope.kind == "finding" and not envelope.ref.startswith(FINDING_REF_PREFIX):
                return "invalid_finding_ref"
            return ""
        if envelope.authority not in EVIDENCE_CONTEXT_AUTHORITIES:
            return "invalid_evidence_authority"
        if not envelope.ref.startswith(EVIDENCE_CITATION_PREFIX):
            return "invalid_evidence_ref"
        return ""

    def _has_non_evidence_proof_citation_support(self, envelope: ContextEnvelope) -> bool:
        if envelope.kind not in EVIDENCE_PROOF_KINDS:
            return False
        prefixes = tuple(prefix.lower() for prefix in NON_EVIDENCE_PROOF_CITATION_PREFIXES)
        return any(str(citation).strip().lower().startswith(prefixes) for citation in envelope.citations)

    def _is_raw_chat_context(self, envelope: ContextEnvelope) -> bool:
        return envelope.source_type in OPERATIONAL_PROMPT_FORBIDDEN_SOURCE_TYPES

    def _is_ctfd_truth_like_authority(self, envelope: ContextEnvelope) -> bool:
        return envelope.source_type == "ctfd" and envelope.authority in TRUTH_LIKE_AUTHORITIES

    def _is_collaboration_truth_like_authority(self, envelope: ContextEnvelope) -> bool:
        return (
            (
                normalized_context_key(envelope.source_type) in COLLABORATION_SOURCE_TYPES
                or normalized_context_key(envelope.kind) in COLLABORATION_REFERENCE_KINDS
            )
            and normalized_context_key(envelope.authority) in TRUTH_LIKE_AUTHORITIES
        )

    def _has_prompt_sink_mismatch(self, envelope: ContextEnvelope) -> bool:
        return normalized_context_key(envelope.sink) != PROMPT_SINK

    def _is_historical(
        self,
        envelope: ContextEnvelope,
        *,
        active_generation_id: str | None,
    ) -> bool:
        return bool(
            active_generation_id
            and envelope.active_generation_id
            and envelope.active_generation_id != active_generation_id
        )
