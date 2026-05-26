from __future__ import annotations

from collections import OrderedDict
from typing import Iterable

from primordial.core.context.bindings import has_target_fact_marker
from primordial.core.context.citations import CitationValidator, NON_EVIDENCE_PROOF_CITATION_PREFIXES, PLACEHOLDER_RAG_REFS
from primordial.core.context.current_refs import (
    current_evidence_refs,
    current_note_refs,
    current_rag_refs,
    operator_note_source_omission_reason,
    prompt_context_omission_reason,
)
from primordial.core.context.evidence_shape import EVIDENCE_CONTEXT_AUTHORITIES, FINDING_REF_PREFIX
from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.generated_exports import (
    has_generated_export_path,
    is_generated_export_context,
    is_generated_export_path,
)
from primordial.core.context.metadata_flags import metadata_value_is_false, raw_metadata_value
from primordial.core.context.normalization import normalized_context_key
from primordial.core.context.assembler_roles import role_specific_omission_reason, safety_sensitive_omission_reason
from primordial.core.context.source_refs import (
    placeholder_source_refs,
    source_refs_metadata_errors,
    source_refs_metadata_values,
    unresolved_ai_derived_source_ref_errors,
)
from primordial.core.context.source_types import (
    COLLABORATION_REFERENCE_KINDS,
    COLLABORATION_SOURCE_TYPES,
    EVIDENCE_PROOF_KINDS,
    NON_EVIDENCE_SOURCE_TYPES,
    RAG_ADVISORY_SOURCE_TYPES,
    TRUTH_LIKE_AUTHORITIES,
)
from primordial.core.context.task_metadata import task_metadata_errors
from primordial.core.context.writeup_policy import prompt_writeup_omission_reason

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
    "submission_result": "COLLABORATION_REFS",
}

ROLE_FORBIDDEN_SECTIONS = {
    "evidence_reviewer": frozenset({"RAG_ADVISORY", "MODEL_DERIVED", "COLLABORATION_REFS"}),
    "policy_gate": frozenset({"RAG_ADVISORY", "COLLABORATION_REFS", "OPERATOR_NOTES"}),
}

EVIDENCE_CITATION_PREFIX = "evidence:"
CURRENT_TARGET_BOUND_KINDS = frozenset({"evidence", "finding"})
MODEL_DERIVED_TARGET_BOUND_KINDS = frozenset({"model_summary", "hypothesis", "candidate_task"})
POLICY_GATE_MODEL_DERIVED_KINDS = frozenset({"candidate_task"})
POLICY_GATE_TARGET_BOUND_AUTHORITY_KINDS = frozenset({"approval", "policy_decision", "scope", "target_status"})
POLICY_GATE_CURRENT_TARGET_BOUND_KINDS = POLICY_GATE_MODEL_DERIVED_KINDS | POLICY_GATE_TARGET_BOUND_AUTHORITY_KINDS
CTFD_REFERENCE_KINDS = frozenset(
    {"ctfd_ref", "challenge_metadata", "scoreboard_projection", "solve_status", "submission_result"}
)

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
        known_evidence_refs = current_evidence_refs(
            envelope_list,
            target_id=target_id,
            active_generation_id=active_generation_id,
            purpose=purpose,
            role=role,
        )
        known_evidence_refs -= {
            envelope.ref
            for envelope in envelope_list
            if envelope.kind in EVIDENCE_PROOF_KINDS and self._is_generated_export_source(envelope)
        }
        while True:
            invalid_evidence_refs = {
                envelope.ref
                for envelope in envelope_list
                if envelope.kind in EVIDENCE_PROOF_KINDS
                and (
                    source_refs_metadata_errors(envelope)
                    or unresolved_ai_derived_source_ref_errors(
                        envelope.ref,
                        source_refs_metadata_values(envelope),
                        known_evidence_refs=known_evidence_refs,
                    )
                )
            }
            pruned_evidence_refs = known_evidence_refs - invalid_evidence_refs
            if pruned_evidence_refs == known_evidence_refs:
                break
            known_evidence_refs = pruned_evidence_refs
        known_rag_refs = current_rag_refs(
            envelope_list,
            target_id=target_id,
            active_generation_id=active_generation_id,
            purpose=purpose,
            role=role,
        )
        known_rag_refs -= {
            envelope.ref
            for envelope in envelope_list
            if envelope.kind == "rag" and self._is_generated_export_source(envelope)
        }
        known_note_refs = current_note_refs(
            envelope_list,
            target_id=target_id,
            active_generation_id=active_generation_id,
            purpose=purpose,
            role=role,
        )
        known_note_refs -= {
            envelope.ref
            for envelope in envelope_list
            if envelope.kind == "operator_note" and self._is_generated_export_source(envelope)
        }
        while True:
            invalid_note_refs = {
                envelope.ref
                for envelope in envelope_list
                if envelope.kind == "operator_note"
                and (
                    source_refs_metadata_errors(envelope)
                    or unresolved_ai_derived_source_ref_errors(
                        envelope.ref,
                        source_refs_metadata_values(envelope),
                        known_evidence_refs=known_evidence_refs,
                        known_note_refs=known_note_refs,
                        known_rag_refs=known_rag_refs,
                    )
                )
            }
            pruned_note_refs = known_note_refs - invalid_note_refs
            invalid_rag_refs = {
                envelope.ref
                for envelope in envelope_list
                if envelope.kind == "rag"
                and (
                    metadata_value_is_false(envelope, "operational_retrieval_allowed")
                    or source_refs_metadata_errors(envelope)
                    or unresolved_ai_derived_source_ref_errors(
                        envelope.ref,
                        source_refs_metadata_values(envelope),
                        known_evidence_refs=known_evidence_refs,
                        known_note_refs=pruned_note_refs,
                        known_rag_refs=known_rag_refs,
                    )
                )
            }
            pruned_rag_refs = known_rag_refs - invalid_rag_refs
            if pruned_note_refs == known_note_refs and pruned_rag_refs == known_rag_refs:
                break
            known_note_refs = pruned_note_refs
            known_rag_refs = pruned_rag_refs

        for envelope in envelope_list:
            reason = self._omission_reason(
                envelope,
                target_id=target_id,
                active_generation_id=active_generation_id,
                known_evidence_refs=known_evidence_refs,
                known_note_refs=known_note_refs,
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
                source_refs = item.get("source_refs") if isinstance(item.get("source_refs"), list) else []
                source_ref_text = f" source_refs={','.join(str(ref) for ref in source_refs)}" if source_refs else ""
                lines.append(
                    "- "
                    f"{item.get('ref')}: "
                    f"kind={item.get('kind')} "
                    f"authority={item.get('authority')} "
                    f"source_type={item.get('source_type')}"
                    f"{citation_text} "
                    f"{source_ref_text} "
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
        item: dict[str, object] = {
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
        source_refs = source_refs_metadata_values(envelope)
        if source_refs:
            item["source_refs"] = list(source_refs)
        return item

    def _omission_reason(
        self,
        envelope: ContextEnvelope,
        *,
        target_id: str | None,
        active_generation_id: str | None,
        known_evidence_refs: set[str],
        known_note_refs: set[str],
        known_rag_refs: set[str],
        purpose: str,
        role: str,
    ) -> str:
        role_name = normalized_context_key(role)
        prompt_context_reason = prompt_context_omission_reason(envelope, purpose=purpose, role=role_name)
        if target_id and envelope.target_id and envelope.target_id != target_id:
            return "wrong_target"
        if self._has_placeholder_rag_ref(envelope):
            return "placeholder_rag_ref"
        if placeholder_source_refs(envelope.citations):
            return "invalid_citation"
        safety_reason = safety_sensitive_omission_reason(envelope, role=role_name)
        if safety_reason:
            return safety_reason
        writeup_reason = prompt_writeup_omission_reason(envelope, role=role_name)
        if writeup_reason:
            return writeup_reason
        if self._is_generated_export_source(envelope):
            return "generated_export"
        if metadata_value_is_false(envelope, "operational_retrieval_allowed"):
            return "operational_retrieval_disabled"
        evidence_shape_reason = self._evidence_proof_shape_omission_reason(envelope)
        if evidence_shape_reason:
            return evidence_shape_reason
        note_source_reason = operator_note_source_omission_reason(envelope)
        if note_source_reason:
            return note_source_reason
        if envelope.kind == "operator_note" and (
            source_refs_metadata_errors(envelope)
            or unresolved_ai_derived_source_ref_errors(
                envelope.ref,
                source_refs_metadata_values(envelope),
                known_evidence_refs=known_evidence_refs,
                known_note_refs=known_note_refs,
                known_rag_refs=known_rag_refs,
            )
        ):
            return "invalid_citation"
        if envelope.kind == "rag" and has_target_fact_marker(envelope):
            return "target_fact_rag"
        if envelope.kind == "rag" and (
            source_refs_metadata_errors(envelope)
            or unresolved_ai_derived_source_ref_errors(
                envelope.ref,
                source_refs_metadata_values(envelope),
                known_evidence_refs=known_evidence_refs,
                known_note_refs=known_note_refs,
                known_rag_refs=known_rag_refs,
            )
        ):
            return "invalid_citation"
        if envelope.kind in EVIDENCE_PROOF_KINDS and (
            source_refs_metadata_errors(envelope)
            or unresolved_ai_derived_source_ref_errors(
                envelope.ref,
                source_refs_metadata_values(envelope),
                known_evidence_refs=known_evidence_refs,
            )
        ):
            return "invalid_citation"
        if not CitationValidator().validate([envelope]).valid:
            return "invalid_citation"
        if self._has_non_evidence_proof_citation_support(envelope):
            return "invalid_citation"
        if self._is_proof_from_non_evidence_source(envelope):
            return "non_evidence_source"
        if envelope.kind in MODEL_DERIVED_TARGET_BOUND_KINDS and (
            source_refs_metadata_errors(envelope)
            or unresolved_ai_derived_source_ref_errors(
                envelope.ref,
                source_refs_metadata_values(envelope),
                known_evidence_refs=known_evidence_refs,
                known_note_refs=known_note_refs,
                known_rag_refs=known_rag_refs,
            )
        ):
            return "invalid_citation"
        if prompt_context_reason == "raw_chat_context":
            return prompt_context_reason
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
        if prompt_context_reason:
            return prompt_context_reason
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

    def _is_generated_export_source(self, envelope: ContextEnvelope) -> bool:
        return (
            is_generated_export_context(envelope)
            or has_generated_export_path(envelope)
            or is_generated_export_path(raw_metadata_value(envelope, "source_url"))
        )

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
            return "invalid_finding_ref" if envelope.kind == "finding" and not envelope.ref.startswith(FINDING_REF_PREFIX) else ""
        if envelope.authority not in EVIDENCE_CONTEXT_AUTHORITIES:
            return "invalid_evidence_authority"
        return "" if envelope.ref.startswith(EVIDENCE_CITATION_PREFIX) else "invalid_evidence_ref"

    def _has_non_evidence_proof_citation_support(self, envelope: ContextEnvelope) -> bool:
        prefixes = tuple(prefix.lower() for prefix in NON_EVIDENCE_PROOF_CITATION_PREFIXES)
        return envelope.kind in EVIDENCE_PROOF_KINDS and any(
            str(citation).strip().lower().startswith(prefixes) for citation in envelope.citations
        )

    def _is_ctfd_truth_like_authority(self, envelope: ContextEnvelope) -> bool:
        return (
            normalized_context_key(envelope.source_type) == "ctfd"
            or normalized_context_key(envelope.kind) in CTFD_REFERENCE_KINDS
        ) and normalized_context_key(envelope.authority) in TRUTH_LIKE_AUTHORITIES

    def _is_collaboration_truth_like_authority(self, envelope: ContextEnvelope) -> bool:
        return normalized_context_key(envelope.authority) in TRUTH_LIKE_AUTHORITIES and (
            normalized_context_key(envelope.source_type) in COLLABORATION_SOURCE_TYPES
            or normalized_context_key(envelope.kind) in COLLABORATION_REFERENCE_KINDS
        )

    def _is_historical(self, envelope: ContextEnvelope, *, active_generation_id: str | None) -> bool:
        return bool(active_generation_id and envelope.active_generation_id and envelope.active_generation_id != active_generation_id)
