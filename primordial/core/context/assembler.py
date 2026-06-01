from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from typing import Iterable

from primordial.core.context.current_refs import (
    current_evidence_refs,
    current_note_refs,
    current_rag_refs,
)
from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.metadata_flags import metadata_value_is_false
from primordial.core.context.omissions import (
    is_generated_export_source,
    is_historical,
    omission_reason,
)
from primordial.core.context.source_markdown import is_source_markdown_context
from primordial.core.context.source_refs import (
    source_refs_metadata_errors,
    source_refs_metadata_values,
    unresolved_ai_derived_source_ref_errors,
)
from primordial.core.context.source_types import (
    EVIDENCE_PROOF_KINDS,
)

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


@dataclass(frozen=True, slots=True)
class KnownContextRefs:
    evidence: set[str]
    notes: set[str]
    rag: set[str]



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
        known_refs = _known_context_refs(
            envelope_list,
            target_id=target_id,
            active_generation_id=active_generation_id,
            purpose=purpose,
            role=role,
        )

        for envelope in envelope_list:
            reason = omission_reason(
                envelope,
                target_id=target_id,
                active_generation_id=active_generation_id,
                known_evidence_refs=known_refs.evidence,
                known_note_refs=known_refs.notes,
                known_rag_refs=known_refs.rag,
                purpose=purpose,
                role=role,
                section_name=self._section_name(envelope),
            )
            if reason:
                omitted.append({"ref": envelope.ref, "reason": reason})
                continue
            if is_historical(envelope, active_generation_id=active_generation_id):
                item = self._section_item(envelope, authority="historical")
                historical_context.append(item)
                if include_historical:
                    sections[self._section_name(envelope)].append(item)
                continue
            sections[self._section_name(envelope)].append(self._section_item(envelope))

        if target_id or active_generation_id:
            sections["AUTHORITATIVE_RUNTIME_STATE"].insert(0, _runtime_state_item(target_id, active_generation_id))
        sections["REQUIRED_OUTPUT_CONTRACT"].append(_required_contract_item(target_id, active_generation_id))
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


def _known_context_refs(
    envelope_list: list[ContextEnvelope],
    *,
    target_id: str | None,
    active_generation_id: str | None,
    purpose: str,
    role: str,
) -> KnownContextRefs:
    evidence = _current_valid_evidence_refs(
        envelope_list,
        target_id=target_id,
        active_generation_id=active_generation_id,
        purpose=purpose,
        role=role,
    )
    notes = _current_note_refs(
        envelope_list,
        target_id=target_id,
        active_generation_id=active_generation_id,
        purpose=purpose,
        role=role,
    )
    rag = _current_rag_refs(
        envelope_list,
        target_id=target_id,
        active_generation_id=active_generation_id,
        purpose=purpose,
        role=role,
    )
    return _pruned_note_and_rag_refs(envelope_list, evidence=evidence, notes=notes, rag=rag)


def _current_valid_evidence_refs(
    envelope_list: list[ContextEnvelope],
    *,
    target_id: str | None,
    active_generation_id: str | None,
    purpose: str,
    role: str,
) -> set[str]:
    evidence = current_evidence_refs(
        envelope_list,
        target_id=target_id,
        active_generation_id=active_generation_id,
        purpose=purpose,
        role=role,
    )
    evidence -= {item.ref for item in envelope_list if item.kind in EVIDENCE_PROOF_KINDS and is_generated_export_source(item)}
    while True:
        invalid = {
            item.ref
            for item in envelope_list
            if item.kind in EVIDENCE_PROOF_KINDS
            and (
                source_refs_metadata_errors(item)
                or unresolved_ai_derived_source_ref_errors(
                    item.ref,
                    source_refs_metadata_values(item),
                    known_evidence_refs=evidence,
                )
            )
        }
        pruned = evidence - invalid
        if pruned == evidence:
            return evidence
        evidence = pruned


def _current_note_refs(
    envelope_list: list[ContextEnvelope],
    *,
    target_id: str | None,
    active_generation_id: str | None,
    purpose: str,
    role: str,
) -> set[str]:
    notes = current_note_refs(
        envelope_list,
        target_id=target_id,
        active_generation_id=active_generation_id,
        purpose=purpose,
        role=role,
    )
    return notes - {item.ref for item in envelope_list if item.kind == "operator_note" and is_generated_export_source(item)}


def _current_rag_refs(
    envelope_list: list[ContextEnvelope],
    *,
    target_id: str | None,
    active_generation_id: str | None,
    purpose: str,
    role: str,
) -> set[str]:
    rag = current_rag_refs(
        envelope_list,
        target_id=target_id,
        active_generation_id=active_generation_id,
        purpose=purpose,
        role=role,
    )
    return rag - {
        item.ref
        for item in envelope_list
        if item.kind == "rag" and (is_generated_export_source(item) or is_source_markdown_context(item))
    }


def _pruned_note_and_rag_refs(
    envelope_list: list[ContextEnvelope],
    *,
    evidence: set[str],
    notes: set[str],
    rag: set[str],
) -> KnownContextRefs:
    while True:
        pruned_notes = notes - _invalid_note_refs(envelope_list, evidence=evidence, notes=notes, rag=rag)
        pruned_rag = rag - _invalid_rag_refs(envelope_list, evidence=evidence, notes=pruned_notes, rag=rag)
        if pruned_notes == notes and pruned_rag == rag:
            return KnownContextRefs(evidence=evidence, notes=notes, rag=rag)
        notes = pruned_notes
        rag = pruned_rag


def _invalid_note_refs(
    envelope_list: list[ContextEnvelope],
    *,
    evidence: set[str],
    notes: set[str],
    rag: set[str],
) -> set[str]:
    return {
        item.ref
        for item in envelope_list
        if item.kind == "operator_note"
        and (
            source_refs_metadata_errors(item)
            or unresolved_ai_derived_source_ref_errors(
                item.ref,
                source_refs_metadata_values(item),
                known_evidence_refs=evidence,
                known_note_refs=notes,
                known_rag_refs=rag,
            )
        )
    }


def _invalid_rag_refs(
    envelope_list: list[ContextEnvelope],
    *,
    evidence: set[str],
    notes: set[str],
    rag: set[str],
) -> set[str]:
    return {
        item.ref
        for item in envelope_list
        if item.kind == "rag"
        and (
            metadata_value_is_false(item, "operational_retrieval_allowed")
            or source_refs_metadata_errors(item)
            or unresolved_ai_derived_source_ref_errors(
                item.ref,
                source_refs_metadata_values(item),
                known_evidence_refs=evidence,
                known_note_refs=notes,
                known_rag_refs=rag,
            )
        )
    }


def _runtime_state_item(target_id: str | None, active_generation_id: str | None) -> dict[str, object]:
    return {
        "ref": "runtime_state:target_context",
        "kind": "authority",
        "authority": "authoritative",
        "source_type": "runtime_state",
        "target_id": target_id,
        "active_generation_id": active_generation_id,
        "content": "Runtime target and generation binding for this context packet.",
        "citations": [],
    }


def _required_contract_item(target_id: str | None, active_generation_id: str | None) -> dict[str, object]:
    return {
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
