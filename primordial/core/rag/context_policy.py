from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.generated_exports import is_generated_export_metadata, is_generated_export_path
from primordial.core.context.normalization import (
    canonical_rag_domain,
    metadata_bool_value,
    metadata_value,
    normalized_metadata_value,
)
from primordial.core.context.source_refs import (
    has_malformed_source_refs_metadata,
    placeholder_source_refs,
    source_refs_metadata_values,
    uncited_source_refs_metadata,
    unsupported_ai_derived_source_refs,
)
from primordial.core.domain.enums import TaskKind
from primordial.core.domain.models import DocumentChunk, Task
from primordial.core.intent.models import OperatorIntentPolicy
from primordial.core.rag.context_models import (
    ACTION_SELECTION_PURPOSES,
    POC_TASK_KINDS,
    REPORTING_DOMAINS,
    RESTRICTED_DOMAINS,
    SAFE_PLANNING_DOMAINS,
)


class RagContextPolicyMixin:
    def _reject_reason(
        self,
        chunk: DocumentChunk,
        *,
        purpose: str,
        role: str,
        task: Task | None,
        operator_intent: str | None,
        intent_policy: OperatorIntentPolicy | None,
    ) -> str:
        metadata = chunk.metadata
        domain = canonical_rag_domain(metadata_value(metadata, "domain") or metadata_value(metadata, "corpus_type"))
        planner_visibility = normalized_metadata_value(metadata, "planner_visibility")
        if _is_generated_export_metadata(metadata):
            return "generated_export"
        source_refs_reason = _source_refs_metadata_reject_reason(metadata)
        if source_refs_reason:
            return source_refs_reason
        if normalized_metadata_value(metadata, "operational_retrieval_allowed") in {"0", "false", "no", "off"}:
            return "operational_retrieval_disabled"
        rag_index_reason = self._rag_index_reject_reason(chunk)
        if rag_index_reason:
            return rag_index_reason
        if self._is_taxonomy_only(domain, planner_visibility) and purpose in ACTION_SELECTION_PURPOSES:
            return "taxonomy-only material cannot drive action selection"
        if self._is_taxonomy_only(domain, planner_visibility) and purpose == "operator_answer":
            return "taxonomy-only material withheld from ordinary operator answers"
        if self._is_taxonomy_only(domain, planner_visibility) and purpose in {"planner_review", "worker_ai_review", "poc_design"}:
            return "taxonomy-only material withheld from execution-oriented context"
        if self._is_restricted(domain, metadata):
            if self._restricted_allowed(role=role, task=task, purpose=purpose, intent_policy=intent_policy):
                return ""
            intent_label = operator_intent or "current intent"
            return f"restricted source requires explicit gated PoC/applicability context under {intent_label}"
        allowed = self._allowed_domains_for(role=role, purpose=purpose)
        if allowed and domain and domain not in allowed:
            return f"domain {domain} is not part of the {purpose}/{role} advisory lane"
        return ""

    def _allowed_domains_for(self, *, role: str, purpose: str) -> set[str]:
        if purpose == "rag_synthesis":
            return set()
        if purpose == "operator_answer":
            return set(SAFE_PLANNING_DOMAINS)
        if purpose == "report_mapping":
            return set(REPORTING_DOMAINS)
        if role in {"local_deep", "operator_chat"}:
            return {*SAFE_PLANNING_DOMAINS, "mitre_attack"}
        if role == "local_code":
            return {*SAFE_PLANNING_DOMAINS, "binary_exploitation", "kernel_security", "hardware_security"}
        if role == "local_compact":
            return set()
        return set(SAFE_PLANNING_DOMAINS)

    def _restricted_allowed(
        self,
        *,
        role: str,
        task: Task | None,
        purpose: str,
        intent_policy: OperatorIntentPolicy | None,
    ) -> bool:
        if purpose not in {"worker_ai_review", "poc_design", "rag_synthesis"} and role != "local_code":
            return False
        if task is None or task.kind not in POC_TASK_KINDS:
            return False
        if intent_policy is None:
            return False
        if task.kind == TaskKind.POC_APPLICABILITY_VALIDATION:
            return bool(intent_policy.poc_applicability_validation)
        if task.kind == TaskKind.EXPLOIT_RESEARCH:
            return bool(intent_policy.public_poc_research or intent_policy.searchsploit_allowed)
        return bool(
            intent_policy.public_poc_research
            or intent_policy.searchsploit_allowed
            or intent_policy.poc_applicability_validation
            or intent_policy.exploit_code_generation
        )

    def _prompt_sink_reject_reason(self, payload: dict[str, Any], *, purpose: str) -> str:
        try:
            envelope = ContextEnvelope.from_rag_chunk(payload, purpose=purpose, sink="prompt")
        except ValueError as exc:
            return str(exc)
        validation = self.sink_validator.validate("prompt", [envelope], known_rag_refs={envelope.ref})
        if validation.valid:
            return ""
        return "; ".join(validation.errors)

    def _rag_index_reject_reason(self, chunk: DocumentChunk) -> str:
        payload = {
            "chunk_id": chunk.id,
            "citation_id": self._citation_id_for_chunk(chunk),
            "text": chunk.text,
            "metadata": chunk.metadata,
        }
        try:
            envelope = ContextEnvelope.from_rag_chunk(
                payload,
                purpose="rag_retrieval",
                sink="rag_index",
                target_id=chunk.target_id,
            )
        except ValueError as exc:
            return str(exc)
        validation = self.sink_validator.validate("rag_index", [envelope], known_rag_refs={envelope.ref})
        if validation.valid:
            return ""
        return "; ".join(validation.errors)

    def _is_restricted(self, domain: str, metadata: dict[str, Any]) -> bool:
        if domain in RESTRICTED_DOMAINS:
            return True
        if normalized_metadata_value(metadata, "planner_visibility") in {"restricted", "quarantine"}:
            return True
        if normalized_metadata_value(metadata, "risk_level") in {"exploit_validation", "post_exploitation_sensitive"}:
            return True
        return metadata_bool_value(metadata, "requires_operator_approval")

    def _is_taxonomy_only(self, domain: str, planner_visibility: str) -> bool:
        return domain == "mitre_attack" or planner_visibility == "taxonomy_only"

    def _usage_policy_from_metadata(self, metadata: dict[str, Any]) -> str:
        domain = canonical_rag_domain(metadata_value(metadata, "domain") or metadata_value(metadata, "corpus_type"))
        visibility = normalized_metadata_value(metadata, "planner_visibility")
        if self._is_taxonomy_only(domain, visibility):
            return "taxonomy_only"
        if self._is_restricted(domain, metadata):
            return "restricted_gated"
        return "advisory_only"


def _is_generated_export_metadata(metadata: dict[str, Any]) -> bool:
    return is_generated_export_metadata(metadata) or is_generated_export_path(metadata_value(metadata, "source_url"))


def _source_refs_metadata_reject_reason(metadata: dict[str, Any]) -> str:
    carrier = SimpleNamespace(metadata=metadata, citations=[])
    if has_malformed_source_refs_metadata(carrier):
        return "malformed source_refs"
    unsupported_refs = unsupported_ai_derived_source_refs(source_refs_metadata_values(carrier))
    if unsupported_refs:
        return f"unsupported source_refs: {', '.join(unsupported_refs)}"
    placeholder_refs = placeholder_source_refs(source_refs_metadata_values(carrier))
    if placeholder_refs:
        return f"placeholder source_refs: {', '.join(placeholder_refs)}"
    uncited_refs = uncited_source_refs_metadata(carrier)
    if uncited_refs:
        return f"uncited source_refs: {', '.join(uncited_refs)}"
    return ""
