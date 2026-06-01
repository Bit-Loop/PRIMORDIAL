from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import json
from typing import Any

from primordial.core.context import ContextEnvelope, ContextSinkValidator, is_operational_context_purpose
from primordial.core.domain.models import json_ready
from primordial.core.providers.lmstudio import LMStudioClient
from primordial.core.providers.wrapper_prompts import build_wrapper_system_prompt
from primordial.core.rag.citations import disallowed_rag_synthesis_model, validate_rag_citations


CitationId = Callable[[dict[str, object]], str]


@dataclass(frozen=True, slots=True)
class RagSynthesisContext:
    chunks: list[dict[str, object]]
    citation_map: list[dict[str, object]]
    response: dict[str, object] | None = None


@dataclass(frozen=True, slots=True)
class RagSynthesisProviderResult:
    answer: str
    model: str
    provider: str


def prepare_rag_synthesis_context(
    *,
    query: str,
    mode: str,
    retrieved_chunks: list[dict[str, object]] | None,
    fallback_search: Callable[[str], list[dict[str, object]]],
    citation_map_for_chunks: Callable[[list[dict[str, object]]], list[dict[str, object]]],
    citation_id_for_chunk: CitationId,
) -> RagSynthesisContext:
    if retrieved_chunks is None:
        if is_operational_context_purpose(mode):
            return RagSynthesisContext([], [], _operational_context_required_response(mode))
        chunks = fallback_search(query)
    else:
        chunks = retrieved_chunks

    clean_chunks = [item for item in chunks if isinstance(item, dict) and not item.get("error")]
    citation_map = citation_map_for_chunks(clean_chunks)
    if is_operational_context_purpose(mode):
        validation = validate_operational_rag_synthesis_context(clean_chunks, mode=mode)
        if not validation.valid:
            return RagSynthesisContext(
                clean_chunks,
                citation_map,
                _invalid_context_response(mode, clean_chunks, citation_map, validation.errors, citation_id_for_chunk),
            )
    if not clean_chunks:
        return RagSynthesisContext([], [], _insufficient_context_response(mode))
    return RagSynthesisContext(clean_chunks, citation_map)


def disallowed_model_response(
    *,
    synthesis_config: Any,
    chunks: list[dict[str, object]],
    citation_map: list[dict[str, object]],
    citation_id_for_chunk: CitationId,
    mode: str,
) -> dict[str, object] | None:
    disallowed = disallowed_rag_synthesis_model(synthesis_config.model, synthesis_config.disallowed_models)
    if not disallowed:
        return None
    return {
        "ok": False,
        "status": "disallowed_model",
        "answer": "",
        "error": f"RAG synthesis model {synthesis_config.model!r} is disallowed by pattern {disallowed!r}",
        "retrieved_ids": _citation_ids(chunks, citation_id_for_chunk),
        "citation_map": citation_map,
        "validation": validate_rag_citations("", chunks, mode=mode, require_citations=True).as_payload(),
    }


def run_rag_synthesis_provider(
    *,
    synthesis_config: Any,
    ollama: Any,
    system: str,
    prompt: str,
) -> RagSynthesisProviderResult:
    if synthesis_config.provider == "ollama":
        response = ollama.generate(
            model=synthesis_config.model,
            system=system,
            prompt=prompt,
            temperature=synthesis_config.temperature,
            timeout_seconds=300,
        )
        return RagSynthesisProviderResult(response.text, response.model, "ollama")
    client = LMStudioClient(
        base_url=lmstudio_base_without_v1(synthesis_config.base_url),
        timeout_seconds=300,
    )
    response = client.chat(
        model=synthesis_config.model,
        system=system,
        prompt=prompt,
        temperature=synthesis_config.temperature,
        max_tokens=synthesis_config.max_tokens,
        timeout_seconds=300,
    )
    return RagSynthesisProviderResult(response.text, response.model, "lmstudio_openai_compatible")


def rag_synthesis_system_prompt() -> str:
    return build_wrapper_system_prompt(
        "rag_synthesis",
        (
            "Answer only from retrieved RAG context. Cite every factual sentence with rag:<chunk_id>. "
            "If context is insufficient, say exactly what is missing. Do not use MITRE taxonomy chunks "
            "to choose actions or expand scope."
        ),
    )


def build_rag_synthesis_prompt(
    query: str,
    chunks: list[dict[str, object]],
    *,
    mode: str,
    safety_context: dict[str, object],
    citation_id_for_chunk: CitationId,
) -> str:
    lines = [
        f"Mode: {mode}",
        f"Question: {query.strip()}",
        f"Safety context: {json.dumps(json_ready(safety_context), sort_keys=True)}",
        "",
        "Retrieved context:",
    ]
    for item in chunks:
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        source_display = str(item.get("source_display") or metadata.get("source_display") or "")
        text = str(item.get("text") or item.get("retrieval_text") or "").strip()
        if len(text) > 1800:
            text = text[:1800].rstrip() + "\n...TRUNCATED_RAG_CHUNK..."
        lines.extend(
            [
                f"[{citation_id_for_chunk(item)}]",
                f"source={source_display}",
                f"source_file={metadata.get('source_file') or item.get('source_file') or ''}",
                f"domain={metadata.get('domain') or metadata.get('corpus_type') or ''}",
                f"planner_visibility={metadata.get('planner_visibility') or ''}",
                text,
                "",
            ]
        )
    lines.append("Answer with citations using only rag:<chunk_id> IDs shown above.")
    return "\n".join(lines)


def provider_error_response(
    *,
    exc: Exception,
    chunks: list[dict[str, object]],
    citation_map: list[dict[str, object]],
    citation_id_for_chunk: CitationId,
) -> dict[str, object]:
    return {
        "ok": False,
        "status": "provider_error",
        "answer": "",
        "error": str(exc),
        "retrieved_ids": _citation_ids(chunks, citation_id_for_chunk),
        "citation_map": citation_map,
    }


def final_rag_synthesis_response(
    *,
    provider_result: RagSynthesisProviderResult,
    chunks: list[dict[str, object]],
    citation_map: list[dict[str, object]],
    mode: str,
) -> dict[str, object]:
    validation = validate_rag_citations(provider_result.answer, chunks, mode=mode, require_citations=True)
    return {
        "ok": validation.valid,
        "status": "ok" if validation.valid else "validation_failed",
        "answer": provider_result.answer,
        "provider": provider_result.provider,
        "model": provider_result.model,
        "retrieved_ids": validation.retrieved_ids,
        "citation_map": citation_map,
        "validation": validation.as_payload(),
    }


def validate_operational_rag_synthesis_context(chunks: list[dict[str, object]], *, mode: str):
    envelopes: list[ContextEnvelope] = []
    errors: list[str] = []
    for item in chunks:
        try:
            envelopes.append(ContextEnvelope.from_rag_chunk(item, purpose=mode, sink="prompt"))
        except ValueError as exc:
            errors.append(str(exc))
    result = ContextSinkValidator().validate("prompt", envelopes)
    if errors:
        result.valid = False
        result.errors.extend(errors)
        result.rejected_refs.extend(f"rag_context:{index}" for index in range(len(errors)))
    return result


def lmstudio_base_without_v1(base_url: str) -> str:
    clean = base_url.rstrip("/")
    return clean[:-3] if clean.endswith("/v1") else clean


def _operational_context_required_response(mode: str) -> dict[str, object]:
    return {
        "ok": False,
        "status": "operational_context_required",
        "answer": "",
        "error": (
            "retrieved_chunks are required for operational RAG synthesis; "
            "unscoped fallback retrieval is not allowed"
        ),
        "retrieved_ids": [],
        "citation_map": [],
        "validation": validate_rag_citations("", [], mode=mode, require_citations=True).as_payload(),
    }


def _invalid_context_response(
    mode: str,
    chunks: list[dict[str, object]],
    citation_map: list[dict[str, object]],
    errors: list[str],
    citation_id_for_chunk: CitationId,
) -> dict[str, object]:
    return {
        "ok": False,
        "status": "invalid_rag_context",
        "answer": "",
        "error": "; ".join(errors),
        "retrieved_ids": _citation_ids(chunks, citation_id_for_chunk),
        "citation_map": citation_map,
        "validation": validate_rag_citations("", chunks, mode=mode, require_citations=True).as_payload(),
    }


def _insufficient_context_response(mode: str) -> dict[str, object]:
    return {
        "ok": False,
        "status": "insufficient_context",
        "answer": "",
        "retrieved_ids": [],
        "citation_map": [],
        "validation": validate_rag_citations("", [], mode=mode, require_citations=True).as_payload(),
    }


def _citation_ids(chunks: list[dict[str, object]], citation_id_for_chunk: CitationId) -> list[str]:
    return [citation_id_for_chunk(item) for item in chunks]
