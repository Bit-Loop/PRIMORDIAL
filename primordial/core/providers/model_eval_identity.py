from __future__ import annotations

import re
from typing import Any


def build_role_fit_summary(
    *,
    recommended_roles: list[str],
    model_suggestions: list[Any],
) -> dict[str, object]:
    candidate_roles = [
        item.role
        for item in sorted(model_suggestions, key=lambda suggestion: (suggestion.rank, -suggestion.confidence))
        if item.status in {"recommended", "candidate"}
    ]
    strengths: list[str] = []
    cautions: list[str] = []
    for suggestion in model_suggestions:
        for reason in suggestion.reasons:
            if reason not in strengths:
                strengths.append(reason)
        for warning in suggestion.warnings:
            if warning not in cautions:
                cautions.append(warning)
    return {
        "best_for": sorted(set(recommended_roles)),
        "candidate_for": list(dict.fromkeys(candidate_roles))[:4],
        "strengths": strengths[:4],
        "cautions": cautions[:4],
    }


def build_role_finding_rationale(suggestions: list[Any]) -> list[str]:
    rationale: list[str] = []
    for suggestion in suggestions:
        if suggestion.status not in {"recommended", "candidate"}:
            continue
        label = f"{suggestion.role}: confidence={suggestion.confidence:.3f}"
        if suggestion.reasons:
            label = f"{label}; {'; '.join(suggestion.reasons[:2])}"
        if label not in rationale:
            rationale.append(label)
    return rationale[:4]


def metadata_role_score(service: Any, role: str, model_id: str, metadata: dict[str, object]) -> float:
    lowered = model_id.lower()
    family = service._model_family(model_id, metadata)
    params = str(metadata.get("params") or "").lower()
    context = service._optional_positive_int(metadata.get("max_context_length")) or 0
    score = 0.0
    if role == "local_code" and any(term in lowered for term in ("coder", "code", "codestral", "codellama")):
        score += 0.10
    if role == "local_deep" and (
        "reason" in lowered or "r1" in lowered or "deepseek" in family or "qwq" in lowered or context >= 16384
    ):
        score += 0.08
    if role == "local_fast" and any(term in params for term in ("1b", "2b", "3b", "4b", "7b", "8b")):
        score += 0.06
    if role == "local_compact" and any(term in params for term in ("1b", "2b", "3b", "4b", "7b", "8b")):
        score += 0.05
    if role == "local_compact" and context >= 8192:
        score += 0.04
    return score


def model_size_class(params: object) -> str:
    text = str(params or "").strip().lower()
    match = re.search(r"(\d+(?:\.\d+)?)\s*b", text)
    if not match:
        return "unknown"
    value = float(match.group(1))
    if value <= 4:
        return "compact"
    if value <= 9:
        return "small"
    if value <= 14:
        return "medium"
    if value <= 34:
        return "large"
    return "very_large"


def build_quality_profile(service: Any, results: list[Any]) -> dict[str, object]:
    avg_score = sum(item.score for item in results) / max(1, len(results))
    pass_rate = sum(1 for item in results if item.passed) / max(1, len(results))
    hallucination_rate = service._reason_rate(results, "hallucinated unsupported facts")
    over_refusal_rate = service._reason_rate(results, "over-refusal")
    if pass_rate >= 0.8 and hallucination_rate <= 0.05:
        quality_class = "strong"
    elif pass_rate >= 0.55 and hallucination_rate <= 0.2:
        quality_class = "usable"
    else:
        quality_class = "weak"
    return {
        "quality_class": quality_class,
        "avg_score": round(avg_score, 4),
        "pass_rate": round(pass_rate, 4),
        "hallucination_rate": round(hallucination_rate, 4),
        "over_refusal_rate": round(over_refusal_rate, 4),
    }


def build_identity_tags(
    *,
    model_id: str,
    family: str,
    size_class: str,
    context_class: str,
    runtime_profile: dict[str, object],
    quality_profile: dict[str, object],
) -> list[str]:
    lowered = model_id.lower()
    tags: list[str] = []
    if any(term in lowered for term in ("coder", "code", "codestral", "codellama")):
        tags.append("code")
    if any(term in lowered for term in ("reason", "r1", "qwq")) or family == "deepseek":
        tags.append("reasoning")
    if size_class in {"compact", "small"}:
        tags.append("compact")
    if context_class in {"long_context", "very_long_context"}:
        tags.append("long_context")
    runtime_class = runtime_profile.get("runtime_class")
    if runtime_class in {"fast", "slow"}:
        tags.append(str(runtime_class))
    residency = runtime_profile.get("residency_hint")
    if residency in {"gpu_weighted", "cpu_weighted", "mixed_cpu_gpu"}:
        tags.append(str(residency))
    quality_class = quality_profile.get("quality_class")
    if quality_class:
        tags.append(f"quality_{quality_class}")
    return sorted(set(tags))
