from __future__ import annotations

from pathlib import Path
from typing import Callable, Iterable

from primordial.core.domain.enums import EventType
from primordial.core.domain.models import EventRecord
from primordial.core.providers.model_eval import ModelEvaluationService


SUPPORTED_MODEL_EVAL_PROVIDERS = {"ollama", "lmstudio"}


def normalize_model_eval_processor(processor: str) -> str:
    selected = str(processor).strip().lower()
    if selected not in {"cpu", "gpu"}:
        raise ValueError("processor must be cpu or gpu")
    return selected


def normalize_model_eval_providers(providers: Iterable[str] | None) -> list[str]:
    normalized: list[str] = []
    for item in providers or ["ollama"]:
        for provider in str(item).split(","):
            clean = provider.strip().lower()
            if clean in SUPPORTED_MODEL_EVAL_PROVIDERS and clean not in normalized:
                normalized.append(clean)
    return normalized or ["ollama"]


def model_eval_service(
    ollama: object,
    *,
    lmstudio: object | None,
    host_metrics_sampler: Callable[[], dict[str, object]],
    lmstudio_profile: dict[str, object],
) -> ModelEvaluationService:
    return ModelEvaluationService(
        ollama,
        lmstudio=lmstudio,
        host_metrics_sampler=host_metrics_sampler,
        lmstudio_profile=lmstudio_profile,
    )


def model_eval_ledger_metadata(
    *,
    processor: str,
    providers: list[str],
    max_context: int,
    context_sizes: list[int] | None,
    exhaustive: bool,
    temperatures: list[float] | None,
    judge_model: str | None,
    max_model_runtime_seconds: int,
    lmstudio_profile_path: str | Path | None,
    default_lmstudio_profile_path: Path,
    lmstudio_profile: dict[str, object],
) -> dict[str, object]:
    profile_path = str(lmstudio_profile_path or default_lmstudio_profile_path) if lmstudio_profile else ""
    return {
        "processor": processor,
        "providers": providers,
        "max_context": max_context,
        "context_sizes": context_sizes or [],
        "exhaustive": exhaustive,
        "temperatures": temperatures or [0.0, 0.1],
        "judge_model": judge_model or "",
        "max_model_runtime_seconds": max_model_runtime_seconds,
        "lmstudio_profile_path": profile_path,
        "lmstudio_profile_applied": bool(lmstudio_profile),
    }


def model_eval_completed_event(
    *,
    payload: dict[str, object],
    artifacts: dict[str, str],
    processor: str,
    providers: list[str],
    lmstudio_profile: dict[str, object],
    max_model_runtime_seconds: int,
) -> EventRecord:
    return EventRecord(
        type=EventType.BOOTSTRAP,
        summary="Model evaluation completed",
        metadata={
            "models": payload["models"],
            "recommendations": payload["recommendations"],
            "role_suggestions": payload.get("role_suggestions", []),
            "model_identification": payload.get("model_identification", {}),
            "processor": processor,
            "providers": providers,
            "artifacts": artifacts,
            "lmstudio_profile_applied": bool(lmstudio_profile),
            "max_model_runtime_seconds": max_model_runtime_seconds,
        },
    )


def record_model_eval_payload(
    store: object,
    *,
    payload: dict[str, object],
    artifacts: dict[str, str],
    processor: str,
    providers: list[str],
    max_context: int,
    context_sizes: list[int] | None,
    exhaustive: bool,
    temperatures: list[float] | None,
    judge_model: str | None,
    max_model_runtime_seconds: int,
    lmstudio_profile_path: str | Path | None,
    default_lmstudio_profile_path: Path,
    lmstudio_profile: dict[str, object],
) -> None:
    run_id = store.insert_model_eval_ledger(
        summary=payload,
        artifacts=artifacts,
        metadata=model_eval_ledger_metadata(
            processor=processor,
            providers=providers,
            max_context=max_context,
            context_sizes=context_sizes,
            exhaustive=exhaustive,
            temperatures=temperatures,
            judge_model=judge_model,
            max_model_runtime_seconds=max_model_runtime_seconds,
            lmstudio_profile_path=lmstudio_profile_path,
            default_lmstudio_profile_path=default_lmstudio_profile_path,
            lmstudio_profile=lmstudio_profile,
        ),
    )
    payload["ledger_run_id"] = run_id
    store.insert_event(
        model_eval_completed_event(
            payload=payload,
            artifacts=artifacts,
            processor=processor,
            providers=providers,
            lmstudio_profile=lmstudio_profile,
            max_model_runtime_seconds=max_model_runtime_seconds,
        )
    )
