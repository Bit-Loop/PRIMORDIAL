from __future__ import annotations

import csv
from datetime import datetime, timezone
import json
import math
from pathlib import Path
from typing import Protocol

from primordial.core.sensitive_text import redact_sensitive_text


class ModelEvalArtifactSummary(Protocol):
    aggregate_rows: list[dict[str, object]]
    artifacts: dict[str, str]

    def as_payload(self) -> dict[str, object]: ...


MODEL_EVAL_ARTIFACT_FIELDNAMES: tuple[str, ...] = (
    "provider",
    "model",
    "recommendation_id",
    "identified_tags",
    "identified_profile",
    "role_recommendation",
    "role_fit_summary",
    "suggested_roles",
    "role_confidence",
    "aggregate_score",
    "role_scores",
    "pass_rate",
    "hallucination_rate",
    "context_hallucination_rates",
    "temperature_hallucination_rates",
    "over_refusal_rate",
    "correct_refusal_rate",
    "safety_warning_rate",
    "avg_tokens_sec",
    "avg_latency_sec",
    "avg_cpu_percent",
    "avg_gpu_percent",
    "avg_gpu_memory_percent",
    "best_context_length",
    "max_context_length",
    "prompt_tokens_avg",
    "completion_tokens_avg",
    "quantization",
    "params",
    "notes",
)
MODEL_EVAL_AGGREGATE_JSON_FIELDS: tuple[tuple[str, object], ...] = (
    ("identified_profile", {}),
    ("role_fit_summary", {}),
    ("suggested_roles", []),
    ("role_confidence", {}),
    ("role_scores", {}),
    ("context_hallucination_rates", {}),
    ("temperature_hallucination_rates", {}),
)


def json_safe(value: object) -> object:
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, str):
        return redact_sensitive_text(value)
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return redact_sensitive_text(value.decode("utf-8", errors="replace"))
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_safe(item) for item in value]
    return redact_sensitive_text(str(value))


def write_model_eval_artifacts(
    summary: ModelEvalArtifactSummary,
    *,
    output_dir: Path,
    csv_path: Path | None = None,
    json_path: Path | None = None,
) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    csv_target = csv_path or output_dir / f"model_eval_{stamp}.csv"
    json_target = json_path or output_dir / f"model_eval_{stamp}.json"
    csv_target.parent.mkdir(parents=True, exist_ok=True)
    json_target.parent.mkdir(parents=True, exist_ok=True)

    _write_model_eval_csv(summary.aggregate_rows, csv_target)
    artifacts = {"csv_path": str(csv_target), "json_path": str(json_target)}
    summary.artifacts = artifacts
    _write_model_eval_json(summary, json_target)
    return artifacts


def _write_model_eval_csv(rows: list[dict[str, object]], csv_target: Path) -> None:
    with csv_target.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=MODEL_EVAL_ARTIFACT_FIELDNAMES)
        writer.writeheader()
        for row in rows:
            serialized = _serialized_aggregate_row(row)
            writer.writerow({key: serialized.get(key, "") for key in MODEL_EVAL_ARTIFACT_FIELDNAMES})


def _serialized_aggregate_row(row: dict[str, object]) -> dict[str, object]:
    serialized = dict(row)
    for field_name, default in MODEL_EVAL_AGGREGATE_JSON_FIELDS:
        serialized[field_name] = json.dumps(json_safe(serialized.get(field_name, default)), sort_keys=True)
    return serialized


def _write_model_eval_json(summary: ModelEvalArtifactSummary, json_target: Path) -> None:
    with json_target.open("w", encoding="utf-8") as handle:
        json.dump(json_safe(summary.as_payload()), handle, indent=2, sort_keys=True)
