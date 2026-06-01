from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from primordial.core.providers.model_eval import ModelEvaluationService
from primordial.core.providers.tuned_benchmark_common import EventSink, host_metrics
from primordial.core.providers.tuned_benchmark_ollama import TunedOllama


def _provider_counts(results: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in results:
        provider = str(item.get("provider") or "unknown")
        counts[provider] = counts.get(provider, 0) + 1
    return counts


def _append_header(
    lines: list[str],
    *,
    stamp: str,
    elapsed_wall: float,
    providers: list[str],
    contexts: list[int],
    temperatures: list[float],
    timeout_seconds: int,
    num_predict: int,
    payload: dict[str, Any],
    provider_counts: dict[str, int],
) -> None:
    hw = host_metrics()
    gpu = hw.get("gpu", {}) if isinstance(hw.get("gpu"), dict) else {}
    mem = hw.get("memory", {}) if isinstance(hw.get("memory"), dict) else {}
    lines.extend(
        [
            "# Tuned Local AI Model Benchmark - 500s Timeout",
            "",
            f"Created: {stamp} UTC",
            f"Wall time: {elapsed_wall / 60:.2f} minutes",
            "",
            "## CPU/GPU Offload Answer",
            "",
            "Ollama/llama.cpp-style inference can split a model across CPU and GPU by offloading selected transformer layers to GPU with `num_gpu`; non-offloaded layers remain CPU-resident. LM Studio is benchmarked, but Primordial leaves LM Studio layer residency to LM Studio runtime settings.",
            "",
            "## Hardware Snapshot",
            "",
            f"- GPU total/free at report write: {gpu.get('memory_total_mb', '')}/{gpu.get('memory_free_mb', '')} MB",
            f"- System RAM available at report write: {mem.get('available_mb', '')} MB",
            "",
            "## Benchmark Configuration",
            "",
            f"- Providers: {', '.join(providers)}",
            f"- Timeout: {timeout_seconds}s per generation",
            f"- Context sizes: {', '.join(str(item) for item in contexts)}",
            f"- Temperatures: {', '.join(str(item) for item in temperatures)}",
            f"- Max generated tokens per call: {num_predict}",
            f"- Case count: {len(ModelEvaluationService().default_cases())}",
            f"- Planned models: {len(payload.get('models', []))}",
            f"- Result rows: {len(payload.get('results', []))}",
            f"- Provider row counts: `{json.dumps(provider_counts, sort_keys=True)}`",
        ]
    )


def _append_offload_policy(lines: list[str], policy_payload: dict[str, Any]) -> None:
    lines.extend(["", "## Ollama Offload Policy", "", "| Model | num_gpu | Probe tok/s | Probe residency |", "| --- | ---: | ---: | --- |"])
    for model, item in sorted(policy_payload["policy"].items()):
        processor = str(item.get("processor") or "").splitlines()[-1].strip()
        lines.append(f"| `{model}` | {item.get('num_gpu')} | {item.get('tokens_per_second', '')} | `{processor}` |")


def _append_recommendations(lines: list[str], payload: dict[str, Any]) -> None:
    lines.extend(["", "## Recommendations", ""])
    recs = payload.get("recommendations", {})
    if recs:
        lines.extend(f"- `{role}`: `{model}`" for role, model in sorted(recs.items()))
    else:
        lines.append("- No model met the current recommendation thresholds.")


def _append_aggregate_results(lines: list[str], aggregate: list[dict[str, Any]]) -> None:
    lines.extend(
        [
            "",
            "## Aggregate Results",
            "",
            "| Provider | Model | Score | Pass Rate | Hallucination | Avg tok/s | Avg latency | Best ctx | Notes |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
        ]
    )
    for row in sorted(aggregate, key=lambda item: float(item.get("aggregate_score") or 0), reverse=True):
        lines.append(
            f"| {row.get('provider', '')} | `{row.get('model', '')}` | {row.get('aggregate_score', '')} | {row.get('pass_rate', '')} | {row.get('hallucination_rate', '')} | {row.get('avg_tokens_sec', '')} | {row.get('avg_latency_sec', '')} | {row.get('best_context_length', '')} | {row.get('notes', '')} |"
        )


def _append_error_summary(lines: list[str], errors: list[dict[str, Any]], events: EventSink, tuned_ollama: TunedOllama) -> None:
    context_policy = {f"{model}@{ctx}": gpu for (model, ctx), gpu in tuned_ollama.context_policy.items()}
    lines.extend(
        [
            "",
            "## Error And Timeout Summary",
            "",
            f"- Rows with errors: {len(errors)}",
            f"- Event counts: `{json.dumps(events.counts(), sort_keys=True)}`",
            f"- Ollama num_gpu use counts: `{json.dumps(tuned_ollama.used_num_gpu_counts, sort_keys=True)}`",
            f"- Ollama context fallback policy: `{json.dumps(context_policy, sort_keys=True)}`",
        ]
    )
    grouped: dict[str, int] = {}
    for item in errors:
        key = f"{item.get('provider')}::{item.get('model')}::{str(item.get('error'))[:100]}"
        grouped[key] = grouped.get(key, 0) + 1
    for key, count in sorted(grouped.items(), key=lambda pair: (-pair[1], pair[0]))[:25]:
        lines.append(f"- {count}x {key}")


def _append_artifacts(lines: list[str], artifacts: dict[str, str], tuning_json: Path, policy_path: Path, events: EventSink) -> None:
    lines.extend(
        [
            "",
            "## Artifacts",
            "",
            f"- Tuning JSON: `{tuning_json}`",
            f"- Tuning policy: `{policy_path}`",
            f"- Benchmark JSON: `{artifacts.get('json_path', '')}`",
            f"- Benchmark CSV: `{artifacts.get('csv_path', '')}`",
            f"- Offload events: `{events.path}`",
        ]
    )


def write_report(
    *,
    root_report: Path,
    stamp: str,
    summary: object,
    artifacts: dict[str, str],
    elapsed_wall: float,
    policy_payload: dict[str, Any],
    tuning_json: Path,
    policy_path: Path,
    events: EventSink,
    tuned_ollama: TunedOllama,
    providers: list[str],
    contexts: list[int],
    temperatures: list[float],
    timeout_seconds: int,
    num_predict: int,
) -> None:
    payload = summary.as_payload()  # type: ignore[attr-defined]
    aggregate = payload.get("aggregate_rows", [])
    results = payload.get("results", [])
    errors = [item for item in results if item.get("error")]
    lines: list[str] = []
    _append_header(lines, stamp=stamp, elapsed_wall=elapsed_wall, providers=providers, contexts=contexts, temperatures=temperatures, timeout_seconds=timeout_seconds, num_predict=num_predict, payload=payload, provider_counts=_provider_counts(results))
    _append_offload_policy(lines, policy_payload)
    _append_recommendations(lines, payload)
    _append_aggregate_results(lines, aggregate)
    _append_error_summary(lines, errors, events, tuned_ollama)
    _append_artifacts(lines, artifacts, tuning_json, policy_path, events)
    root_report.write_text("\n".join(lines) + "\n", encoding="utf-8")
