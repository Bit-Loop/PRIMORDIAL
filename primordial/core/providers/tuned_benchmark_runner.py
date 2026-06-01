from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from primordial.core.providers.lmstudio import LMStudioClient
from primordial.core.providers.model_eval import ModelEvaluationService
from primordial.core.providers.tuned_benchmark_common import EventSink, host_metrics, parse_csv_floats, parse_csv_ints
from primordial.core.providers.tuned_benchmark_lmstudio import ProgressLMStudio
from primordial.core.providers.tuned_benchmark_ollama import TunedOllama
from primordial.core.providers.tuned_benchmark_report import write_report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Primordial tuned local model benchmark.")
    parser.add_argument("--tuning-dir", type=Path, default=Path("artifacts/model_eval/offload_tuning_20260508T175122Z"))
    parser.add_argument("--timeout", type=int, default=500)
    parser.add_argument("--num-predict", type=int, default=256)
    parser.add_argument("--contexts", default="2048,4096,8192,16384,32768")
    parser.add_argument("--temperatures", default="0.0,0.1")
    parser.add_argument("--providers", default="ollama,lmstudio")
    return parser.parse_args()


def load_inputs(args: argparse.Namespace) -> tuple[dict[str, object], dict[str, int], list[int], list[float], list[str], Path, Path]:
    policy_path = args.tuning_dir / "ollama_offload_policy.json"
    tuning_json = args.tuning_dir / "ollama_offload_tuning.json"
    policy_payload = json.loads(policy_path.read_text(encoding="utf-8"))
    raw_policy = policy_payload.get("policy", {})
    policy = {model: int(item["num_gpu"]) for model, item in raw_policy.items()}
    contexts = parse_csv_ints(args.contexts)
    temperatures = parse_csv_floats(args.temperatures)
    providers = [item.strip() for item in args.providers.split(",") if item.strip()]
    return policy_payload, policy, contexts, temperatures, providers, policy_path, tuning_json


def print_start(output_dir: Path, root_report: Path, providers: list[str], contexts: list[int], temperatures: list[float], args, policy) -> None:
    print(f"tuned benchmark artifacts: {output_dir}", flush=True)
    print(f"root report target: {root_report}", flush=True)
    print(f"providers={providers} contexts={contexts} temps={temperatures} timeout={args.timeout}s num_predict={args.num_predict}", flush=True)
    print(f"ollama policy={policy}", flush=True)


def build_evaluator(args, policy: dict[str, int], events: EventSink) -> tuple[ModelEvaluationService, TunedOllama]:
    tuned_ollama = TunedOllama(policy=policy, events=events, num_predict=args.num_predict, timeout_seconds=args.timeout)
    lmstudio = ProgressLMStudio(LMStudioClient(timeout_seconds=args.timeout), events=events, timeout_seconds=args.timeout)
    evaluator = ModelEvaluationService(ollama=tuned_ollama, lmstudio=lmstudio, host_metrics_sampler=host_metrics)
    return evaluator, tuned_ollama


def evaluate(evaluator: ModelEvaluationService, tuned_ollama: TunedOllama, args, providers, contexts, temperatures):
    started = time.perf_counter()
    try:
        summary = evaluator.evaluate(
            providers=providers,
            exhaustive=True,
            context_sizes=contexts,
            max_context=max(contexts),
            temperatures=temperatures,
            timeout_seconds=args.timeout,
            include_outputs=False,
            num_gpu=None,
        )
    finally:
        if tuned_ollama.last_model:
            tuned_ollama.stop(tuned_ollama.last_model)
    return summary, time.perf_counter() - started


def update_summary_config(summary, args, providers, contexts, temperatures, policy_path, tuning_json, events, tuned_ollama, policy) -> None:
    summary.eval_config.update(
        {
            "timeout_seconds": args.timeout,
            "num_predict": args.num_predict,
            "providers": providers,
            "context_sizes": contexts,
            "temperatures": temperatures,
            "offload_tuning_policy_path": str(policy_path),
            "offload_tuning_json_path": str(tuning_json),
            "offload_events_path": str(events.path),
            "ollama_num_gpu_policy": policy,
            "ollama_used_num_gpu_counts": tuned_ollama.used_num_gpu_counts,
            "ollama_context_policy": {f"{model}@{ctx}": gpu for (model, ctx), gpu in tuned_ollama.context_policy.items()},
            "lmstudio_note": "LM Studio layer residency is provider-managed by current Primordial client.",
            "timeout_behavior": "Ollama models are disabled after timeout; failed contexts are cached after fallbacks fail.",
        }
    )


def main() -> int:
    args = parse_args()
    root = Path.cwd()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    policy_payload, policy, contexts, temperatures, providers, policy_path, tuning_json = load_inputs(args)
    output_dir = root / "artifacts" / "model_eval" / f"tuned_full_500s_{stamp}"
    output_dir.mkdir(parents=True, exist_ok=True)
    events = EventSink(output_dir / "offload_events.jsonl")
    root_report = root / f"MODEL_BENCHMARK_TUNED_500S_{stamp}.md"
    print_start(output_dir, root_report, providers, contexts, temperatures, args, policy)
    evaluator, tuned_ollama = build_evaluator(args, policy, events)
    summary, elapsed_wall = evaluate(evaluator, tuned_ollama, args, providers, contexts, temperatures)
    update_summary_config(summary, args, providers, contexts, temperatures, policy_path, tuning_json, events, tuned_ollama, policy)
    artifacts = evaluator.write_artifacts(summary, output_dir=output_dir)
    write_report(root_report=root_report, stamp=stamp, summary=summary, artifacts=artifacts, elapsed_wall=elapsed_wall, policy_payload=policy_payload, tuning_json=tuning_json, policy_path=policy_path, events=events, tuned_ollama=tuned_ollama, providers=providers, contexts=contexts, temperatures=temperatures, timeout_seconds=args.timeout, num_predict=args.num_predict)
    print(f"[benchmark complete] wall_minutes={elapsed_wall / 60:.2f}", flush=True)
    print(f"JSON={artifacts.get('json_path')}", flush=True)
    print(f"CSV={artifacts.get('csv_path')}", flush=True)
    print(f"REPORT={root_report}", flush=True)
    return 0
