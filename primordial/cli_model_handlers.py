from __future__ import annotations

import argparse
from collections.abc import Callable
import json
from typing import Any


PayloadFormatter = Callable[[dict[str, object]], str]


def _emit_payload(args: argparse.Namespace, payload: dict[str, object], formatter: PayloadFormatter) -> int:
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(formatter(payload))
    return 0


def run_models_command(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: Any,
) -> int:
    command = args.models_command or "warm"
    handlers = {
        "status": _run_models_status,
        "set-role": _run_models_set_role,
        "warm": _run_models_warm,
        "evaluate": _run_models_evaluate,
        "tune-lmstudio": _run_models_tune_lmstudio,
    }
    handler = handlers.get(command)
    if handler is None:
        parser.error(f"unknown models subcommand: {command}")
    return handler(args, parser, runtime, callbacks)


def _run_models_status(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: Any,
) -> int:
    return _emit_payload(args, runtime.models_payload(), callbacks.format_models_status)


def _run_models_set_role(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: Any,
) -> int:
    processors = {args.role: args.processor} if args.processor else None
    payload = runtime.update_model_roles({args.role: args.model}, processors=processors)
    return _emit_payload(args, payload, callbacks.format_models_status)


def _run_models_warm(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: Any,
) -> int:
    outcome = runtime.warm_model_routes(keep_alive=args.keep_alive)
    if args.json:
        print(json.dumps(outcome, indent=2, sort_keys=True))
    else:
        for result in outcome["results"]:
            status = "ok" if result["ok"] else f"failed: {result['error']}"
            print(f"{result['route']}: {result['model']} {status}")
    return 0


def _run_models_evaluate(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: Any,
) -> int:
    payload = runtime.evaluate_models(
        models=args.model or None,
        limit=args.limit,
        include_outputs=args.include_outputs,
        processor=args.processor,
        providers=args.providers.split(","),
        exhaustive=args.exhaustive,
        csv_path=args.csv,
        json_out=args.json_out,
        max_context=args.max_context,
        context_sizes=args.context_size,
        temperatures=args.temperature,
        judge_model=args.judge_model,
        lmstudio_profile_path=args.lmstudio_profile,
        use_lmstudio_profile=not args.no_lmstudio_profile,
        max_model_runtime_seconds=max(1, int(args.max_model_minutes * 60)),
    )
    return _emit_payload(args, payload, callbacks.format_model_evaluation)


def _run_models_tune_lmstudio(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: Any,
) -> int:
    payload = runtime.tune_lmstudio_models(
        models=args.model or None,
        context_length=args.context,
        max_tokens=args.max_tokens,
        temperature=args.temperature,
        cpu_reserve_mb=args.cpu_reserve_mb,
        vram_soft_reserve_mb=args.vram_soft_reserve_mb,
        timeout_seconds=args.timeout,
        profile_out=args.profile_out,
        json_out=args.json_out,
    )
    return _emit_payload(args, payload, callbacks.format_lmstudio_tuning)
