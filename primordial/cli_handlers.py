from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import dataclass
import json
import os
from typing import Any

from primordial.cli_model_handlers import run_models_command
from primordial.cli_rag_handlers import run_rag_command

from primordial.core.domain.enums import MethodologyName, ScopeProfile


PayloadFormatter = Callable[[dict[str, object]], str]


@dataclass(frozen=True)
class CliRuntimeCallbacks:
    format_models_status: PayloadFormatter
    format_model_evaluation: PayloadFormatter
    format_lmstudio_tuning: PayloadFormatter
    format_credentials_status: PayloadFormatter
    format_caido_status: PayloadFormatter
    format_findings_context: PayloadFormatter
    format_rag_status: PayloadFormatter
    format_rag_import: PayloadFormatter
    format_rag_chunk: PayloadFormatter
    format_rag_ingest: PayloadFormatter
    format_rag_search: PayloadFormatter
    format_rag_hints: PayloadFormatter
    format_rag_vuln_hints: PayloadFormatter
    format_rag_vuln_sync: PayloadFormatter
    render_dashboard: Callable[[Any], str]
    render_scope: Callable[..., str]
    launch_tui: Callable[[Any], int]
    serve_web_console: Callable[..., None]
    prompt: Callable[[str], str]
    secret_prompt: Callable[[str], str]
    default_caido_graphql_url: str


def run_runtime_command(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: CliRuntimeCallbacks,
) -> int:
    command = args.command or "show"
    handlers: dict[str, Callable[[argparse.Namespace, argparse.ArgumentParser, Any, CliRuntimeCallbacks], int]] = {
        "tick": _run_tick,
        "repair": _run_repair,
        "run-loop": _run_loop,
        "compact": _run_compact,
        "process-queues": _run_process_queues,
        "models": run_models_command,
        "credentials": _run_credentials,
        "caido": _run_caido,
        "skills": _run_skills,
        "findings-context": _run_findings_context,
        "rag": run_rag_command,
        "ask": _run_ask,
        "import-scope": _run_import_scope,
        "add-target": _run_add_target,
        "remove-target": _run_remove_target,
        "start-session": _run_start_session,
        "scope": _run_scope,
        "approve": _run_approve,
        "deny": _run_deny,
        "tui": _run_tui,
        "gui": _run_web_console,
        "web": _run_web_console,
    }
    handler = handlers.get(command)
    if handler is None:
        print(callbacks.render_dashboard(runtime))
        return 0
    return handler(args, parser, runtime, callbacks)


def _emit_payload(args: argparse.Namespace, payload: dict[str, object], formatter: PayloadFormatter) -> int:
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(formatter(payload))
    return 0


def _print_dashboard(runtime: Any, callbacks: CliRuntimeCallbacks) -> int:
    print(callbacks.render_dashboard(runtime))
    return 0


def _run_tick(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: CliRuntimeCallbacks,
) -> int:
    report = runtime.run_tick(max_executions=args.max_executions)
    print(report.summary)
    return _print_dashboard(runtime, callbacks)


def _run_repair(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: CliRuntimeCallbacks,
) -> int:
    outcome = runtime.repair_execution_state()
    if args.tick:
        report = runtime.run_tick(max_executions=args.max_executions)
        outcome["tick_summary"] = report.summary
    print(json.dumps(outcome, indent=2, sort_keys=True))
    return _print_dashboard(runtime, callbacks)


def _run_loop(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: CliRuntimeCallbacks,
) -> int:
    for _ in range(args.cycles):
        runtime.run_tick(max_executions=args.max_executions)
    status = _print_dashboard(runtime, callbacks)
    if os.environ.get("PRIMORDIAL_CTF_AUTONOMOUS_ATTEMPT") == "true":
        _emit_ctf_capture_refs(runtime)
    return status


def _run_compact(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: CliRuntimeCallbacks,
) -> int:
    created = runtime.compact_memory()
    print(f"memory_entries_created={created}")
    return _print_dashboard(runtime, callbacks)


def _run_process_queues(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: CliRuntimeCallbacks,
) -> int:
    print(runtime.process_external_queues())
    return _print_dashboard(runtime, callbacks)


def _run_credentials(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: CliRuntimeCallbacks,
) -> int:
    command = args.credentials_command or "status"
    handlers = {
        "status": _run_credentials_status,
        "set-notion": _run_credentials_set_notion,
        "set-discord": _run_credentials_set_discord,
        "set-known": _run_credentials_set_known,
        "set-lab": _run_credentials_set_known,
        "set-caido": _run_credentials_set_caido,
        "clear": _run_credentials_clear,
    }
    handler = handlers.get(command)
    if handler is None:
        parser.error(f"unknown credentials subcommand: {command}")
    return handler(args, parser, runtime, callbacks)


def _run_credentials_status(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: CliRuntimeCallbacks,
) -> int:
    return _emit_payload(args, runtime.credentials_payload(), callbacks.format_credentials_status)


def _prompt_value(value: str | None, prompt: str, callbacks: CliRuntimeCallbacks, *, secret: bool = False) -> str:
    if value is not None:
        return value
    reader = callbacks.secret_prompt if secret else callbacks.prompt
    return reader(prompt).strip()


def _run_credentials_set_notion(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: CliRuntimeCallbacks,
) -> int:
    runtime.set_notion_credentials(
        api_key=_prompt_value(args.api_key, "Notion API key: ", callbacks, secret=True),
        parent_page_id=_prompt_value(args.parent_page_id, "Notion parent page ID: ", callbacks),
        version=args.version,
    )
    print(callbacks.format_credentials_status(runtime.credentials_payload()))
    return 0


def _run_credentials_set_discord(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: CliRuntimeCallbacks,
) -> int:
    webhook_url = _prompt_value(args.webhook_url, "Discord webhook URL: ", callbacks, secret=True)
    runtime.set_discord_credentials(webhook_url=webhook_url)
    print(callbacks.format_credentials_status(runtime.credentials_payload()))
    return 0


def _run_credentials_set_known(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: CliRuntimeCallbacks,
) -> int:
    runtime.set_known_credentials(
        username=_prompt_value(args.username, "Known username: ", callbacks),
        password=_prompt_value(args.password, "Known password: ", callbacks, secret=True),
        domain=_prompt_value(args.domain, "Known domain (optional): ", callbacks),
    )
    print(callbacks.format_credentials_status(runtime.credentials_payload()))
    return 0


def _run_credentials_set_caido(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: CliRuntimeCallbacks,
) -> int:
    graphql_prompt = f"Caido GraphQL URL [{callbacks.default_caido_graphql_url}]: "
    runtime.set_caido_credentials(
        graphql_url=_prompt_value(args.graphql_url, graphql_prompt, callbacks),
        api_token=_prompt_value(args.api_token, "Caido API token: ", callbacks, secret=True),
    )
    print(callbacks.format_credentials_status(runtime.credentials_payload()))
    return 0


def _run_credentials_clear(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: CliRuntimeCallbacks,
) -> int:
    runtime.clear_credentials(args.service)
    print(callbacks.format_credentials_status(runtime.credentials_payload()))
    return 0


def _run_caido(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: CliRuntimeCallbacks,
) -> int:
    command = args.caido_command or "status"
    if command == "status":
        payload = runtime.caido_status_payload(check_health=args.check_health)
        return _emit_payload(args, payload, callbacks.format_caido_status)
    parser.error(f"unknown caido subcommand: {command}")


def _run_skills(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: CliRuntimeCallbacks,
) -> int:
    command = args.skills_command or "list"
    if command != "list":
        parser.error(f"unknown skills subcommand: {command}")
    payload = runtime.skills_payload(include_body=args.include_body)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for skill in payload["skills"]:
            print(f"{skill['id']}: {skill['summary']}")
    return 0


def _run_findings_context(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: CliRuntimeCallbacks,
) -> int:
    command = args.findings_command or "show"
    if command == "show":
        payload = runtime.findings_context_payload(target=args.target, include_guidance=True)
        return _emit_payload(args, payload, callbacks.format_findings_context)
    if command == "sync":
        return _run_findings_sync(args, runtime)
    if command == "audit":
        return _run_findings_audit(args, runtime)
    parser.error(f"unknown findings-context subcommand: {command}")


def _run_findings_sync(args: argparse.Namespace, runtime: Any) -> int:
    payload = runtime.sync_findings_context_exports()
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for item in payload["synced"]:
            workspace = item["workspace"]
            print(f"{item['target']}: {workspace['notion_export_path']}")
    return 0


def _run_findings_audit(args: argparse.Namespace, runtime: Any) -> int:
    payload = runtime.audit_findings_context_exports()
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        summary = payload["summary"]
        print(f"generated_exports={summary['files_seen']} quarantine_required={summary['quarantine_required']}")
    return 0


def _run_ask(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: CliRuntimeCallbacks,
) -> int:
    payload = runtime.ask_operator_ai(" ".join(args.message), target=args.target)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    print(f"model={payload['model']}")
    if not payload["ok"]:
        print(f"error={payload['error']}")
        return 1
    print(payload["answer"]["body"])
    return 0


def _run_import_scope(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: CliRuntimeCallbacks,
) -> int:
    runtime.import_scope(args.path, ScopeProfile(args.profile))
    return _print_dashboard(runtime, callbacks)


def _run_add_target(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: CliRuntimeCallbacks,
) -> int:
    metadata = _metadata_json_arg(args.metadata_json, parser)
    runtime.register_target(
        handle=args.handle,
        display_name=args.display_name,
        profile=ScopeProfile(args.profile),
        assets=args.asset or [args.handle],
        in_scope=not args.out_of_scope,
        metadata=metadata,
    )
    print(callbacks.render_scope(runtime, as_json=getattr(args, "json", False)))
    return 0


def _metadata_json_arg(value: str | None, parser: argparse.ArgumentParser) -> dict[str, object]:
    if not value:
        return {}
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as exc:
        parser.error(f"--metadata-json must be a JSON object: {exc}")
    if not isinstance(payload, dict):
        parser.error("--metadata-json must be a JSON object")
    return payload


def _emit_ctf_capture_refs(runtime: Any) -> None:
    refs: list[str] = []
    for evidence in runtime.store.list_evidence(limit=500):
        for key, prefix in (
            ("captured_flag_ref", "evidence:captured-flag"),
            ("benchmark_solve_ref", "evidence:benchmark-solve"),
        ):
            ref = str(evidence.metadata.get(key, "")).strip()
            if not ref.startswith(prefix):
                continue
            line = f"{key}={ref}"
            if line not in refs:
                refs.append(line)
    for ref in refs:
        print(ref)


def _run_remove_target(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: CliRuntimeCallbacks,
) -> int:
    print(runtime.remove_target(args.handle, ScopeProfile(args.profile) if args.profile else None))
    print(callbacks.render_scope(runtime))
    return 0


def _run_start_session(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: CliRuntimeCallbacks,
) -> int:
    runtime.start_session(
        methodology=MethodologyName(args.methodology),
        profile=ScopeProfile(args.profile),
        title=args.title,
    )
    return _print_dashboard(runtime, callbacks)


def _run_scope(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: CliRuntimeCallbacks,
) -> int:
    print(callbacks.render_scope(runtime, as_json=args.json))
    return 0


def _run_approve(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: CliRuntimeCallbacks,
) -> int:
    if args.all_safe:
        outcome = runtime.approve_all_safe_tasks(limit=args.limit, run_tick=args.tick)
        print(json.dumps(outcome, indent=2, sort_keys=True))
        return _print_dashboard(runtime, callbacks)
    if not args.task_id:
        parser.error("approve requires task_id unless --all-safe is used")
    runtime.approve_task(args.task_id, approved=True)
    return _print_dashboard(runtime, callbacks)


def _run_deny(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: CliRuntimeCallbacks,
) -> int:
    runtime.approve_task(args.task_id, approved=False)
    return _print_dashboard(runtime, callbacks)


def _run_tui(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: CliRuntimeCallbacks,
) -> int:
    return callbacks.launch_tui(runtime)


def _run_web_console(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: CliRuntimeCallbacks,
) -> int:
    callbacks.serve_web_console(runtime, host=args.host, port=args.port)
    return 0
