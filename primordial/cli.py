from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import signal
import sys
import time
from urllib import error as urlerror
from urllib import request as urlrequest

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from primordial.app.runtime import PrimordialRuntime
from primordial.adapters.caido import CaidoIntegrationService
from primordial.core.doctor import dumps_doctor_json, format_doctor_report, run_doctor
from primordial.core.domain.enums import MethodologyName, ScopeProfile
from primordial.core.local_runtime import load_project_env, resolve_project_root
from primordial.core.startup import StartupPreflightError, run_startup_preflight
from primordial.core.web import serve_web_console
from primordial.ui.textual_app import launch_tui, render_dashboard_text, render_scope_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Primordial operator platform CLI")
    subparsers = parser.add_subparsers(dest="command")

    tick = subparsers.add_parser("tick", help="Run one orchestration tick.")
    tick.add_argument("--max-executions", type=int, default=3)

    repair = subparsers.add_parser("repair", help="Recover stale execution state without running tools by default.")
    repair.add_argument("--tick", action="store_true", help="Run one orchestration tick after repair.")
    repair.add_argument("--max-executions", type=int, default=1)

    run_loop = subparsers.add_parser("run-loop", help="Run repeated orchestration ticks.")
    run_loop.add_argument("--cycles", type=int, default=3)
    run_loop.add_argument("--max-executions", type=int, default=3)

    subparsers.add_parser("show", help="Render a dashboard snapshot to stdout.")
    scope = subparsers.add_parser("scope", help="Show current scope, targets, and assets.")
    scope.add_argument("--json", action="store_true")
    subparsers.add_parser("compact", help="Run one memory compaction cycle.")
    subparsers.add_parser("process-queues", help="Process Notion and Discord queues.")
    subparsers.add_parser("tui", help="Launch the Textual UI or terminal fallback.")
    gui = subparsers.add_parser("gui", help="Launch the web control console.")
    gui.add_argument("--host", default="127.0.0.1")
    gui.add_argument("--port", type=int, default=1337)
    web = subparsers.add_parser("web", help="Launch the HTML5 web control console.")
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=1337)
    stop_server = subparsers.add_parser("stop-server", help="Gracefully stop the web control console.")
    stop_server.add_argument("--host", default="127.0.0.1")
    stop_server.add_argument("--port", type=int, default=1337)
    stop_server.add_argument("--timeout", type=float, default=5.0)
    stop_server.add_argument(
        "--kill",
        action="store_true",
        help="If the HTTP stop endpoint is unavailable, send SIGTERM to the recorded web server PID.",
    )
    doctor = subparsers.add_parser("doctor", help="Check V1 Postgres, pgvector, schema, and runtime health.")
    doctor.add_argument("--json", action="store_true")

    models = subparsers.add_parser("models", help="Manage local model residency and benchmarking.")
    models_subparsers = models.add_subparsers(dest="models_command")
    models_warm = models_subparsers.add_parser("warm", help="Preload configured local model routes into Ollama.")
    models_warm.add_argument("--keep-alive", default="8h")
    models_warm.add_argument("--json", action="store_true")
    models_status = models_subparsers.add_parser("status", help="Show installed Ollama models and role mappings.")
    models_status.add_argument("--json", action="store_true")
    models_set = models_subparsers.add_parser("set-role", help="Set a model for a runtime role.")
    models_set.add_argument("role", choices=list(PrimordialRuntime.MODEL_ROLE_CONFIG))
    models_set.add_argument("model")
    models_set.add_argument("--processor", choices=["gpu", "cpu"])
    models_set.add_argument("--json", action="store_true")
    models_eval = models_subparsers.add_parser(
        "evaluate",
        help="Benchmark installed/local models on safe Primordial code and synthetic PoC-adaptation tasks.",
    )
    models_eval.add_argument("--model", action="append", default=[], help="Model to evaluate. Repeat to compare multiple models.")
    models_eval.add_argument("--limit", type=int, help="Limit auto-selected installed models.")
    models_eval.add_argument("--processor", choices=["gpu", "cpu"], default="cpu")
    models_eval.add_argument("--include-outputs", action="store_true")
    models_eval.add_argument("--providers", default="ollama", help="Comma-separated providers: ollama,lmstudio.")
    models_eval.add_argument("--exhaustive", action="store_true", help="Sweep supported context lengths up to --max-context.")
    models_eval.add_argument("--csv", type=Path, help="Optional CSV artifact path.")
    models_eval.add_argument("--json-out", type=Path, help="Optional detailed JSON artifact path.")
    models_eval.add_argument("--max-context", type=int, default=32768)
    models_eval.add_argument(
        "--context-size",
        type=int,
        action="append",
        help="Specific context length to evaluate. Repeat to compare sizes.",
    )
    models_eval.add_argument(
        "--temperature",
        type=float,
        action="append",
        help="Temperature to evaluate. Repeat to override the default 0.0 and 0.1 sweep.",
    )
    models_eval.add_argument("--judge-model", help="Optional supplemental local judge model name.")
    models_eval.add_argument("--lmstudio-profile", type=Path, help="Optional LM Studio tuning profile JSON path.")
    models_eval.add_argument("--no-lmstudio-profile", action="store_true", help="Disable LM Studio tuning profile loading.")
    models_eval.add_argument(
        "--max-model-minutes",
        type=float,
        default=30.0,
        help="Hard planning cutoff per local model run before recommending Claude/GPT offload.",
    )
    models_eval.add_argument("--json", action="store_true")
    models_tune_lmstudio = models_subparsers.add_parser(
        "tune-lmstudio",
        help="Tune LM Studio load settings at a small context and persist a benchmark profile.",
    )
    models_tune_lmstudio.add_argument("--model", action="append", default=[], help="LM Studio model to tune. Repeat for multiple.")
    models_tune_lmstudio.add_argument("--context", type=int, default=1024)
    models_tune_lmstudio.add_argument("--max-tokens", type=int, default=128)
    models_tune_lmstudio.add_argument("--temperature", type=float, default=0.0)
    models_tune_lmstudio.add_argument("--cpu-reserve-mb", type=int, default=4096)
    models_tune_lmstudio.add_argument("--vram-soft-reserve-mb", type=int, default=128)
    models_tune_lmstudio.add_argument("--timeout", type=int, default=120)
    models_tune_lmstudio.add_argument("--profile-out", type=Path)
    models_tune_lmstudio.add_argument("--json-out", type=Path)
    models_tune_lmstudio.add_argument("--json", action="store_true")

    caido = subparsers.add_parser("caido", help="Inspect Caido integration status.")
    caido_subparsers = caido.add_subparsers(dest="caido_command")
    caido_status = caido_subparsers.add_parser("status", help="Show Caido configuration and optional health.")
    caido_status.add_argument("--check-health", action="store_true")
    caido_status.add_argument("--json", action="store_true")

    skills = subparsers.add_parser("skills", help="List locally loaded runtime skills.")
    skills_subparsers = skills.add_subparsers(dest="skills_command")
    skills_list = skills_subparsers.add_parser("list", help="List loaded skill summaries.")
    skills_list.add_argument("--json", action="store_true")
    skills_list.add_argument("--include-body", action="store_true")

    findings_context = subparsers.add_parser("findings-context", help="Inspect or sync durable local findings context.")
    findings_subparsers = findings_context.add_subparsers(dest="findings_command")
    findings_show = findings_subparsers.add_parser("show", help="Show target findings workspace paths and guidance.")
    findings_show.add_argument("--target")
    findings_show.add_argument("--json", action="store_true")
    findings_sync = findings_subparsers.add_parser("sync", help="Regenerate local Notion export mirrors from runtime state.")
    findings_sync.add_argument("--json", action="store_true")

    rag = subparsers.add_parser("rag", help="Import selected local documents and search cited RAG chunks.")
    rag_subparsers = rag.add_subparsers(dest="rag_command")
    rag_ingest = rag_subparsers.add_parser("ingest", help="Import one selected local document for a scoped target.")
    rag_ingest.add_argument("path")
    rag_ingest.add_argument("--target", required=True, help="Target handle or ID.")
    rag_ingest.add_argument(
        "--corpus-type",
        default="operator_note",
        choices=["operator_note", "cve_advisory", "exploit_note", "htb_writeup"],
        help="How Primordial should treat the imported RAG material.",
    )
    rag_ingest.add_argument("--source-trust", help="Optional source trust label stored with chunks.")
    rag_ingest.add_argument(
        "--hint-policy",
        choices=["advisory", "direct_task_hints", "disabled"],
        help="Whether tagged RAG material may produce planner task hints.",
    )
    rag_ingest.add_argument(
        "--approve-url",
        action="store_true",
        help="Explicitly approve fetching and ingesting an http(s) URL.",
    )
    rag_ingest.add_argument("--no-docling", action="store_true", help="Disable optional Docling conversion.")
    rag_ingest.add_argument("--no-embed", action="store_true", help="Store chunks without creating embeddings.")
    rag_ingest.add_argument("--json", action="store_true")
    rag_search = rag_subparsers.add_parser("search", help="Search imported document chunks for a target.")
    rag_search.add_argument("query", nargs="+")
    rag_search.add_argument("--target", required=True, help="Target handle or ID.")
    rag_search.add_argument("--limit", type=int, default=5)
    rag_search.add_argument(
        "--corpus-type",
        action="append",
        choices=["operator_note", "cve_advisory", "exploit_note", "htb_writeup"],
        help="Filter by corpus type. Repeat for multiple types.",
    )
    rag_search.add_argument("--json", action="store_true")
    rag_cve_search = rag_subparsers.add_parser("cve-search", help="Search CVE advisory and exploit-note RAG chunks.")
    rag_cve_search.add_argument("query", nargs="+")
    rag_cve_search.add_argument("--target", required=True, help="Target handle or ID.")
    rag_cve_search.add_argument("--limit", type=int, default=5)
    rag_cve_search.add_argument("--json", action="store_true")
    rag_hints = rag_subparsers.add_parser("hints", help="Show policy-gated direct task hints from tagged RAG chunks.")
    rag_hints.add_argument("query", nargs="*")
    rag_hints.add_argument("--target", required=True, help="Target handle or ID.")
    rag_hints.add_argument("--limit", type=int, default=8)
    rag_hints.add_argument("--json", action="store_true")

    ask = subparsers.add_parser("ask", help="Ask the bounded operator AI about current Primordial state.")
    ask.add_argument("message", nargs="+")
    ask.add_argument("--target", help="Target handle or target ID to focus the answer.")
    ask.add_argument("--json", action="store_true")

    credentials = subparsers.add_parser("credentials", help="Manage local Notion, Discord, Caido, and known credentials.")
    credentials_subparsers = credentials.add_subparsers(dest="credentials_command")
    credentials_status = credentials_subparsers.add_parser("status", help="Show redacted credential status.")
    credentials_status.add_argument("--json", action="store_true")
    credentials_notion = credentials_subparsers.add_parser("set-notion", help="Set Notion integration credentials.")
    credentials_notion.add_argument("--api-key")
    credentials_notion.add_argument("--parent-page-id")
    credentials_notion.add_argument("--version", default="2022-06-28")
    credentials_discord = credentials_subparsers.add_parser("set-discord", help="Set Discord webhook credentials.")
    credentials_discord.add_argument("--webhook-url")
    credentials_known = credentials_subparsers.add_parser("set-known", help="Set known credentials for credentialed verification.")
    credentials_known.add_argument("--username")
    credentials_known.add_argument("--password")
    credentials_known.add_argument("--domain")
    credentials_lab = credentials_subparsers.add_parser("set-lab", help="Compatibility alias for set-known.")
    credentials_lab.add_argument("--username")
    credentials_lab.add_argument("--password")
    credentials_lab.add_argument("--domain")
    credentials_caido = credentials_subparsers.add_parser("set-caido", help="Set Caido GraphQL credentials.")
    credentials_caido.add_argument("--graphql-url")
    credentials_caido.add_argument("--api-token")
    credentials_clear = credentials_subparsers.add_parser("clear", help="Clear credentials for a service.")
    credentials_clear.add_argument("service", choices=["notion", "discord", "known", "lab", "caido"])

    add_target = subparsers.add_parser("add-target", help="Add or update a single target and its scope assets.")
    add_target.add_argument("handle")
    add_target.add_argument(
        "--profile",
        choices=[item.value for item in ScopeProfile],
        default=ScopeProfile.HACK_THE_BOX.value,
    )
    add_target.add_argument("--display-name")
    add_target.add_argument("--asset", action="append", default=[])
    add_target.add_argument("--out-of-scope", action="store_true")

    remove_target = subparsers.add_parser("remove-target", help="Remove a target and all linked runtime records.")
    remove_target.add_argument("handle")
    remove_target.add_argument(
        "--profile",
        choices=[item.value for item in ScopeProfile],
    )

    import_scope = subparsers.add_parser("import-scope", help="Import a JSON or line-based scope file.")
    import_scope.add_argument("path", type=Path)
    import_scope.add_argument(
        "--profile",
        choices=[item.value for item in ScopeProfile],
        default=ScopeProfile.HACKERONE.value,
    )

    start_session = subparsers.add_parser("start-session", help="Start a new methodology session.")
    start_session.add_argument(
        "--methodology",
        choices=[item.value for item in MethodologyName],
        default=MethodologyName.WEB_APP_CORE.value,
    )
    start_session.add_argument(
        "--profile",
        choices=[item.value for item in ScopeProfile],
        default=ScopeProfile.HACKERONE.value,
    )
    start_session.add_argument("--title", default="Primordial Session")

    approve = subparsers.add_parser("approve", help="Approve pending tasks.")
    approve.add_argument("task_id", nargs="?")
    approve.add_argument("--all-safe", action="store_true", help="Approve queued NEEDS_APPROVAL tasks that current policy now allows.")
    approve.add_argument("--tick", action="store_true", help="Run one orchestration tick after --all-safe approves tasks.")
    approve.add_argument("--limit", type=int, default=200)

    deny = subparsers.add_parser("deny", help="Deny a pending task.")
    deny.add_argument("task_id")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "doctor":
        payload = run_doctor()
        if args.json:
            print(dumps_doctor_json(payload))
        else:
            print(format_doctor_report(payload))
        return 0 if payload.get("ok") else 2
    if args.command == "stop-server":
        return stop_web_console_server(
            host=args.host,
            port=args.port,
            timeout_seconds=args.timeout,
            kill_fallback=args.kill,
        )
    try:
        run_startup_preflight()
        runtime = PrimordialRuntime.from_env()
        runtime.initialize()
    except StartupPreflightError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    try:
        command = args.command or "show"
        if command == "tick":
            report = runtime.run_tick(max_executions=args.max_executions)
            print(report.summary)
            print(render_dashboard_text(runtime))
            return 0
        if command == "repair":
            outcome = runtime.repair_execution_state()
            if args.tick:
                report = runtime.run_tick(max_executions=args.max_executions)
                outcome["tick_summary"] = report.summary
            print(json.dumps(outcome, indent=2, sort_keys=True))
            print(render_dashboard_text(runtime))
            return 0
        if command == "run-loop":
            for _ in range(args.cycles):
                runtime.run_tick(max_executions=args.max_executions)
            print(render_dashboard_text(runtime))
            return 0
        if command == "compact":
            created = runtime.compact_memory()
            print(f"memory_entries_created={created}")
            print(render_dashboard_text(runtime))
            return 0
        if command == "process-queues":
            outcome = runtime.process_external_queues()
            print(outcome)
            print(render_dashboard_text(runtime))
            return 0
        if command == "models":
            models_command = args.models_command or "warm"
            if models_command == "status":
                payload = runtime.models_payload()
                if args.json:
                    print(json.dumps(payload, indent=2, sort_keys=True))
                else:
                    print(_format_models_status(payload))
                return 0
            if models_command == "set-role":
                processors = {args.role: args.processor} if args.processor else None
                payload = runtime.update_model_roles({args.role: args.model}, processors=processors)
                if args.json:
                    print(json.dumps(payload, indent=2, sort_keys=True))
                else:
                    print(_format_models_status(payload))
                return 0
            if models_command == "warm":
                outcome = runtime.warm_model_routes(keep_alive=args.keep_alive)
                if args.json:
                    print(json.dumps(outcome, indent=2, sort_keys=True))
                else:
                    for result in outcome["results"]:
                        status = "ok" if result["ok"] else f"failed: {result['error']}"
                        print(f"{result['route']}: {result['model']} {status}")
                return 0
            if models_command == "evaluate":
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
                if args.json:
                    print(json.dumps(payload, indent=2, sort_keys=True))
                else:
                    print(_format_model_evaluation(payload))
                return 0
            if models_command == "tune-lmstudio":
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
                if args.json:
                    print(json.dumps(payload, indent=2, sort_keys=True))
                else:
                    print(_format_lmstudio_tuning(payload))
                return 0
        if command == "credentials":
            credentials_command = args.credentials_command or "status"
            if credentials_command == "status":
                payload = runtime.credentials_payload()
                if getattr(args, "json", False):
                    print(json.dumps(payload, indent=2, sort_keys=True))
                else:
                    print(_format_credentials_status(payload))
                return 0
            if credentials_command == "set-notion":
                api_key = args.api_key if args.api_key is not None else getpass.getpass("Notion API key: ").strip()
                parent_page_id = (
                    args.parent_page_id
                    if args.parent_page_id is not None
                    else input("Notion parent page ID: ").strip()
                )
                runtime.set_notion_credentials(
                    api_key=api_key,
                    parent_page_id=parent_page_id,
                    version=args.version,
                )
                print(_format_credentials_status(runtime.credentials_payload()))
                return 0
            if credentials_command == "set-discord":
                webhook_url = (
                    args.webhook_url
                    if args.webhook_url is not None
                    else getpass.getpass("Discord webhook URL: ").strip()
                )
                runtime.set_discord_credentials(webhook_url=webhook_url)
                print(_format_credentials_status(runtime.credentials_payload()))
                return 0
            if credentials_command in {"set-known", "set-lab"}:
                username = args.username if args.username is not None else input("Known username: ").strip()
                password = args.password if args.password is not None else getpass.getpass("Known password: ").strip()
                domain = args.domain if args.domain is not None else input("Known domain (optional): ").strip()
                runtime.set_known_credentials(username=username, password=password, domain=domain)
                print(_format_credentials_status(runtime.credentials_payload()))
                return 0
            if credentials_command == "set-caido":
                default_graphql_url = CaidoIntegrationService.DEFAULT_GRAPHQL_URL
                graphql_url = (
                    args.graphql_url
                    if args.graphql_url is not None
                    else input(f"Caido GraphQL URL [{default_graphql_url}]: ").strip()
                )
                api_token = (
                    args.api_token
                    if args.api_token is not None
                    else getpass.getpass("Caido API token: ").strip()
                )
                runtime.set_caido_credentials(graphql_url=graphql_url, api_token=api_token)
                print(_format_credentials_status(runtime.credentials_payload()))
                return 0
            if credentials_command == "clear":
                runtime.clear_credentials(args.service)
                print(_format_credentials_status(runtime.credentials_payload()))
                return 0
        if command == "caido":
            caido_command = args.caido_command or "status"
            if caido_command == "status":
                payload = runtime.caido_status_payload(check_health=args.check_health)
                if args.json:
                    print(json.dumps(payload, indent=2, sort_keys=True))
                else:
                    print(_format_caido_status(payload))
                return 0
        if command == "skills":
            skills_command = args.skills_command or "list"
            if skills_command == "list":
                payload = runtime.skills_payload(include_body=args.include_body)
                if args.json:
                    print(json.dumps(payload, indent=2, sort_keys=True))
                else:
                    for skill in payload["skills"]:
                        print(f"{skill['id']}: {skill['summary']}")
                return 0
        if command == "findings-context":
            findings_command = args.findings_command or "show"
            if findings_command == "show":
                payload = runtime.findings_context_payload(target=args.target, include_guidance=True)
                if args.json:
                    print(json.dumps(payload, indent=2, sort_keys=True))
                else:
                    print(_format_findings_context(payload))
                return 0
            if findings_command == "sync":
                payload = runtime.sync_findings_context_exports()
                if args.json:
                    print(json.dumps(payload, indent=2, sort_keys=True))
                else:
                    for item in payload["synced"]:
                        workspace = item["workspace"]
                        print(f"{item['target']}: {workspace['notion_export_path']}")
                return 0
        if command == "rag":
            rag_command = args.rag_command
            if rag_command is None:
                parser.error("rag requires a subcommand: ingest, search, cve-search, or hints")
            if rag_command == "ingest":
                payload = runtime.rag_ingest_document(
                    args.path,
                    target=args.target,
                    use_docling=not args.no_docling,
                    embed=not args.no_embed,
                    corpus_type=args.corpus_type,
                    source_trust=args.source_trust,
                    hint_policy=args.hint_policy,
                    allow_remote_url=args.approve_url,
                )
                if args.json:
                    print(json.dumps(payload, indent=2, sort_keys=True))
                else:
                    print(_format_rag_ingest(payload))
                return 0
            if rag_command == "search":
                payload = runtime.rag_search(
                    " ".join(args.query),
                    target=args.target,
                    limit=args.limit,
                    corpus_types=args.corpus_type,
                )
                if args.json:
                    print(json.dumps(payload, indent=2, sort_keys=True))
                else:
                    print(_format_rag_search(payload))
                return 0
            if rag_command == "cve-search":
                payload = runtime.rag_cve_search(" ".join(args.query), target=args.target, limit=args.limit)
                if args.json:
                    print(json.dumps(payload, indent=2, sort_keys=True))
                else:
                    print(_format_rag_search(payload))
                return 0
            if rag_command == "hints":
                payload = runtime.rag_hints(" ".join(args.query), target=args.target, limit=args.limit)
                if args.json:
                    print(json.dumps(payload, indent=2, sort_keys=True))
                else:
                    print(_format_rag_hints(payload))
                return 0
        if command == "ask":
            payload = runtime.ask_operator_ai(" ".join(args.message), target=args.target)
            if args.json:
                print(json.dumps(payload, indent=2, sort_keys=True))
            else:
                print(f"model={payload['model']}")
                if not payload["ok"]:
                    print(f"error={payload['error']}")
                    return 1
                print(payload["answer"]["body"])
            return 0
        if command == "import-scope":
            runtime.import_scope(args.path, ScopeProfile(args.profile))
            print(render_dashboard_text(runtime))
            return 0
        if command == "add-target":
            runtime.register_target(
                handle=args.handle,
                display_name=args.display_name,
                profile=ScopeProfile(args.profile),
                assets=args.asset or [args.handle],
                in_scope=not args.out_of_scope,
            )
            print(render_scope_text(runtime, as_json=args.json if hasattr(args, "json") else False))
            return 0
        if command == "remove-target":
            outcome = runtime.remove_target(
                args.handle,
                ScopeProfile(args.profile) if args.profile else None,
            )
            print(outcome)
            print(render_scope_text(runtime))
            return 0
        if command == "start-session":
            runtime.start_session(
                methodology=MethodologyName(args.methodology),
                profile=ScopeProfile(args.profile),
                title=args.title,
            )
            print(render_dashboard_text(runtime))
            return 0
        if command == "scope":
            print(render_scope_text(runtime, as_json=args.json))
            return 0
        if command == "approve":
            if args.all_safe:
                outcome = runtime.approve_all_safe_tasks(limit=args.limit, run_tick=args.tick)
                print(json.dumps(outcome, indent=2, sort_keys=True))
                print(render_dashboard_text(runtime))
                return 0
            if not args.task_id:
                parser.error("approve requires task_id unless --all-safe is used")
            runtime.approve_task(args.task_id, approved=True)
            print(render_dashboard_text(runtime))
            return 0
        if command == "deny":
            runtime.approve_task(args.task_id, approved=False)
            print(render_dashboard_text(runtime))
            return 0
        if command == "tui":
            return launch_tui(runtime)
        if command in {"gui", "web"}:
            serve_web_console(runtime, host=args.host, port=args.port)
            return 0

        print(render_dashboard_text(runtime))
        return 0
    finally:
        runtime.shutdown()


def stop_web_console_server(
    *,
    host: str = "127.0.0.1",
    port: int = 1337,
    timeout_seconds: float = 5.0,
    kill_fallback: bool = False,
) -> int:
    url = f"http://{host}:{port}/api/server/stop"
    body = json.dumps({"confirm": "stop"}).encode("utf-8")
    request = urlrequest.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlrequest.urlopen(request, timeout=max(0.5, timeout_seconds)) as response:
            response.read()
            if 200 <= response.status < 300:
                print(f"requested graceful stop for Primordial web console on {host}:{port}")
                return 0
    except (OSError, urlerror.URLError, TimeoutError) as exc:
        if not kill_fallback:
            print(f"web console stop endpoint unavailable: {exc}", file=sys.stderr)
            print("rerun with --kill to send SIGTERM to the recorded server PID", file=sys.stderr)
            return 2

    root = resolve_project_root()
    load_project_env(root)
    runtime_dir = Path(os.getenv("PRIMORDIAL_RUNTIME_DIR", root / "runtime")).resolve()
    pid_path = runtime_dir / f"primordial-web-{port}.pid"
    try:
        pid = int(pid_path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError) as exc:
        print(f"could not read web console PID from {pid_path}: {exc}", file=sys.stderr)
        return 2

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        print(f"recorded web console PID {pid} is not running")
        return 0
    except OSError as exc:
        print(f"failed to stop web console PID {pid}: {exc}", file=sys.stderr)
        return 2

    deadline = time.monotonic() + max(0.5, timeout_seconds)
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            print(f"stopped Primordial web console PID {pid}")
            return 0
        time.sleep(0.1)
    print(f"sent SIGTERM to Primordial web console PID {pid}; process is still exiting")
    return 0


def _format_credentials_status(payload: dict[str, object]) -> str:
    lines = [f"credential_store={payload.get('path')}"]
    services = payload.get("services", {})
    if not isinstance(services, dict):
        return "\n".join(lines)
    for service, fields in services.items():
        lines.append(str(service))
        if not isinstance(fields, dict):
            continue
        for key, status in fields.items():
            if not isinstance(status, dict):
                continue
            configured = "configured" if status.get("configured") else "missing"
            source = status.get("source", "missing")
            hint = status.get("hint") or ""
            suffix = f" {hint}" if hint else ""
            lines.append(f"  {key}: {configured} ({source}){suffix}")
    return "\n".join(lines)


def _format_caido_status(payload: dict[str, object]) -> str:
    lines = [
        f"configured={payload.get('configured')}",
        f"ok={payload.get('ok')}",
        f"graphql_url={payload.get('graphql_url') or 'missing'}",
    ]
    if payload.get("error"):
        lines.append(f"error={payload['error']}")
    if payload.get("status_code"):
        lines.append(f"status_code={payload['status_code']}")
    return "\n".join(lines)


def _format_findings_context(payload: dict[str, object]) -> str:
    if "workspace" in payload:
        workspace = payload["workspace"]
        if not isinstance(workspace, dict):
            return ""
        lines = [f"{key}={value}" for key, value in workspace.items() if key != "guidance"]
        if workspace.get("guidance"):
            lines.append("\n" + str(workspace["guidance"]))
        return "\n".join(lines)
    lines = [
        f"findings_dir={payload.get('findings_dir')}",
        f"notion_exports_dir={payload.get('notion_exports_dir')}",
    ]
    for item in payload.get("targets", []):
        if isinstance(item, dict):
            target = item.get("target", {})
            workspace = item.get("workspace", {})
            if isinstance(target, dict) and isinstance(workspace, dict):
                lines.append(f"{target.get('handle')}: {workspace.get('target_dir')}")
    return "\n".join(lines)


def _format_rag_ingest(payload: dict[str, object]) -> str:
    evidence = payload.get("evidence", {})
    evidence_id = evidence.get("id") if isinstance(evidence, dict) else "none"
    lines = [
        f"source={payload.get('source_path')}",
        f"source_ref={payload.get('source_ref')}",
        f"sha256={payload.get('source_sha256')}",
        f"corpus_type={payload.get('corpus_type')}",
        f"source_trust={payload.get('source_trust')}",
        f"hint_policy={payload.get('hint_policy')}",
        f"converter={payload.get('converter')}",
        f"evidence={evidence_id}",
        f"chunks={payload.get('chunk_count')}",
        f"embeddings={payload.get('embedding_count')} model={payload.get('embedding_model') or 'none'}",
        f"redactions={payload.get('redaction_count')}",
    ]
    artifacts = payload.get("artifacts", [])
    if isinstance(artifacts, list):
        for artifact in artifacts:
            if isinstance(artifact, dict):
                lines.append(f"artifact={artifact.get('id')} {artifact.get('path')}")
    return "\n".join(lines)


def _format_rag_search(payload: dict[str, object]) -> str:
    lines = [f"query={payload.get('query')}"]
    results = payload.get("results", [])
    if not isinstance(results, list) or not results:
        lines.append("No RAG chunks matched.")
        return "\n".join(lines)
    for result in results:
        if not isinstance(result, dict):
            continue
        evidence_refs = result.get("evidence_refs", [])
        evidence = ",".join(str(item) for item in evidence_refs) if isinstance(evidence_refs, list) else ""
        text = str(result.get("text") or "").replace("\n", " ")
        if len(text) > 220:
            text = text[:220].rstrip() + "..."
        classification = result.get("applicability_classification")
        classification_part = f" applicability={classification}" if classification else ""
        lines.append(
            f"{result.get('chunk_id')} score={result.get('score')} "
            f"evidence={evidence or 'none'}{classification_part} title={result.get('title')}"
        )
        lines.append(f"  {text}")
    return "\n".join(lines)


def _format_rag_hints(payload: dict[str, object]) -> str:
    lines = [f"query={payload.get('query')}"]
    actions = payload.get("candidate_actions", [])
    hints = payload.get("hints", {})
    if isinstance(actions, list) and actions:
        lines.append("Accepted candidate actions:")
        for action in actions:
            if not isinstance(action, dict):
                continue
            metadata = action.get("metadata", {})
            chunk_ids = metadata.get("supporting_rag_chunk_ids", []) if isinstance(metadata, dict) else []
            chunk_text = ",".join(str(item) for item in chunk_ids) if isinstance(chunk_ids, list) else ""
            classification = metadata.get("rag_applicability_classification") if isinstance(metadata, dict) else ""
            lines.append(
                f"- {action.get('kind')} {action.get('title')} "
                f"classification={classification or 'unknown'} rag={chunk_text or 'none'}"
            )
    else:
        lines.append("No RAG task hints were admitted.")
    rejected = hints.get("rejected", []) if isinstance(hints, dict) else []
    if isinstance(rejected, list) and rejected:
        lines.append("Rejected hints:")
        for item in rejected[:8]:
            if isinstance(item, dict):
                lines.append(f"- {item.get('title')} ({item.get('reason')})")
    return "\n".join(lines)


def _format_models_status(payload: dict[str, object]) -> str:
    ollama = payload.get("ollama", {})
    lines = []
    if isinstance(ollama, dict):
        lines.append(f"ollama={ollama.get('base_url')} ok={ollama.get('ok')}")
        if ollama.get("error"):
            lines.append(f"error={ollama['error']}")
    lines.append("roles:")
    for role in payload.get("roles", []):
        if not isinstance(role, dict):
            continue
        num_gpu = role.get("num_gpu")
        device = role.get("processor")
        gpu_note = "num_gpu=0" if num_gpu == 0 else "default GPU runtime"
        lines.append(
            f"  {role.get('role')}: {role.get('selected_model')} "
            f"({role.get('label')}, {device}, {gpu_note}, default={role.get('default_model')})"
        )
    available = payload.get("available_models", [])
    lines.append(f"available_models={', '.join(available) if isinstance(available, list) else ''}")
    return "\n".join(lines)


def _format_model_evaluation(payload: dict[str, object]) -> str:
    lines = ["Model evaluation:"]
    providers = payload.get("providers", [])
    if isinstance(providers, list) and providers:
        lines.append(f"providers={','.join(str(item) for item in providers)}")
    eval_config = payload.get("eval_config", {})
    if isinstance(eval_config, dict) and eval_config.get("temperatures"):
        temperatures = eval_config.get("temperatures", [])
        if isinstance(temperatures, list):
            lines.append(f"temperatures={','.join(str(item) for item in temperatures)}")
    artifacts = payload.get("artifacts", {})
    if isinstance(artifacts, dict) and artifacts:
        if artifacts.get("csv_path"):
            lines.append(f"csv={artifacts.get('csv_path')}")
        if artifacts.get("json_path"):
            lines.append(f"json={artifacts.get('json_path')}")
    recommendations = payload.get("recommendations", {})
    if isinstance(recommendations, dict) and recommendations:
        lines.append("recommendations:")
        for role in ("local_fast", "local_deep", "local_code", "local_compact"):
            if role in recommendations:
                lines.append(f"  {role}: {recommendations[role]}")
    suggestions = payload.get("role_suggestions", [])
    if isinstance(suggestions, list) and suggestions:
        lines.append("role suggestions:")
        for role in ("local_fast", "local_deep", "local_code", "local_compact"):
            role_items = [
                item
                for item in suggestions
                if isinstance(item, dict)
                and item.get("role") == role
                and item.get("status") in {"recommended", "candidate"}
            ]
            for item in sorted(role_items, key=lambda entry: (entry.get("rank") or 99, str(entry.get("model") or "")))[:2]:
                confidence = item.get("confidence")
                status = item.get("status")
                model = item.get("recommendation_id") or item.get("model")
                lines.append(f"  {role}: {model} rank={item.get('rank')} confidence={confidence} status={status}")
                reasons = item.get("reasons", [])
                warnings = item.get("warnings", [])
                detail = []
                if isinstance(reasons, list) and reasons:
                    detail.append("; ".join(str(reason) for reason in reasons[:2]))
                if isinstance(warnings, list) and warnings:
                    detail.append("warnings: " + "; ".join(str(warning) for warning in warnings[:2]))
                if detail:
                    lines.append(f"    {' | '.join(detail)}")
    aggregate_rows = payload.get("aggregate_rows", [])
    if isinstance(aggregate_rows, list) and aggregate_rows:
        lines.append("models:")
        for row in aggregate_rows:
            if not isinstance(row, dict):
                continue
            score = row.get("aggregate_score")
            latency = row.get("avg_latency_sec")
            speed = row.get("avg_tokens_sec")
            role = row.get("role_recommendation") or "-"
            lines.append(
                f"  {row.get('provider')} {row.get('model')} roles={role} "
                f"score={score} latency={latency or '-'}s tok/s={speed or '-'} "
                f"ctx={row.get('best_context_length') or '-'}"
            )
            tags = row.get("identified_tags")
            if tags:
                lines.append(f"    tags: {tags}")
            notes = row.get("notes")
            if notes:
                lines.append(f"    notes: {notes}")
        return "\n".join(lines)
    lines.append("results:")
    for item in payload.get("results", []):
        if not isinstance(item, dict) or item.get("stage") not in {None, "eval"}:
            continue
        status = "PASS" if item.get("passed") else "FAIL"
        elapsed = item.get("elapsed_seconds")
        elapsed_text = f" elapsed={elapsed:.2f}s" if isinstance(elapsed, (int, float)) else ""
        provider = item.get("provider") or "ollama"
        context = f" ctx={item.get('context_length')}" if item.get("context_length") else ""
        temperature = f" temp={item.get('temperature')}" if item.get("temperature") is not None else ""
        lines.append(
            f"  {status} {provider} {item.get('model')} {item.get('case_id')} "
            f"score={item.get('score')}{elapsed_text}{context}{temperature}"
        )
        reasons = item.get("reasons", [])
        if isinstance(reasons, list) and reasons:
            lines.append(f"    reasons: {'; '.join(str(reason) for reason in reasons[:3])}")
    return "\n".join(lines)


def _format_lmstudio_tuning(payload: dict[str, object]) -> str:
    lines = ["LM Studio tuning:"]
    lines.append(f"status={payload.get('status')}")
    error = payload.get("error")
    if error:
        lines.append(f"error={error}")
    artifacts = payload.get("artifacts", {})
    if isinstance(artifacts, dict):
        if artifacts.get("profile_path"):
            lines.append(f"profile={artifacts.get('profile_path')}")
        if artifacts.get("json_path"):
            lines.append(f"json={artifacts.get('json_path')}")
    warnings = payload.get("warnings", [])
    if isinstance(warnings, list) and warnings:
        lines.append("warnings:")
        for warning in warnings[:6]:
            lines.append(f"  {warning}")
    models = payload.get("models", {})
    if isinstance(models, dict) and models:
        lines.append("models:")
        emitted: set[str] = set()
        for key, profile in sorted(models.items()):
            model = str(key)
            if model.startswith("lmstudio:"):
                continue
            if model in emitted or not isinstance(profile, dict):
                continue
            emitted.add(model)
            config = profile.get("best_config", {})
            speed = profile.get("tokens_per_second")
            lines.append(f"  {model}: tok/s={speed} config={json.dumps(config, sort_keys=True)}")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
