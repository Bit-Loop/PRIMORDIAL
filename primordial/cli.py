from __future__ import annotations

import argparse
import getpass
import json
from pathlib import Path
import sys

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from primordial.app.runtime import PrimordialRuntime
from primordial.core.domain.enums import MethodologyName, ScopeProfile
from primordial.core.web import serve_web_console
from primordial.ui.textual_app import launch_tui, render_dashboard_text, render_scope_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Primordial operator platform CLI")
    subparsers = parser.add_subparsers(dest="command")

    tick = subparsers.add_parser("tick", help="Run one orchestration tick.")
    tick.add_argument("--max-executions", type=int, default=3)

    run_loop = subparsers.add_parser("run-loop", help="Run repeated orchestration ticks.")
    run_loop.add_argument("--cycles", type=int, default=3)
    run_loop.add_argument("--max-executions", type=int, default=3)

    subparsers.add_parser("show", help="Render a dashboard snapshot to stdout.")
    scope = subparsers.add_parser("scope", help="Show current scope, targets, and assets.")
    scope.add_argument("--json", action="store_true")
    subparsers.add_parser("compact", help="Run one memory compaction cycle.")
    subparsers.add_parser("process-queues", help="Process Notion and Discord queues.")
    subparsers.add_parser("tui", help="Launch the Textual UI or terminal fallback.")
    subparsers.add_parser("gui", help="Launch the local desktop launcher.")
    web = subparsers.add_parser("web", help="Launch the HTML5 web control console.")
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=1337)

    models = subparsers.add_parser("models", help="Manage local Ollama model residency.")
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
        help="Benchmark installed/local models on safe Primordial code and mock PoC-adaptation tasks.",
    )
    models_eval.add_argument("--model", action="append", default=[], help="Model to evaluate. Repeat to compare multiple models.")
    models_eval.add_argument("--limit", type=int, help="Limit auto-selected installed models.")
    models_eval.add_argument("--processor", choices=["gpu", "cpu"], default="cpu")
    models_eval.add_argument("--include-outputs", action="store_true")
    models_eval.add_argument("--json", action="store_true")

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

    ask = subparsers.add_parser("ask", help="Ask the bounded operator AI about current Primordial state.")
    ask.add_argument("message", nargs="+")
    ask.add_argument("--target", help="Target handle or target ID to focus the answer.")
    ask.add_argument("--json", action="store_true")

    credentials = subparsers.add_parser("credentials", help="Manage local Notion, Discord, Caido, and lab credentials.")
    credentials_subparsers = credentials.add_subparsers(dest="credentials_command")
    credentials_status = credentials_subparsers.add_parser("status", help="Show redacted credential status.")
    credentials_status.add_argument("--json", action="store_true")
    credentials_notion = credentials_subparsers.add_parser("set-notion", help="Set Notion integration credentials.")
    credentials_notion.add_argument("--api-key")
    credentials_notion.add_argument("--parent-page-id")
    credentials_notion.add_argument("--version", default="2022-06-28")
    credentials_discord = credentials_subparsers.add_parser("set-discord", help="Set Discord webhook credentials.")
    credentials_discord.add_argument("--webhook-url")
    credentials_lab = credentials_subparsers.add_parser("set-lab", help="Set HTB/lab credentials for credentialed verification.")
    credentials_lab.add_argument("--username")
    credentials_lab.add_argument("--password")
    credentials_lab.add_argument("--domain")
    credentials_caido = credentials_subparsers.add_parser("set-caido", help="Set Caido GraphQL credentials.")
    credentials_caido.add_argument("--graphql-url")
    credentials_caido.add_argument("--api-token")
    credentials_clear = credentials_subparsers.add_parser("clear", help="Clear credentials for a service.")
    credentials_clear.add_argument("service", choices=["notion", "discord", "lab", "caido"])

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

    approve = subparsers.add_parser("approve", help="Approve a pending task.")
    approve.add_argument("task_id")

    deny = subparsers.add_parser("deny", help="Deny a pending task.")
    deny.add_argument("task_id")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    runtime = PrimordialRuntime.from_env()
    runtime.initialize()
    try:
        command = args.command or "show"
        if command == "tick":
            report = runtime.run_tick(max_executions=args.max_executions)
            print(report.summary)
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
                )
                if args.json:
                    print(json.dumps(payload, indent=2, sort_keys=True))
                else:
                    print(_format_model_evaluation(payload))
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
            if credentials_command == "set-lab":
                username = args.username if args.username is not None else input("Lab username: ").strip()
                password = args.password if args.password is not None else getpass.getpass("Lab password: ").strip()
                domain = args.domain if args.domain is not None else input("Lab domain (optional): ").strip()
                runtime.set_lab_credentials(username=username, password=password, domain=domain)
                print(_format_credentials_status(runtime.credentials_payload()))
                return 0
            if credentials_command == "set-caido":
                graphql_url = (
                    args.graphql_url
                    if args.graphql_url is not None
                    else input("Caido GraphQL URL: ").strip()
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
            runtime.approve_task(args.task_id, approved=True)
            print(render_dashboard_text(runtime))
            return 0
        if command == "deny":
            runtime.approve_task(args.task_id, approved=False)
            print(render_dashboard_text(runtime))
            return 0
        if command == "tui":
            return launch_tui(runtime)
        if command == "gui":
            from primordial.gui.launcher import launch_local_gui

            return launch_local_gui(runtime)
        if command == "web":
            serve_web_console(runtime, host=args.host, port=args.port)
            return 0

        print(render_dashboard_text(runtime))
        return 0
    finally:
        runtime.shutdown()


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
    recommendations = payload.get("recommendations", {})
    if isinstance(recommendations, dict) and recommendations:
        lines.append("recommendations:")
        for category, model in sorted(recommendations.items()):
            lines.append(f"  {category}: {model}")
    lines.append("results:")
    for item in payload.get("results", []):
        if not isinstance(item, dict):
            continue
        status = "PASS" if item.get("passed") else "FAIL"
        elapsed = item.get("elapsed_seconds")
        elapsed_text = f" elapsed={elapsed:.2f}s" if isinstance(elapsed, (int, float)) else ""
        lines.append(
            f"  {status} {item.get('model')} {item.get('case_id')} "
            f"score={item.get('score')}{elapsed_text}"
        )
        reasons = item.get("reasons", [])
        if isinstance(reasons, list) and reasons:
            lines.append(f"    reasons: {'; '.join(str(reason) for reason in reasons[:3])}")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
