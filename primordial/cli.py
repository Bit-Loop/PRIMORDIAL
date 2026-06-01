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
from primordial.cli_handlers import CliRuntimeCallbacks, run_runtime_command
from primordial.cli_formatters import (
    _format_attck_preprocess,
    _format_caido_status,
    _format_credentials_status,
    _format_findings_context,
    _format_lmstudio_tuning,
    _format_model_evaluation,
    _format_models_status,
    _format_rag_chunk,
    _format_rag_hints,
    _format_rag_import,
    _format_rag_ingest,
    _format_rag_search,
    _format_rag_status,
    _format_rag_vuln_hints,
    _format_rag_vuln_sync,
)
from primordial.cli_parser import build_cli_parser
from primordial.core.doctor import dumps_doctor_json, format_doctor_report, run_doctor
from primordial.core.domain.enums import MethodologyName, ScopeProfile
from primordial.core.local_runtime import load_project_env, resolve_project_root
from primordial.core.rag.attack import AttackIndexPreprocessor
from primordial.core.startup import StartupPreflightError, run_startup_preflight
from primordial.core.web import serve_web_console
from primordial.ui.textual_app import launch_tui, render_dashboard_text, render_scope_text


def build_parser() -> argparse.ArgumentParser:
    return build_cli_parser(
        model_roles=PrimordialRuntime.MODEL_ROLE_CONFIG,
        scope_profiles=[item.value for item in ScopeProfile],
        methodologies=[item.value for item in MethodologyName],
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    pre_runtime_result = _run_pre_runtime_command(args)
    if pre_runtime_result is not None:
        return pre_runtime_result
    try:
        run_startup_preflight()
        runtime = PrimordialRuntime.from_env()
        runtime.initialize()
    except StartupPreflightError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    try:
        return run_runtime_command(args, parser, runtime, _runtime_callbacks())
    finally:
        runtime.shutdown()


def _run_pre_runtime_command(args: argparse.Namespace) -> int | None:
    if args.command == "doctor":
        return _run_doctor_command(args)
    if args.command == "stop-server":
        return stop_web_console_server(
            host=args.host,
            port=args.port,
            timeout_seconds=args.timeout,
            kill_fallback=args.kill,
        )
    if args.command == "rag" and args.rag_command == "preprocess-attck":
        return _run_attck_preprocess_command(args)
    return None


def _run_doctor_command(args: argparse.Namespace) -> int:
    payload = run_doctor()
    if args.json:
        print(dumps_doctor_json(payload))
    else:
        print(format_doctor_report(payload))
    return 0 if payload.get("ok") else 2


def _run_attck_preprocess_command(args: argparse.Namespace) -> int:
    project_root = resolve_project_root()
    load_project_env(project_root)
    source_dir = _project_path(project_root, args.source_dir)
    output_root = Path(args.out_dir) if args.out_dir else project_root / "runtime" / "artifacts" / "rag"
    if not output_root.is_absolute():
        output_root = project_root / output_root
    payload = AttackIndexPreprocessor().preprocess(source_dir=source_dir, output_root=output_root)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(_format_attck_preprocess(payload))
    return 0


def _project_path(project_root: Path, raw_path: str) -> Path:
    path = Path(raw_path)
    return path if path.is_absolute() else project_root / path


def _runtime_callbacks() -> CliRuntimeCallbacks:
    return CliRuntimeCallbacks(
        format_models_status=_format_models_status,
        format_model_evaluation=_format_model_evaluation,
        format_lmstudio_tuning=_format_lmstudio_tuning,
        format_credentials_status=_format_credentials_status,
        format_caido_status=_format_caido_status,
        format_findings_context=_format_findings_context,
        format_rag_status=_format_rag_status,
        format_rag_import=_format_rag_import,
        format_rag_chunk=_format_rag_chunk,
        format_rag_ingest=_format_rag_ingest,
        format_rag_search=_format_rag_search,
        format_rag_hints=_format_rag_hints,
        format_rag_vuln_hints=_format_rag_vuln_hints,
        format_rag_vuln_sync=_format_rag_vuln_sync,
        render_dashboard=render_dashboard_text,
        render_scope=render_scope_text,
        launch_tui=launch_tui,
        serve_web_console=serve_web_console,
        prompt=input,
        secret_prompt=getpass.getpass,
        default_caido_graphql_url=CaidoIntegrationService.DEFAULT_GRAPHQL_URL,
    )


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



if __name__ == "__main__":
    raise SystemExit(main())
