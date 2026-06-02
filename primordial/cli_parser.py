from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable


def build_cli_parser(
    *,
    model_roles: Iterable[str],
    scope_profiles: Iterable[str],
    methodologies: Iterable[str],
) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Primordial operator platform CLI")
    subparsers = parser.add_subparsers(dest="command")
    _add_core_commands(subparsers)
    _add_model_commands(subparsers, model_roles)
    _add_adapter_catalog_commands(subparsers)
    _add_rag_commands(subparsers)
    _add_operator_commands(subparsers, scope_profiles, methodologies)
    return parser


def _add_core_commands(subparsers: argparse._SubParsersAction) -> None:
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
    _add_web_commands(subparsers)
    doctor = subparsers.add_parser("doctor", help="Check V1 Postgres, pgvector, schema, and runtime health.")
    doctor.add_argument("--json", action="store_true")


def _add_web_commands(subparsers: argparse._SubParsersAction) -> None:
    for command, help_text in (
        ("gui", "Launch the web control console."),
        ("web", "Launch the HTML5 web control console."),
    ):
        parser = subparsers.add_parser(command, help=help_text)
        parser.add_argument("--host", default="127.0.0.1")
        parser.add_argument("--port", type=int, default=1337)
    stop_server = subparsers.add_parser("stop-server", help="Gracefully stop the web control console.")
    stop_server.add_argument("--host", default="127.0.0.1")
    stop_server.add_argument("--port", type=int, default=1337)
    stop_server.add_argument("--timeout", type=float, default=5.0)
    stop_server.add_argument(
        "--kill",
        action="store_true",
        help="If the HTTP stop endpoint is unavailable, send SIGTERM to the recorded web server PID.",
    )


def _add_model_commands(subparsers: argparse._SubParsersAction, model_roles: Iterable[str]) -> None:
    models = subparsers.add_parser("models", help="Manage local model residency and benchmarking.")
    model_subparsers = models.add_subparsers(dest="models_command")
    warm = model_subparsers.add_parser("warm", help="Preload configured local model routes into Ollama.")
    warm.add_argument("--keep-alive", default="8h")
    warm.add_argument("--json", action="store_true")
    status = model_subparsers.add_parser("status", help="Show installed Ollama models and role mappings.")
    status.add_argument("--json", action="store_true")
    set_role = model_subparsers.add_parser("set-role", help="Set a model for a runtime role.")
    set_role.add_argument("role", choices=list(model_roles))
    set_role.add_argument("model")
    set_role.add_argument("--processor", choices=["gpu", "cpu"])
    set_role.add_argument("--json", action="store_true")
    _add_model_evaluate_command(model_subparsers)
    _add_model_tune_lmstudio_command(model_subparsers)


def _add_model_evaluate_command(model_subparsers: argparse._SubParsersAction) -> None:
    evaluate = model_subparsers.add_parser(
        "evaluate",
        help="Benchmark installed/local models on safe Primordial code and synthetic PoC-adaptation tasks.",
    )
    evaluate.add_argument("--model", action="append", default=[], help="Model to evaluate. Repeat to compare multiple models.")
    evaluate.add_argument("--limit", type=int, help="Limit auto-selected installed models.")
    evaluate.add_argument("--processor", choices=["gpu", "cpu"], default="cpu")
    evaluate.add_argument("--include-outputs", action="store_true")
    evaluate.add_argument("--providers", default="ollama", help="Comma-separated providers: ollama,lmstudio.")
    evaluate.add_argument("--exhaustive", action="store_true", help="Sweep supported context lengths up to --max-context.")
    evaluate.add_argument("--csv", type=Path, help="Optional CSV artifact path.")
    evaluate.add_argument("--json-out", type=Path, help="Optional detailed JSON artifact path.")
    evaluate.add_argument("--max-context", type=int, default=32768)
    evaluate.add_argument("--context-size", type=int, action="append", help="Specific context length to evaluate. Repeat to compare sizes.")
    evaluate.add_argument("--temperature", type=float, action="append", help="Temperature to evaluate. Repeat to override the default 0.0 and 0.1 sweep.")
    evaluate.add_argument("--judge-model", help="Optional supplemental local judge model name.")
    evaluate.add_argument("--lmstudio-profile", type=Path, help="Optional LM Studio tuning profile JSON path.")
    evaluate.add_argument("--no-lmstudio-profile", action="store_true", help="Disable LM Studio tuning profile loading.")
    evaluate.add_argument("--max-model-minutes", type=float, default=30.0, help="Hard planning cutoff per local model run before recommending Claude/GPT offload.")
    evaluate.add_argument("--json", action="store_true")


def _add_model_tune_lmstudio_command(model_subparsers: argparse._SubParsersAction) -> None:
    tune = model_subparsers.add_parser(
        "tune-lmstudio",
        help="Tune LM Studio load settings at a small context and persist a benchmark profile.",
    )
    tune.add_argument("--model", action="append", default=[], help="LM Studio model to tune. Repeat for multiple.")
    tune.add_argument("--context", type=int, default=1024)
    tune.add_argument("--max-tokens", type=int, default=128)
    tune.add_argument("--temperature", type=float, default=0.0)
    tune.add_argument("--cpu-reserve-mb", type=int, default=4096)
    tune.add_argument("--vram-soft-reserve-mb", type=int, default=128)
    tune.add_argument("--timeout", type=int, default=120)
    tune.add_argument("--profile-out", type=Path)
    tune.add_argument("--json-out", type=Path)
    tune.add_argument("--json", action="store_true")


def _add_adapter_catalog_commands(subparsers: argparse._SubParsersAction) -> None:
    caido = subparsers.add_parser("caido", help="Inspect Caido integration status.")
    caido_status = caido.add_subparsers(dest="caido_command").add_parser("status", help="Show Caido configuration and optional health.")
    caido_status.add_argument("--check-health", action="store_true")
    caido_status.add_argument("--json", action="store_true")
    skills = subparsers.add_parser("skills", help="List locally loaded runtime skills.")
    skills_list = skills.add_subparsers(dest="skills_command").add_parser("list", help="List loaded skill summaries.")
    skills_list.add_argument("--json", action="store_true")
    skills_list.add_argument("--include-body", action="store_true")
    findings = subparsers.add_parser("findings-context", help="Inspect or sync durable local findings context.")
    findings_subparsers = findings.add_subparsers(dest="findings_command")
    show = findings_subparsers.add_parser("show", help="Show target findings workspace paths and guidance.")
    show.add_argument("--target")
    show.add_argument("--json", action="store_true")
    findings_subparsers.add_parser("sync", help="Regenerate local Notion export mirrors from runtime state.").add_argument("--json", action="store_true")
    findings_subparsers.add_parser("audit", help="Audit generated findings exports for quarantine metadata.").add_argument("--json", action="store_true")


def _add_rag_commands(subparsers: argparse._SubParsersAction) -> None:
    rag = subparsers.add_parser("rag", help="Import selected local documents and search cited RAG chunks.")
    rag_subparsers = rag.add_subparsers(dest="rag_command")
    rag_subparsers.add_parser("status", help="Show live RAG chunk and embedding counts.").add_argument("--json", action="store_true")
    _add_rag_import_command(rag_subparsers)
    _add_rag_ingest_and_search_commands(rag_subparsers)
    _add_rag_vuln_commands(rag_subparsers)


def _add_rag_import_command(rag_subparsers: argparse._SubParsersAction) -> None:
    import_cmd = rag_subparsers.add_parser("import", help="Import preprocessed offline chunks into the runtime DB.")
    import_cmd.add_argument("--chunks-dir", default="primordial-rag-preprocess/output/chunks", help="Directory containing chunks.jsonl from the preprocessing pipeline.")
    for flag in ("--dry-run", "--force", "--reembed", "--skip-embeddings"):
        import_cmd.add_argument(flag, action="store_true")
    for flag in ("--domain", "--source-file", "--doc-id"):
        import_cmd.add_argument(flag, action="append", default=[])
    import_cmd.add_argument("--limit", type=int)
    import_cmd.add_argument("--json", action="store_true")


def _add_rag_ingest_and_search_commands(rag_subparsers: argparse._SubParsersAction) -> None:
    chunk = rag_subparsers.add_parser("chunk", help="Inspect one imported RAG chunk.")
    inspect_cmd = chunk.add_subparsers(dest="rag_chunk_command").add_parser("inspect", help="Inspect one imported RAG chunk.")
    inspect_cmd.add_argument("chunk_id")
    inspect_cmd.add_argument("--json", action="store_true")
    ingest = rag_subparsers.add_parser("ingest", help="Import one selected local document for a scoped target.")
    ingest.add_argument("path")
    ingest.add_argument("--target", required=True, help="Target handle or ID.")
    ingest.add_argument("--corpus-type", default="operator_note", help="How Primordial should treat the imported RAG material.")
    ingest.add_argument("--source-trust", help="Optional source trust label stored with chunks.")
    ingest.add_argument("--hint-policy", choices=["advisory", "direct_task_hints", "disabled"], help="Whether tagged RAG material may produce planner task hints.")
    ingest.add_argument("--approve-url", action="store_true", help="Explicitly approve fetching and ingesting an http(s) URL.")
    ingest.add_argument("--no-docling", action="store_true", help="Disable optional Docling conversion.")
    ingest.add_argument("--no-embed", action="store_true", help="Store chunks without creating embeddings.")
    ingest.add_argument("--json", action="store_true")
    _add_rag_search_commands(rag_subparsers)


def _add_rag_search_commands(rag_subparsers: argparse._SubParsersAction) -> None:
    attck = rag_subparsers.add_parser("preprocess-attck", help="Parse MITRE ATT&CK STIX JSON into structured non-vector indexes.")
    attck.add_argument("--source-dir", default="docs/RAG_SRC", help="Directory containing ATT&CK STIX JSON files.")
    attck.add_argument("--out-dir", help="Output root for index directories. Defaults to runtime/artifacts/rag under the project root.")
    attck.add_argument("--json", action="store_true")
    search = rag_subparsers.add_parser("search", help="Search imported document chunks for a target.")
    search.add_argument("query", nargs="+")
    search.add_argument("--target", help="Target handle or ID. Omit to search the global imported corpus.")
    search.add_argument("--limit", type=int, default=5)
    for flag in ("--corpus-type", "--domain", "--source-file", "--doc-id", "--chunk-type"):
        search.add_argument(flag, action="append", default=[] if flag != "--corpus-type" else None, help="Filter by imported domain." if flag == "--domain" else None)
    cve_search = rag_subparsers.add_parser("cve-search", help="Search CVE advisory and exploit-note RAG chunks.")
    cve_search.add_argument("query", nargs="+")
    cve_search.add_argument("--target", required=True, help="Target handle or ID.")
    cve_search.add_argument("--limit", type=int, default=5)
    cve_search.add_argument("--json", action="store_true")
    hints = rag_subparsers.add_parser("hints", help="Show policy-gated direct task hints from tagged RAG chunks.")
    hints.add_argument("query", nargs="*")
    hints.add_argument("--target", required=True, help="Target handle or ID.")
    hints.add_argument("--limit", type=int, default=8)
    hints.add_argument("--json", action="store_true")
    search.add_argument("--json", action="store_true")


def _add_rag_vuln_commands(rag_subparsers: argparse._SubParsersAction) -> None:
    vuln = rag_subparsers.add_parser("vuln", help="Inspect vulnerability-intelligence RAG cards.")
    vuln_subparsers = vuln.add_subparsers(dest="rag_vuln_command")
    vuln_subparsers.add_parser("status", help="Show vulnerability-intel RAG counts.").add_argument("--json", action="store_true")
    _add_rag_vuln_sync_command(vuln_subparsers)
    import_cmd = vuln_subparsers.add_parser("import", help="Import vulnerability-intel card chunks.")
    import_cmd.add_argument("--chunks-dir", default="primordial-rag-preprocess/output/vuln/chunks")
    for flag in ("--dry-run", "--force", "--reembed", "--skip-embeddings"):
        import_cmd.add_argument(flag, action="store_true")
    import_cmd.add_argument("--limit", type=int)
    import_cmd.add_argument("--json", action="store_true")
    search = vuln_subparsers.add_parser("search", help="Search vulnerability-intel cards.")
    search.add_argument("query", nargs="+")
    search.add_argument("--limit", type=int, default=8)
    for flag in ("--cve-id", "--ghsa-id", "--osv-id", "--package", "--ecosystem"):
        search.add_argument(flag)
    search.add_argument("--kev", action="store_true")
    search.add_argument("--epss-percentile", type=float)
    search.add_argument("--json", action="store_true")
    hints = vuln_subparsers.add_parser("hints", help="Return hint-only vulnerability context.")
    hints.add_argument("query", nargs="*")
    hints.add_argument("--limit", type=int, default=8)
    hints.add_argument("--kev", action="store_true")
    hints.add_argument("--json", action="store_true")


def _add_rag_vuln_sync_command(vuln_subparsers: argparse._SubParsersAction) -> None:
    sync = vuln_subparsers.add_parser("sync", help="Sync official vulnerability feeds, preprocess cards, and import vuln RAG chunks.")
    sync.add_argument("--since-year", type=int, default=2020)
    sync.add_argument("--embed-all", dest="embed_all", action="store_true", default=True)
    sync.add_argument("--embed-relevant-only", dest="embed_all", action="store_false")
    sync.add_argument("--source", action="append", choices=["nvd", "kev", "epss", "cvelist_v5", "osv", "ghsa"], help="Limit sync to a source. Repeat for multiple sources.")
    sync.add_argument("--max-nvd-pages", type=int, help="Bound NVD pagination for smoke tests or partial backfills.")
    sync.add_argument("--max-enrichment-cves", type=int, default=250)
    sync.add_argument("--rate-limit-seconds", type=float)
    sync.add_argument("--timeout", type=float, default=45.0)
    for flag in ("--skip-import", "--force", "--reembed", "--skip-embeddings"):
        sync.add_argument(flag, action="store_true")
    sync.add_argument("--limit", type=int)
    sync.add_argument("--json", action="store_true")


def _add_operator_commands(
    subparsers: argparse._SubParsersAction,
    scope_profiles: Iterable[str],
    methodologies: Iterable[str],
) -> None:
    ask = subparsers.add_parser("ask", help="Ask the bounded operator AI about current Primordial state.")
    ask.add_argument("message", nargs="+")
    ask.add_argument("--target", help="Target handle or target ID to focus the answer.")
    ask.add_argument("--json", action="store_true")
    _add_credentials_commands(subparsers)
    _add_scope_session_commands(subparsers, scope_profiles, methodologies)


def _add_credentials_commands(subparsers: argparse._SubParsersAction) -> None:
    credentials = subparsers.add_parser("credentials", help="Manage local Notion, Discord, Caido, and known credentials.")
    credential_subparsers = credentials.add_subparsers(dest="credentials_command")
    credential_subparsers.add_parser("status", help="Show redacted credential status.").add_argument("--json", action="store_true")
    notion = credential_subparsers.add_parser("set-notion", help="Set Notion integration credentials.")
    notion.add_argument("--api-key")
    notion.add_argument("--parent-page-id")
    notion.add_argument("--version", default="2022-06-28")
    credential_subparsers.add_parser("set-discord", help="Set Discord webhook credentials.").add_argument("--webhook-url")
    for command, help_text in (("set-known", "Set known credentials for credentialed verification."), ("set-lab", "Compatibility alias for set-known.")):
        parser = credential_subparsers.add_parser(command, help=help_text)
        parser.add_argument("--username")
        parser.add_argument("--password")
        parser.add_argument("--domain")
    caido = credential_subparsers.add_parser("set-caido", help="Set Caido GraphQL credentials.")
    caido.add_argument("--graphql-url")
    caido.add_argument("--api-token")
    clear = credential_subparsers.add_parser("clear", help="Clear credentials for a service.")
    clear.add_argument("service", choices=["notion", "discord", "known", "lab", "caido"])


def _add_scope_session_commands(
    subparsers: argparse._SubParsersAction,
    scope_profiles: Iterable[str],
    methodologies: Iterable[str],
) -> None:
    profile_choices = list(scope_profiles)
    add_target = subparsers.add_parser("add-target", help="Add or update a single target and its scope assets.")
    add_target.add_argument("handle")
    add_target.add_argument("--profile", choices=profile_choices, default="hack_the_box")
    add_target.add_argument("--display-name")
    add_target.add_argument("--asset", action="append", default=[])
    add_target.add_argument("--metadata-json", help="JSON object merged into target metadata.")
    add_target.add_argument("--out-of-scope", action="store_true")
    remove_target = subparsers.add_parser("remove-target", help="Remove a target and all linked runtime records.")
    remove_target.add_argument("handle")
    remove_target.add_argument("--profile", choices=profile_choices)
    import_scope = subparsers.add_parser("import-scope", help="Import a JSON or line-based scope file.")
    import_scope.add_argument("path", type=Path)
    import_scope.add_argument("--profile", choices=profile_choices, default="hackerone")
    start_session = subparsers.add_parser("start-session", help="Start a new methodology session.")
    start_session.add_argument("--methodology", choices=list(methodologies), default="web_app_core")
    start_session.add_argument("--profile", choices=profile_choices, default="hackerone")
    start_session.add_argument("--title", default="Primordial Session")
    approve = subparsers.add_parser("approve", help="Approve pending tasks.")
    approve.add_argument("task_id", nargs="?")
    approve.add_argument("--all-safe", action="store_true", help="Approve queued NEEDS_APPROVAL tasks that current policy now allows.")
    approve.add_argument("--tick", action="store_true", help="Run one orchestration tick after --all-safe approves tasks.")
    approve.add_argument("--limit", type=int, default=200)
    subparsers.add_parser("deny", help="Deny a pending task.").add_argument("task_id")
