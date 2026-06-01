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


def run_rag_command(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: Any,
) -> int:
    command = args.rag_command
    if command is None:
        parser.error("rag requires a subcommand")
    handlers = {
        "status": _run_rag_status,
        "import": _run_rag_import,
        "chunk": _run_rag_chunk,
        "ingest": _run_rag_ingest,
        "search": _run_rag_search,
        "cve-search": _run_rag_cve_search,
        "hints": _run_rag_hints,
        "vuln": _run_rag_vuln,
    }
    handler = handlers.get(command)
    if handler is None:
        parser.error(f"unknown rag subcommand: {command}")
    return handler(args, parser, runtime, callbacks)


def _run_rag_status(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: Any,
) -> int:
    return _emit_payload(args, runtime.rag_status(), callbacks.format_rag_status)


def _run_rag_import(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: Any,
) -> int:
    payload = runtime.rag_import_chunks(
        args.chunks_dir,
        dry_run=args.dry_run,
        force=args.force,
        reembed=args.reembed,
        skip_embeddings=args.skip_embeddings,
        domains=args.domain,
        source_files=args.source_file,
        doc_ids=args.doc_id,
        limit=args.limit,
    )
    return _emit_payload(args, payload, callbacks.format_rag_import)


def _run_rag_chunk(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: Any,
) -> int:
    if args.rag_chunk_command != "inspect":
        parser.error("rag chunk requires a subcommand: inspect")
    return _emit_payload(args, runtime.rag_chunk_inspect(args.chunk_id), callbacks.format_rag_chunk)


def _run_rag_ingest(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: Any,
) -> int:
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
    return _emit_payload(args, payload, callbacks.format_rag_ingest)


def _run_rag_search(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: Any,
) -> int:
    payload = runtime.rag_search(
        " ".join(args.query),
        target=args.target,
        limit=args.limit,
        corpus_types=args.corpus_type,
        filters={
            "domain": args.domain,
            "source_file": args.source_file,
            "doc_id": args.doc_id,
            "chunk_type": args.chunk_type,
        },
    )
    return _emit_payload(args, payload, callbacks.format_rag_search)


def _run_rag_cve_search(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: Any,
) -> int:
    payload = runtime.rag_cve_search(" ".join(args.query), target=args.target, limit=args.limit)
    return _emit_payload(args, payload, callbacks.format_rag_search)


def _run_rag_hints(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: Any,
) -> int:
    payload = runtime.rag_hints(" ".join(args.query), target=args.target, limit=args.limit)
    return _emit_payload(args, payload, callbacks.format_rag_hints)


def _run_rag_vuln(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: Any,
) -> int:
    command = args.rag_vuln_command
    if command is None:
        parser.error("rag vuln requires a subcommand")
    handlers = {
        "status": _run_rag_vuln_status,
        "sync": _run_rag_vuln_sync,
        "import": _run_rag_vuln_import,
        "search": _run_rag_vuln_search,
        "hints": _run_rag_vuln_hints,
    }
    handler = handlers.get(command)
    if handler is None:
        parser.error(f"unknown rag vuln subcommand: {command}")
    return handler(args, parser, runtime, callbacks)


def _run_rag_vuln_status(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: Any,
) -> int:
    payload = runtime.rag_vuln_status()
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(callbacks.format_rag_status(payload))
        print(f"vuln_intel_chunks={payload['vuln_intel_chunks']}")
    return 0


def _run_rag_vuln_sync(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: Any,
) -> int:
    payload = runtime.rag_vuln_sync(
        since_year=args.since_year,
        embed_all=args.embed_all,
        sources=args.source,
        timeout_seconds=args.timeout,
        rate_limit_seconds=args.rate_limit_seconds,
        max_nvd_pages=args.max_nvd_pages,
        max_enrichment_cves=args.max_enrichment_cves,
        skip_import=args.skip_import,
        force=args.force,
        reembed=args.reembed,
        skip_embeddings=args.skip_embeddings,
        limit=args.limit,
    )
    return _emit_payload(args, payload, callbacks.format_rag_vuln_sync)


def _run_rag_vuln_import(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: Any,
) -> int:
    payload = runtime.rag_import_chunks(
        args.chunks_dir,
        dry_run=args.dry_run,
        force=args.force,
        reembed=args.reembed,
        skip_embeddings=args.skip_embeddings,
        domains=["vuln_intel"],
        limit=args.limit,
    )
    return _emit_payload(args, payload, callbacks.format_rag_import)


def _run_rag_vuln_search(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: Any,
) -> int:
    payload = runtime.rag_vuln_search(" ".join(args.query), limit=args.limit, filters=_vuln_cli_filters(args))
    return _emit_payload(args, payload, callbacks.format_rag_search)


def _run_rag_vuln_hints(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    runtime: Any,
    callbacks: Any,
) -> int:
    filters = {"kev": True} if args.kev else {}
    payload = runtime.rag_vuln_hints(" ".join(args.query), limit=args.limit, filters=filters)
    return _emit_payload(args, payload, callbacks.format_rag_vuln_hints)


def _vuln_cli_filters(args: argparse.Namespace) -> dict[str, object]:
    filters: dict[str, object] = {}
    for key in ("cve_id", "ghsa_id", "osv_id", "package", "ecosystem"):
        value = getattr(args, key, None)
        if value:
            filters[key] = [str(value)]
    if getattr(args, "kev", False):
        filters["kev"] = True
    epss = getattr(args, "epss_percentile", None)
    if epss is not None:
        filters["epss_percentile"] = {"gte": float(epss)}
    return filters
