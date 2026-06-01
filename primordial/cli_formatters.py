from __future__ import annotations

import json


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


def _format_rag_status(payload: dict[str, object]) -> str:
    configured = payload.get("configured_embeddings", {})
    synthesis = payload.get("configured_synthesis", {})
    lines = [
        f"document_chunks={payload.get('document_chunks')}",
        f"record_embeddings={payload.get('record_embeddings')}",
    ]
    if isinstance(configured, dict):
        lines.append(
            f"embeddings={configured.get('provider')}:{configured.get('model')} "
            f"dimension={configured.get('dimension') or 'unknown'}"
        )
    if isinstance(synthesis, dict):
        lines.append(f"synthesis={synthesis.get('provider')}:{synthesis.get('model')}")
    domains = payload.get("domains", [])
    if isinstance(domains, list) and domains:
        lines.append("domains:")
        for item in domains:
            if isinstance(item, dict):
                lines.append(f"  {item.get('domain')}: {item.get('count')}")
    models = payload.get("embedding_models", [])
    if isinstance(models, list) and models:
        lines.append("embedding_models:")
        for item in models:
            if isinstance(item, dict):
                lines.append(f"  {item.get('provider')}:{item.get('model')}: {item.get('count')}")
    return "\n".join(lines)


def _format_rag_import(payload: dict[str, object]) -> str:
    lines = [
        f"dry_run={payload.get('dry_run')}",
        f"files_seen={payload.get('files_seen')}",
        f"records_seen={payload.get('records_seen')}",
        (
            f"chunks inserted={payload.get('chunks_inserted')} updated={payload.get('chunks_updated')} "
            f"skipped={payload.get('chunks_skipped')}"
        ),
        (
            f"embeddings inserted={payload.get('embeddings_inserted')} updated={payload.get('embeddings_updated')} "
            f"skipped={payload.get('embeddings_skipped')} "
            f"provider={payload.get('embedding_provider')} model={payload.get('embedding_model')}"
        ),
        f"failures={payload.get('failures')}",
    ]
    errors = payload.get("errors", [])
    if isinstance(errors, list):
        for error in errors[:10]:
            lines.append(f"error={error}")
    return "\n".join(lines)


def _format_rag_chunk(payload: dict[str, object]) -> str:
    chunk = payload.get("chunk", {})
    embedding = payload.get("embedding", {})
    if not isinstance(chunk, dict):
        return "No chunk payload."
    metadata = chunk.get("metadata", {}) if isinstance(chunk.get("metadata"), dict) else {}
    lines = [
        f"chunk={chunk.get('citation_id') or chunk.get('id')}",
        f"title={chunk.get('title')}",
        f"domain={metadata.get('domain') or metadata.get('corpus_type')}",
        f"source_file={metadata.get('source_file')}",
        f"source_sha256={chunk.get('source_sha256')}",
        f"text={str(chunk.get('text') or '')[:500]}",
    ]
    if isinstance(embedding, dict):
        lines.append(f"embedding={embedding.get('embedding_model')} dim={embedding.get('embedding_dim')}")
    return "\n".join(lines)


def _format_attck_preprocess(payload: dict[str, object]) -> str:
    lines = [
        "ATT&CK structured indexes:",
        f"raw_vectorized={payload.get('raw_vectorized')}",
        f"structured_records_vectorized={payload.get('structured_records_vectorized')}",
    ]
    indexes = payload.get("indexes", [])
    if isinstance(indexes, list):
        for index in indexes:
            if not isinstance(index, dict):
                continue
            lines.append(
                f"{index.get('index_name')}: domain={index.get('domain')} "
                f"techniques={index.get('technique_count')} relationships={index.get('relationship_count')} "
                f"path={index.get('path')}"
            )
    allowed = payload.get("allowed_uses", [])
    prohibited = payload.get("prohibited_uses", [])
    if isinstance(allowed, list):
        lines.append("allowed_uses=" + ",".join(str(item) for item in allowed))
    if isinstance(prohibited, list):
        lines.append("prohibited_uses=" + ",".join(str(item) for item in prohibited))
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
            f"{result.get('citation_id') or result.get('chunk_id')} score={result.get('score')} "
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


def _vuln_cli_filters(args) -> dict[str, object]:
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


def _format_rag_vuln_hints(payload: dict[str, object]) -> str:
    lines = [f"query={payload.get('query')}", f"policy={payload.get('policy')}"]
    hints = payload.get("hints", [])
    if not isinstance(hints, list) or not hints:
        lines.append("No vulnerability-intelligence hints matched.")
        return "\n".join(lines)
    for hint in hints:
        if not isinstance(hint, dict):
            continue
        lines.append(
            f"- {hint.get('hint_type')} {hint.get('cve_id') or hint.get('vuln_id')} "
            f"citation={hint.get('citation_id')} task={hint.get('creates_executable_task')}"
        )
        lines.append(f"  {hint.get('summary')}")
    return "\n".join(lines)


def _format_rag_vuln_sync(payload: dict[str, object]) -> str:
    sync = payload.get("sync") if isinstance(payload.get("sync"), dict) else {}
    import_summary = payload.get("import") if isinstance(payload.get("import"), dict) else {}
    manifest = sync.get("preprocess_manifest") if isinstance(sync.get("preprocess_manifest"), dict) else {}
    lines = [
        f"ok={payload.get('ok')}",
        f"vuln_intel_chunks={payload.get('vuln_intel_chunks')}",
        f"chunks_dir={payload.get('chunks_dir')}",
        f"sync_duration_seconds={sync.get('duration_seconds')}",
        f"records={manifest.get('records', 0)} cards={manifest.get('cards', 0)} events={manifest.get('events', 0)}",
    ]
    if import_summary:
        lines.append(
            "import "
            f"seen={import_summary.get('records_seen', 0)} "
            f"inserted={import_summary.get('chunks_inserted', 0)} "
            f"updated={import_summary.get('chunks_updated', 0)} "
            f"skipped={import_summary.get('chunks_skipped', 0)} "
            f"embeddings={import_summary.get('embeddings_inserted', 0) + import_summary.get('embeddings_updated', 0)} "
            f"failures={import_summary.get('failures', 0)}"
        )
    sources = sync.get("sources") if isinstance(sync.get("sources"), dict) else {}
    for name, result in sorted(sources.items()):
        if not isinstance(result, dict):
            continue
        lines.append(
            f"{name}: status={result.get('status')} records={result.get('records', 0)} "
            f"files={result.get('files_written', 0)} failures={result.get('failures', 0)}"
        )
    lines.append("policy=hints_only; no executable tasks or scope expansion are created from vuln RAG.")
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
    _append_model_eval_metadata(lines, payload)
    _append_model_eval_recommendations(lines, payload)
    _append_model_eval_role_suggestions(lines, payload)
    if _append_model_eval_aggregate_rows(lines, payload):
        return "\n".join(lines)
    _append_model_eval_results(lines, payload)
    return "\n".join(lines)


def _append_model_eval_metadata(lines: list[str], payload: dict[str, object]) -> None:
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


def _append_model_eval_recommendations(lines: list[str], payload: dict[str, object]) -> None:
    recommendations = payload.get("recommendations", {})
    if isinstance(recommendations, dict) and recommendations:
        lines.append("recommendations:")
        for role in ("local_fast", "local_deep", "local_code", "local_compact"):
            if role in recommendations:
                lines.append(f"  {role}: {recommendations[role]}")


def _append_model_eval_role_suggestions(lines: list[str], payload: dict[str, object]) -> None:
    suggestions = payload.get("role_suggestions", [])
    if isinstance(suggestions, list) and suggestions:
        lines.append("role suggestions:")
        for role in ("local_fast", "local_deep", "local_code", "local_compact"):
            role_items = _model_eval_role_items(suggestions, role)
            for item in sorted(role_items, key=lambda entry: (entry.get("rank") or 99, str(entry.get("model") or "")))[:2]:
                _append_model_eval_role_item(lines, role, item)


def _model_eval_role_items(suggestions: list[object], role: str) -> list[dict[str, object]]:
    return [
        item
        for item in suggestions
        if isinstance(item, dict)
        and item.get("role") == role
        and item.get("status") in {"recommended", "candidate"}
    ]


def _append_model_eval_role_item(lines: list[str], role: str, item: dict[str, object]) -> None:
    confidence = item.get("confidence")
    status = item.get("status")
    model = item.get("recommendation_id") or item.get("model")
    lines.append(f"  {role}: {model} rank={item.get('rank')} confidence={confidence} status={status}")
    detail = _model_eval_role_detail(item)
    if detail:
        lines.append(f"    {' | '.join(detail)}")


def _model_eval_role_detail(item: dict[str, object]) -> list[str]:
    detail = []
    reasons = item.get("reasons", [])
    warnings = item.get("warnings", [])
    if isinstance(reasons, list) and reasons:
        detail.append("; ".join(str(reason) for reason in reasons[:2]))
    if isinstance(warnings, list) and warnings:
        detail.append("warnings: " + "; ".join(str(warning) for warning in warnings[:2]))
    return detail


def _append_model_eval_aggregate_rows(lines: list[str], payload: dict[str, object]) -> bool:
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
        return True
    return False


def _append_model_eval_results(lines: list[str], payload: dict[str, object]) -> None:
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
