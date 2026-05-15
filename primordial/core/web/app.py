from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
from threading import Lock, RLock
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from primordial.app.runtime import PrimordialRuntime
from primordial.core.domain.enums import AgentRole, ProviderRoute, ScopeProfile, TaskKind


@dataclass(slots=True)
class WebResponse:
    status: int
    body: bytes
    content_type: str
    headers: dict[str, str] = field(default_factory=dict)


class PrimordialWebApp:
    STALE_WEB_ACTION_SECONDS = 900

    def __init__(self, runtime: PrimordialRuntime) -> None:
        self.runtime = runtime
        self._lock = RLock()
        self._tick_lock = Lock()
        self._actions_lock = RLock()
        self._active_actions: dict[str, dict[str, Any]] = {}
        self._static_dir = Path(__file__).resolve().parent / "static"

    def dispatch(
        self,
        method: str,
        raw_path: str,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
    ) -> WebResponse:
        parsed = urlsplit(raw_path)
        path = parsed.path or "/"
        query = parse_qs(parsed.query)

        if method == "GET" and path == "/":
            return self._static_response("index.html", "text/html; charset=utf-8")
        if method == "GET" and not path.startswith("/api/"):
            static = self._static_asset_response(path)
            if static is not None:
                return static
        if method == "GET" and path == "/api/health":
            return self._json_response(self.runtime.health_payload())
        if method == "GET" and path == "/api/control-plane":
            target = self._optional_query_string(query, "target")
            live_metrics = self._bool_param(query, "live_metrics", False)
            return self._json_response(self._control_plane_payload(target=target, live_metrics=live_metrics))
        if method == "GET" and path == "/api/system-metrics":
            return self._json_response(self._system_metrics_payload())
        if method == "GET" and path == "/api/storage-status":
            return self._json_response(self.runtime.storage_status_payload())
        if method == "GET" and path == "/api/self-test":
            with self._lock:
                return self._json_response(self.runtime.self_test_payload())
        if method == "GET" and path == "/api/operator-intent":
            return self._json_response(self.runtime.operator_intent_payload())
        if method == "GET" and path == "/api/credentials":
            return self._json_response(self.runtime.credentials_payload())
        if method == "GET" and path == "/api/rag/status":
            return self._json_response(self.runtime.rag_status())
        if method == "GET" and path == "/api/rag/config":
            return self._json_response(self.runtime.rag_config_payload())
        if method == "GET" and path.startswith("/api/rag/chunks/"):
            chunk_id = unquote(path.rsplit("/", 1)[-1])
            try:
                return self._json_response(self._rag_chunk_api_payload(self.runtime.rag_chunk_inspect(chunk_id)))
            except ValueError as exc:
                return self._json_response({"ok": False, "error": str(exc)}, status=404)
        if method == "GET" and path.startswith("/api/rag/sources/"):
            doc_id = unquote(path.rsplit("/", 1)[-1])
            try:
                return self._json_response(self.runtime.rag_source_profile(doc_id, limit=self._int_param(query, "limit", 50)))
            except ValueError as exc:
                return self._json_response({"ok": False, "error": str(exc)}, status=404)
        if method == "POST" and path == "/api/rag/import":
            payload = self._parse_json_body(body)
            try:
                return self._run_tracked_action(
                    "Import RAG corpus",
                    "rag-import",
                    lambda: self.runtime.rag_import_chunks(
                        self._optional_string(payload, "chunks_dir"),
                        dry_run=bool(payload.get("dry_run", False)),
                        force=bool(payload.get("force", False)),
                        reembed=bool(payload.get("reembed", False)),
                        skip_embeddings=bool(payload.get("skip_embeddings", False)),
                        domains=self._payload_list(payload, "domain"),
                        source_files=self._payload_list(payload, "source_file"),
                        doc_ids=self._payload_list(payload, "doc_id"),
                        limit=self._optional_int(payload, "limit"),
                    ),
                    use_runtime_lock=False,
                )
            except (TypeError, ValueError) as exc:
                return self._json_response({"ok": False, "error": str(exc)}, status=400)
        if method == "POST" and path == "/api/rag/search":
            payload = self._parse_json_body(body)
            query_text = str(payload.get("query") or "").strip()
            if not query_text:
                return self._json_response({"ok": False, "error": "query is required"}, status=400)
            try:
                return self._json_response(
                    self.runtime.rag_search(
                        query_text,
                        target=self._optional_string(payload, "target"),
                        limit=self._optional_int(payload, "limit") or 5,
                        corpus_types=self._payload_list(payload, "corpus_types") or self._payload_list(payload, "corpus_type"),
                        filters=self._rag_filters_payload(payload),
                    )
                )
            except ValueError as exc:
                return self._json_response({"ok": False, "error": str(exc)}, status=400)
        if method == "POST" and path == "/api/rag/hints":
            payload = self._parse_json_body(body)
            target = str(payload.get("target") or "").strip()
            if not target:
                return self._json_response({"ok": False, "error": "target is required"}, status=400)
            try:
                return self._json_response(
                    self.runtime.rag_hints(
                        str(payload.get("query") or ""),
                        target=target,
                        limit=self._optional_int(payload, "limit") or 8,
                    )
                )
            except ValueError as exc:
                return self._json_response({"ok": False, "error": str(exc)}, status=400)
        if method == "POST" and path == "/api/rag/synthesize":
            payload = self._parse_json_body(body)
            query_text = str(payload.get("query") or "").strip()
            if not query_text:
                return self._json_response({"ok": False, "error": "query is required"}, status=400)
            retrieved_chunks = payload.get("retrieved_chunks")
            if retrieved_chunks is not None and not isinstance(retrieved_chunks, list):
                return self._json_response({"ok": False, "error": "retrieved_chunks must be a list"}, status=400)
            safety_context = payload.get("safety_context")
            if safety_context is not None and not isinstance(safety_context, dict):
                return self._json_response({"ok": False, "error": "safety_context must be an object"}, status=400)
            if retrieved_chunks is None:
                try:
                    search = self.runtime.rag_search(
                        query_text,
                        target=self._optional_string(payload, "target"),
                        limit=self._optional_int(payload, "limit") or 5,
                        corpus_types=self._payload_list(payload, "corpus_types")
                        or self._payload_list(payload, "corpus_type"),
                        filters=self._rag_filters_payload(payload),
                    )
                except ValueError as exc:
                    return self._json_response({"ok": False, "error": str(exc)}, status=400)
                retrieved_chunks = search.get("results", []) if isinstance(search.get("results"), list) else []
            result = self.runtime.synthesize_rag_answer(
                query_text,
                mode=str(payload.get("mode") or "grounded_answer"),
                retrieved_chunks=[item for item in retrieved_chunks if isinstance(item, dict)],
                safety_context=safety_context or {},
            )
            return self._json_response(result, status=200 if result.get("status") != "provider_error" else 502)
        if method == "POST" and path == "/api/rag/eval":
            payload = self._parse_json_body(body)
            queries = payload.get("queries")
            if isinstance(queries, str):
                query_list = [line.strip() for line in queries.splitlines() if line.strip()]
            elif isinstance(queries, list):
                query_list = [str(item).strip() for item in queries if str(item).strip()]
            else:
                return self._json_response({"ok": False, "error": "queries must be a list or newline-delimited string"}, status=400)
            try:
                return self._json_response(
                    self.runtime.rag_eval_probes(
                        query_list,
                        target=self._optional_string(payload, "target"),
                        limit=self._optional_int(payload, "limit") or 5,
                        corpus_types=self._payload_list(payload, "corpus_types")
                        or self._payload_list(payload, "corpus_type"),
                        filters=self._rag_filters_payload(payload),
                    )
                )
            except ValueError as exc:
                return self._json_response({"ok": False, "error": str(exc)}, status=400)
        if method == "GET" and path == "/api/skills":
            include_body = self._bool_param(query, "include_body", False)
            with self._lock:
                return self._json_response(self.runtime.skills_payload(include_body=include_body))
        if method == "GET" and path == "/api/findings-context":
            target = self._optional_query_string(query, "target")
            include_guidance = self._bool_param(query, "include_guidance", True)
            with self._lock:
                try:
                    return self._json_response(
                        self.runtime.findings_context_payload(target=target, include_guidance=include_guidance)
                    )
                except ValueError as exc:
                    return self._json_response({"error": str(exc)}, status=404)
        if method == "POST" and path == "/api/findings-context/guidance":
            payload = self._parse_json_body(body)
            target = str(payload.get("target", "")).strip()
            guidance = str(payload.get("guidance", ""))
            if not target:
                return self._json_response({"error": "target is required"}, status=400)
            with self._lock:
                try:
                    outcome = self.runtime.update_target_guidance(target, guidance)
                    return self._action_response("update-target-guidance", {"findings_context": outcome})
                except ValueError as exc:
                    return self._json_response({"error": str(exc)}, status=404)
        if method == "GET" and path == "/api/integrations/caido":
            check_health = self._bool_param(query, "check_health", False)
            return self._json_response(self.runtime.caido_status_payload(check_health=check_health))
        if method == "POST" and path == "/api/integrations/caido/search":
            payload = self._parse_json_body(body)
            with self._lock:
                try:
                    result = self.runtime.caido_search_requests(
                        target=self._optional_string(payload, "target"),
                        httpql=self._optional_string(payload, "httpql"),
                        limit=self._optional_int(payload, "limit") or 50,
                        offset=self._optional_int(payload, "offset") or 0,
                    )
                    return self._json_response(result, status=200 if result.get("ok") else 502)
                except ValueError as exc:
                    return self._json_response({"ok": False, "error": str(exc)}, status=400)
        if method == "GET" and path.startswith("/api/integrations/caido/requests/"):
            request_id = unquote(path.rsplit("/", 1)[-1])
            with self._lock:
                result = self.runtime.caido_request_detail(request_id)
                return self._json_response(result, status=200 if result.get("ok") else 502)
        if method == "POST" and path == "/api/integrations/caido/import":
            payload = self._parse_json_body(body)
            request_ids = payload.get("request_ids", [])
            if not isinstance(request_ids, list):
                return self._json_response({"ok": False, "error": "request_ids must be a list"}, status=400)
            target = str(payload.get("target", "")).strip()
            if not target:
                return self._json_response({"ok": False, "error": "target is required"}, status=400)
            with self._lock:
                try:
                    return self._action_response(
                        "caido-import",
                        self.runtime.caido_import_requests(
                            target=target,
                            request_ids=[str(item) for item in request_ids],
                            httpql=str(payload.get("httpql") or ""),
                        ),
                    )
                except ValueError as exc:
                    return self._json_response({"ok": False, "error": str(exc)}, status=400)
        if method == "POST" and path == "/api/integrations/caido/replay/draft":
            payload = self._parse_json_body(body)
            target = str(payload.get("target", "")).strip()
            raw_request = str(payload.get("raw_request") or "")
            if not target:
                return self._json_response({"ok": False, "error": "target is required"}, status=400)
            with self._lock:
                try:
                    result = self.runtime.caido_replay_draft(target=target, raw_request=raw_request)
                    return self._json_response(result, status=200 if result.get("ok") else 502)
                except ValueError as exc:
                    return self._json_response({"ok": False, "error": str(exc)}, status=400)
        if method == "POST" and path == "/api/integrations/caido/replay/send":
            payload = self._parse_json_body(body)
            target = str(payload.get("target", "")).strip()
            raw_request = str(payload.get("raw_request") or "")
            if not target:
                return self._json_response({"ok": False, "error": "target is required"}, status=400)
            with self._lock:
                try:
                    result = self.runtime.caido_replay_send(
                        target=target,
                        raw_request=raw_request,
                        confirmation=self._optional_string(payload, "confirmation"),
                        session_id=self._optional_string(payload, "session_id"),
                    )
                    if result.get("ok"):
                        return self._action_response("caido-replay-send", result)
                    return self._json_response(result, status=502)
                except ValueError as exc:
                    return self._json_response({"ok": False, "error": str(exc)}, status=400)
        if method == "GET" and path == "/api/models":
            return self._json_response(self.runtime.models_payload())
        if method == "GET" and path == "/api/chat":
            limit = self._int_param(query, "limit", 20)
            target = self._optional_query_string(query, "target")
            with self._lock:
                return self._json_response(self.runtime.operator_chat_payload(limit=limit, target=target))
        if method == "GET" and path == "/api/dashboard":
            return self._json_response(self._dashboard_payload())
        if method == "GET" and path == "/api/work-status":
            return self._json_response(self.work_status_payload())
        if method == "GET" and path == "/api/execution-mode":
            return self._json_response(self.runtime.execution_mode_payload())
        if method == "GET" and path == "/api/runtime-settings":
            return self._json_response(self.runtime.runtime_tuning_payload())
        if method == "GET" and path == "/api/scope":
            return self._json_response(self.runtime.scope_payload())
        if method == "GET" and path == "/api/scope-profiles":
            return self._json_response(self.runtime.scope_profiles_payload())
        if method == "GET" and path == "/api/targets":
            return self._json_response(self.runtime.scope_payload())
        if method == "GET" and path == "/api/audit":
            limit = self._int_param(query, "limit", 25)
            return self._json_response(self.runtime.audit_payload(limit=limit))
        if method == "GET" and path == "/api/records":
            limit = self._int_param(query, "limit", 25)
            target_id = self._optional_query_string(query, "target_id")
            return self._json_response(self.runtime.records_payload(limit=limit, target_id=target_id))
        if method == "GET" and path.startswith("/api/tasks/"):
            task_id = path.rsplit("/", 1)[-1]
            with self._lock:
                payload = self.runtime.task_audit_payload(task_id, limit=self._int_param(query, "limit", 25))
            if payload is None:
                return self._json_response({"error": "task not found"}, status=404)
            return self._json_response(payload)
        if method == "POST" and path == "/api/actions/tick":
            payload = self._parse_json_body(body)
            max_executions = int(payload.get("max_executions", 3))
            return self._run_tracked_action(
                "Run orchestration tick",
                "tick",
                lambda: self._tick_action(max_executions),
            )
        if method == "POST" and path == "/api/actions/compact":
            return self._run_tracked_action(
                "Compact memory",
                "compact",
                lambda: {"memory_entries_created": self.runtime.compact_memory()},
            )
        if method == "POST" and path == "/api/actions/process-queues":
            return self._run_tracked_action(
                "Process external queues",
                "process-queues",
                self.runtime.process_external_queues,
            )
        if method == "POST" and path == "/api/actions/sync-findings-context":
            return self._run_tracked_action(
                "Sync findings context",
                "sync-findings-context",
                self.runtime.sync_findings_context_exports,
            )
        if method == "POST" and path == "/api/actions/warm-models":
            payload = self._parse_json_body(body)
            keep_alive = str(payload.get("keep_alive", "8h")).strip() or "8h"
            return self._run_tracked_action(
                "Warm Ollama model lanes",
                "warm-models",
                lambda: self.runtime.warm_model_routes(keep_alive=keep_alive),
            )
        if method == "POST" and path == "/api/actions/clear-models":
            return self._run_tracked_action(
                "Clear Ollama model lanes",
                "clear-models",
                self.runtime.clear_model_routes,
            )
        if method == "POST" and path == "/api/actions/stop-work":
            return self._run_tracked_action(
                "Stop active work",
                "stop-work",
                self.runtime.stop_active_work,
            )
        if method == "POST" and path == "/api/actions/clear-stale-web-actions":
            payload = self._parse_json_body(body)
            max_age_seconds = self._optional_int(payload, "max_age_seconds") or self.STALE_WEB_ACTION_SECONDS
            cleared = self._clear_stale_actions(max_age_seconds=max_age_seconds)
            return self._action_response(
                "clear-stale-web-actions",
                {"cleared": cleared, "max_age_seconds": max_age_seconds},
            )
        if method == "POST" and path == "/api/ui/commands":
            payload = self._parse_json_body(body)
            command = str(payload.get("command", "")).strip()
            if not command:
                return self._json_response({"error": "command is required"}, status=400)
            with self._lock:
                try:
                    outcome = self.runtime.create_ui_command_proposal(command, payload)
                except ValueError as exc:
                    return self._json_response({"error": str(exc)}, status=400)
                return self._action_response("ui-command-proposal", outcome)
        if method == "POST" and path == "/api/execution-mode":
            payload = self._parse_json_body(body)
            mode = str(payload.get("mode", "")).strip()
            interval = payload.get("interval_seconds")
            try:
                interval_seconds = int(interval) if interval is not None else None
                outcome = self.runtime.update_execution_mode(mode, interval_seconds=interval_seconds)
                return self._action_response("execution-mode", {"execution_mode": outcome})
            except (TypeError, ValueError) as exc:
                return self._json_response({"error": str(exc)}, status=400)
        if method == "POST" and path == "/api/runtime-settings":
            payload = self._parse_json_body(body)
            try:
                outcome = self.runtime.update_runtime_tuning(
                    gpu_ai_timeout_seconds=self._optional_int(payload, "gpu_ai_timeout_seconds"),
                    cpu_ai_timeout_seconds=self._optional_int(payload, "cpu_ai_timeout_seconds"),
                    stale_run_timeout_seconds=self._optional_int(payload, "stale_run_timeout_seconds"),
                    min_free_cpu_ram_mb=self._optional_int(payload, "min_free_cpu_ram_mb"),
                    min_free_gpu_ram_mb=self._optional_int(payload, "min_free_gpu_ram_mb"),
                )
                return self._action_response("runtime-settings", {"runtime_tuning": outcome})
            except (TypeError, ValueError) as exc:
                return self._json_response({"error": str(exc)}, status=400)
        if method == "POST" and path == "/api/operator-intent":
            payload = self._parse_json_body(body)
            intent_id = str(payload.get("intent_id", "")).strip()
            if not intent_id:
                return self._json_response({"error": "intent_id is required"}, status=400)
            try:
                outcome = self.runtime.set_operator_intent(intent_id)
            except KeyError as exc:
                return self._json_response({"error": str(exc)}, status=400)
            return self._action_response("operator-intent", {"operator_intent": outcome})
        if method == "POST" and path == "/api/runtime-control":
            payload = self._parse_json_body(body)
            mode = str(payload.get("mode", "")).strip()
            intent_id = str(payload.get("intent_id", "")).strip()
            interval = payload.get("interval_seconds")
            if not mode:
                return self._json_response({"error": "mode is required"}, status=400)
            if not intent_id:
                return self._json_response({"error": "intent_id is required"}, status=400)
            try:
                outcome = self.runtime.update_runtime_control(
                    mode=mode,
                    interval_seconds=int(interval) if interval is not None else None,
                    intent_id=intent_id,
                )
            except (KeyError, TypeError, ValueError) as exc:
                return self._json_response({"error": str(exc)}, status=400)
            return self._runtime_control_response(outcome)
        if method == "POST" and path == "/api/models":
            payload = self._parse_json_body(body)
            selections = payload.get("roles", {})
            processors = payload.get("processors", {})
            wrapper_mode = payload.get("wrapper_mode")
            if not isinstance(selections, dict):
                return self._json_response({"error": "roles must be an object"}, status=400)
            if not isinstance(processors, dict):
                return self._json_response({"error": "processors must be an object"}, status=400)
            if wrapper_mode is not None and not isinstance(wrapper_mode, dict):
                return self._json_response({"error": "wrapper_mode must be an object"}, status=400)
            with self._lock:
                try:
                    models = self.runtime.update_model_roles(
                        {str(key): str(value) for key, value in selections.items()},
                        processors={str(key): str(value) for key, value in processors.items()},
                        wrapper_mode={str(key): value for key, value in wrapper_mode.items()} if wrapper_mode else None,
                    )
                except ValueError as exc:
                    return self._json_response({"error": str(exc)}, status=400)
                return self._action_response("update-model-roles", {"models": models})
        if method == "POST" and path == "/api/actions/approve":
            payload = self._parse_json_body(body)
            task_id = str(payload.get("task_id", "")).strip()
            if not task_id:
                return self._json_response({"error": "task_id is required"}, status=400)
            with self._lock:
                task = self.runtime.approve_task(task_id, approved=True)
                if task is None:
                    return self._json_response({"error": "task not found"}, status=404)
                return self._action_response("approve", {"task_id": task_id, "status": task.status.value})
        if method == "POST" and path == "/api/actions/deny":
            payload = self._parse_json_body(body)
            task_id = str(payload.get("task_id", "")).strip()
            if not task_id:
                return self._json_response({"error": "task_id is required"}, status=400)
            with self._lock:
                task = self.runtime.approve_task(task_id, approved=False)
                if task is None:
                    return self._json_response({"error": "task not found"}, status=404)
                return self._action_response("deny", {"task_id": task_id, "status": task.status.value})
        if method == "POST" and path == "/api/credentials/notion":
            payload = self._parse_json_body(body)
            credentials = self.runtime.set_notion_credentials(
                api_key=self._optional_string(payload, "api_key"),
                parent_page_id=self._optional_string(payload, "parent_page_id"),
                version=self._optional_string(payload, "version"),
            )
            return self._action_response("set-notion-credentials", {"credentials": credentials})
        if method == "POST" and path == "/api/credentials/discord":
            payload = self._parse_json_body(body)
            try:
                credentials = self.runtime.set_discord_credentials(
                    webhook_url=self._optional_string(payload, "webhook_url"),
                )
            except ValueError as exc:
                return self._json_response({"error": str(exc)}, status=400)
            return self._action_response("set-discord-credentials", {"credentials": credentials})
        if method == "POST" and path == "/api/credentials/known":
            payload = self._parse_json_body(body)
            credentials = self.runtime.set_known_credentials(
                username=self._optional_string(payload, "username"),
                password=self._optional_string(payload, "password"),
                domain=self._optional_string(payload, "domain"),
            )
            return self._action_response("set-known-credentials", {"credentials": credentials})
        if method == "POST" and path == "/api/credentials/lab":
            payload = self._parse_json_body(body)
            credentials = self.runtime.set_lab_credentials(
                username=self._optional_string(payload, "username"),
                password=self._optional_string(payload, "password"),
                domain=self._optional_string(payload, "domain"),
            )
            return self._action_response("set-lab-credentials", {"credentials": credentials})
        if method == "POST" and path == "/api/credentials/caido":
            payload = self._parse_json_body(body)
            credentials = self.runtime.set_caido_credentials(
                graphql_url=self._optional_string(payload, "graphql_url"),
                api_token=self._optional_string(payload, "api_token"),
            )
            return self._action_response("set-caido-credentials", {"credentials": credentials})
        if method == "POST" and path == "/api/chat":
            payload = self._parse_json_body(body)
            message = str(payload.get("message", "")).strip()
            if not message:
                return self._json_response({"error": "message is required"}, status=400)
            target = self._optional_string(payload, "target")
            return self._run_tracked_action(
                "Ask operator AI",
                "operator-chat",
                lambda: {"chat": self.runtime.ask_operator_ai(message, target=target)},
                use_runtime_lock=False,
            )
        if method == "DELETE" and path.startswith("/api/credentials/"):
            service = unquote(path.rsplit("/", 1)[-1])
            try:
                credentials = self.runtime.clear_credentials(service)
            except ValueError as exc:
                return self._json_response({"error": str(exc)}, status=400)
            return self._action_response("clear-credentials", {"credentials": credentials})
        if method == "POST" and path == "/api/targets":
            payload = self._parse_json_body(body)
            handle = str(payload.get("handle", "")).strip()
            profile = str(payload.get("profile", "")).strip()
            if not handle:
                return self._json_response({"error": "handle is required"}, status=400)
            if not profile:
                return self._json_response({"error": "profile is required"}, status=400)
            assets = payload.get("assets", [])
            if not isinstance(assets, list):
                return self._json_response({"error": "assets must be a list"}, status=400)
            active_ip = self._optional_string(payload, "active_ip")
            replace_scope_assets = bool(payload.get("replace_scope_assets", False))
            try:
                parsed_profile = self.runtime.resolve_scope_profile(profile)
            except ValueError:
                return self._json_response({"error": "invalid profile"}, status=400)
            with self._lock:
                try:
                    if replace_scope_assets:
                        target = self.runtime.replace_target_scope_assets(
                            handle=handle,
                            display_name=payload.get("display_name") and str(payload["display_name"]) or handle,
                            profile=parsed_profile,
                            in_scope=bool(payload.get("in_scope", True)),
                            active_ip=active_ip,
                            asset_rows=self._target_asset_rows(handle, active_ip, assets),
                        )
                    else:
                        target = self.runtime.update_target_fields(
                            handle=handle,
                            display_name=payload.get("display_name") and str(payload["display_name"]),
                            profile=parsed_profile,
                            assets=assets or [handle],
                            active_ip=active_ip,
                            in_scope=bool(payload.get("in_scope", True)),
                            metadata=dict(payload.get("metadata", {})) if isinstance(payload.get("metadata", {}), dict) else {},
                        )
                except ValueError as exc:
                    return self._json_response({"error": str(exc)}, status=400)
                return self._action_response("register-target", self._scope_refresh_result(target=target))
        if method == "POST" and path == "/api/scope/import":
            payload = self._parse_json_body(body)
            scope_payload = payload.get("scope", payload)
            profile = payload.get("profile")
            try:
                parsed_profile = self.runtime.resolve_scope_profile(str(profile)) if profile else None
                if not isinstance(scope_payload, dict):
                    return self._json_response({"error": "scope must be an object"}, status=400)
                with self._lock:
                    outcome = self.runtime.import_scope_payload(
                        scope_payload,
                        profile=parsed_profile,
                        source_name=str(payload.get("source", "web import")),
                    )
                    merged = dict(outcome)
                    merged.update(self._scope_refresh_result())
                    return self._action_response("import-scope", merged)
            except (KeyError, TypeError, ValueError) as exc:
                return self._json_response({"error": str(exc)}, status=400)
        if method == "DELETE" and path.startswith("/api/targets/"):
            handle = unquote(path.rsplit("/", 1)[-1])
            raw_profile = query.get("profile", [])
            parsed_profile = None
            if raw_profile:
                try:
                    parsed_profile = ScopeProfile(raw_profile[0])
                except ValueError:
                    return self._json_response({"error": "invalid profile"}, status=400)
            with self._lock:
                outcome = self.runtime.remove_target(handle, parsed_profile)
                if outcome.get("blocked"):
                    return self._json_response({"ok": False, "error": outcome["reason"], "result": outcome}, status=409)
                if not outcome["removed"]:
                    return self._json_response({"error": "target not found"}, status=404)
                merged = dict(outcome)
                merged.update(self._scope_refresh_result())
                return self._action_response("remove-target", merged)
        return self._json_response({"error": "not found", "path": path}, status=404)

    def _tick_action(self, max_executions: int) -> dict[str, Any]:
        if not self._tick_lock.acquire(blocking=False):
            return {"report": {"summary": "tick already running", "completed_runs": 0}, "skipped": True}
        try:
            report = self.runtime.run_tick(max_executions=max_executions)
            return {"report": {"summary": report.summary, "completed_runs": len(report.completed_runs)}}
        finally:
            self._tick_lock.release()

    def _run_tracked_action(self, label: str, action: str, worker, *, use_runtime_lock: bool = True) -> WebResponse:
        action_id = self._begin_action(label)
        try:
            if use_runtime_lock:
                with self._lock:
                    result = worker()
            else:
                result = worker()
            return self._action_response(action, result)
        finally:
            self._finish_action(action_id)

    def _begin_action(self, label: str) -> str:
        started = datetime.now(timezone.utc)
        action_id = f"web_{started.strftime('%Y%m%dT%H%M%S%fZ')}"
        with self._actions_lock:
            self._active_actions[action_id] = {
                "id": action_id,
                "kind": "web_action",
                "label": label,
                "status": "running",
                "started_at": started.isoformat(),
                "started_at_epoch": started.timestamp(),
            }
        return action_id

    def _finish_action(self, action_id: str) -> None:
        with self._actions_lock:
            self._active_actions.pop(action_id, None)

    def _active_web_actions(self) -> list[dict[str, Any]]:
        now = datetime.now(timezone.utc).timestamp()
        with self._actions_lock:
            actions = []
            for action in self._active_actions.values():
                item = {key: value for key, value in action.items() if key != "started_at_epoch"}
                started_at_epoch = action.get("started_at_epoch")
                age_seconds = int(max(0, now - float(started_at_epoch))) if started_at_epoch is not None else 0
                item["age_seconds"] = age_seconds
                item["stale_after_seconds"] = self.STALE_WEB_ACTION_SECONDS
                item["stale"] = age_seconds >= self.STALE_WEB_ACTION_SECONDS
                if item["stale"]:
                    item["status"] = "stale"
                actions.append(item)
            return actions

    def _clear_stale_actions(self, *, max_age_seconds: int) -> int:
        now = datetime.now(timezone.utc).timestamp()
        cleared = 0
        with self._actions_lock:
            for action_id, action in list(self._active_actions.items()):
                started_at_epoch = action.get("started_at_epoch")
                if started_at_epoch is None:
                    continue
                if now - float(started_at_epoch) >= max(1, max_age_seconds):
                    self._active_actions.pop(action_id, None)
                    cleared += 1
        return cleared

    def _dashboard_payload(self) -> dict[str, Any]:
        payload = self.runtime.dashboard_payload()
        payload["work_status"] = self.work_status_payload()
        return payload

    def work_status_payload(self) -> dict[str, Any]:
        payload = self.runtime.work_status_payload()
        web_actions = self._active_web_actions()
        if web_actions:
            payload = dict(payload)
            payload["web_actions"] = web_actions
            payload["is_busy"] = True
            stale_count = sum(1 for action in web_actions if action.get("stale"))
            if stale_count:
                payload["summary"] = (
                    f"Web console has {stale_count} stale action(s); runtime work may have continued in the background."
                )
            else:
                payload["summary"] = f"Web console is running {len(web_actions)} action(s)."
            counts = dict(payload.get("counts", {}))
            counts["web_actions"] = len(web_actions)
            counts["stale_web_actions"] = stale_count
            payload["counts"] = counts
        else:
            payload["web_actions"] = []
        return payload

    def continuous_tick_once(self) -> dict[str, Any]:
        mode = self.runtime.execution_mode_payload()
        if mode.get("mode") != "continuous":
            return {"ran": False, "interval_seconds": mode.get("interval_seconds", 30)}
        if not self._tick_lock.acquire(blocking=False):
            return {
                "ran": False,
                "busy": True,
                "interval_seconds": mode.get("interval_seconds", 30),
                "summary": "previous continuous tick still running",
            }
        try:
            report = self.runtime.run_tick(max_executions=1)
            return {"ran": True, "interval_seconds": mode.get("interval_seconds", 30), "summary": report.summary}
        finally:
            self._tick_lock.release()

    def _action_response(self, action: str, result: dict[str, Any]) -> WebResponse:
        payload: dict[str, Any] = {
            "ok": True,
            "action": action,
            "result": result,
            "work_status": self.work_status_payload(),
        }
        if isinstance(result, dict):
            for key in (
                "execution_mode",
                "runtime_tuning",
                "operator_intent",
                "credentials",
                "target",
                "scope",
                "scopePayload",
                "scopeProfiles",
                "models",
                "caido",
                "findings_context",
                "storage_status",
            ):
                if key in result:
                    payload[key] = result[key]
        return self._json_response(payload)

    def _scope_refresh_result(self, *, target=None) -> dict[str, Any]:
        scope_payload = self.runtime.scope_payload()
        scope_profiles = self.runtime.scope_profiles_payload()
        scope_targets = [item for item in scope_payload.get("targets", []) if self._target_handle(item)]
        return {
            "target": target.as_payload() if target is not None else None,
            "scope": self._scope_view(scope_targets),
            "scopePayload": scope_payload,
            "scopeProfiles": scope_profiles,
        }

    def _runtime_control_response(self, result: dict[str, Any]) -> WebResponse:
        return self._json_response(
            {
                "ok": True,
                "action": "runtime-control",
                "execution_mode": result["execution_mode"],
                "operator_intent": result["operator_intent"],
                "work_status": self.work_status_payload(),
            }
        )

    def _target_asset_rows(
        self,
        handle: str,
        active_ip: str | None,
        assets: list[Any],
    ) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        seen: set[str] = set()

        def add(asset: str, asset_type: str | None = None, metadata: dict[str, object] | None = None) -> None:
            raw_asset = str(asset or "").strip()
            if not raw_asset or raw_asset in seen:
                return
            seen.add(raw_asset)
            row: dict[str, object] = {"asset": raw_asset, "asset_type": asset_type or self.runtime._infer_asset_type(raw_asset)}
            if metadata:
                row["metadata"] = metadata
            rows.append(row)

        add(handle, "hostname")
        for item in assets:
            if isinstance(item, dict):
                add(
                    str(item.get("asset") or ""),
                    str(item.get("asset_type") or "") or None,
                    dict(item.get("metadata", {})) if isinstance(item.get("metadata"), dict) else None,
                )
            else:
                add(str(item or ""))
        if active_ip:
            add(active_ip, "ip", {"active": True, "operator_confirmed": True})
        return rows or [{"asset": handle, "asset_type": "hostname"}]

    def _static_asset_response(self, raw_path: str) -> WebResponse | None:
        asset = unquote(raw_path.lstrip("/"))
        if not asset or asset.endswith("/"):
            return self._static_response("index.html", "text/html; charset=utf-8")
        path = (self._static_dir / asset).resolve()
        try:
            path.relative_to(self._static_dir.resolve())
        except ValueError:
            return self._json_response({"error": "not found", "path": raw_path}, status=404)
        if not path.is_file():
            return self._static_response("index.html", "text/html; charset=utf-8")
        return self._file_response(path, self._content_type(path))

    def _static_response(self, filename: str, content_type: str) -> WebResponse:
        path = self._static_dir / filename
        if not path.exists():
            return self._json_response({"error": "asset missing", "asset": filename}, status=404)
        return self._file_response(path, content_type)

    def _file_response(self, path: Path, content_type: str) -> WebResponse:
        return WebResponse(
            status=200,
            body=path.read_bytes(),
            content_type=content_type,
            headers={"Cache-Control": "no-store"},
        )

    def _content_type(self, path: Path) -> str:
        suffix = path.suffix.lower()
        if suffix == ".html":
            return "text/html; charset=utf-8"
        if suffix == ".js":
            return "text/javascript; charset=utf-8"
        if suffix == ".css":
            return "text/css; charset=utf-8"
        if suffix == ".json":
            return "application/json; charset=utf-8"
        if suffix == ".svg":
            return "image/svg+xml"
        if suffix == ".png":
            return "image/png"
        if suffix in {".jpg", ".jpeg"}:
            return "image/jpeg"
        if suffix == ".woff2":
            return "font/woff2"
        return "application/octet-stream"

    def _json_response(self, payload: dict[str, Any], status: int = 200) -> WebResponse:
        return WebResponse(
            status=status,
            body=json.dumps(payload, indent=2, sort_keys=True).encode("utf-8"),
            content_type="application/json; charset=utf-8",
            headers={"Cache-Control": "no-store"},
        )

    def _parse_json_body(self, body: bytes) -> dict[str, Any]:
        if not body:
            return {}
        try:
            payload = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError("invalid JSON payload") from exc
        if not isinstance(payload, dict):
            raise ValueError("JSON payload must be an object")
        return payload

    def _int_param(self, query: dict[str, list[str]], name: str, default: int) -> int:
        raw = query.get(name, [])
        if not raw:
            return default
        try:
            return max(1, int(raw[0]))
        except ValueError:
            return default

    def _bool_param(self, query: dict[str, list[str]], name: str, default: bool) -> bool:
        raw = query.get(name, [])
        if not raw:
            return default
        return raw[0].strip().lower() in {"1", "true", "yes", "on"}

    def _optional_string(self, payload: dict[str, Any], key: str) -> str | None:
        value = payload.get(key)
        if value is None:
            return None
        return str(value).strip() or None

    def _optional_int(self, payload: dict[str, Any], key: str) -> int | None:
        value = payload.get(key)
        if value is None or value == "":
            return None
        return int(value)

    def _payload_list(self, payload: dict[str, Any], key: str) -> list[str]:
        value = payload.get(key)
        if value is None:
            return []
        if isinstance(value, list | tuple | set):
            return [str(item).strip() for item in value if str(item).strip()]
        return [str(value).strip()] if str(value).strip() else []

    def _rag_filters_payload(self, payload: dict[str, Any]) -> dict[str, object]:
        raw = payload.get("filters")
        filters: dict[str, object] = dict(raw) if isinstance(raw, dict) else {}
        for key in (
            "domain",
            "source_file",
            "doc_id",
            "chunk_type",
            "card_type",
            "risk_family",
            "output_mode",
            "source_priority",
        ):
            values = self._payload_list(payload, key)
            if values:
                filters[key] = values
        if "requires_authorized_scope" in payload:
            filters["requires_authorized_scope"] = bool(payload.get("requires_authorized_scope"))
        return filters

    def _rag_chunk_api_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        result = dict(payload)
        embedding = result.get("embedding")
        if isinstance(embedding, dict):
            result["embedding"] = {
                key: value
                for key, value in embedding.items()
                if key not in {"embedding", "vector", "values"}
            }
        return result

    def _optional_query_string(self, query: dict[str, list[str]], key: str) -> str | None:
        values = query.get(key, [])
        if not values:
            return None
        return values[0].strip() or None

    def _control_plane_payload(self, *, target: str | None = None, live_metrics: bool = False) -> dict[str, Any]:
        dashboard = self.runtime.dashboard_payload()
        if live_metrics:
            dashboard = dict(dashboard)
            dashboard["system_metrics"] = self.runtime.system_metrics_payload(force_refresh=True)
        work_status = self.work_status_payload()
        scope = self.runtime.scope_payload()
        scope_profiles = self.runtime.scope_profiles_payload()
        audit = self.runtime.audit_payload(limit=50)
        credentials = self.runtime.credentials_payload()
        caido_status = self.runtime.caido_status_payload(check_health=False)
        models = self.runtime.models_payload()
        intent = self.runtime.operator_intent_payload()
        execution_mode = self.runtime.execution_mode_payload()
        runtime_tuning = self.runtime.runtime_tuning_payload()
        storage_status = self.runtime.storage_status_payload()
        findings_context = self.runtime.findings_context_payload(include_guidance=False)
        skills = self.runtime.skills_payload(include_body=False)
        metrics = dashboard.get("system_metrics", {})
        counts = dashboard.get("counts", {}) if isinstance(dashboard.get("counts"), dict) else {}
        all_targets = [item for item in scope.get("targets", []) if self._target_handle(item)]
        selected_target = self._selected_target_filter(target, all_targets)
        targets = self._filter_scope_targets(all_targets, selected_target)
        selected_target_id = self._target_id_for_handle(selected_target, all_targets)
        records = self.runtime.records_payload(limit=100, target_id=selected_target_id)
        task_items = self._tasks_view(dashboard, work_status, targets)
        if selected_target:
            task_items = [item for item in task_items if item.get("target") == selected_target]
        approval_items = self._approvals_view(work_status, task_items)
        event_items = self._events_view(audit)
        notes = self._notes_view(targets, findings_context, credentials, audit)
        interests = self._interests_view(records, targets)
        graph = self._graph_view(targets, records)
        traces = self._traces_view(audit, task_items, selected_target=selected_target)
        geo = self._geo_view(targets, caido_status, models)
        model_rows = self._models_view(models)
        plan = self._plan_view(intent, dashboard, skills, work_status, records)
        network = metrics.get("network", {}) if isinstance(metrics.get("network"), dict) else {}
        gpu_metrics = metrics.get("gpu", {}) if isinstance(metrics.get("gpu"), dict) else {}
        gpu_memory = self._gpu_memory_payload(gpu_metrics)
        premium_wrapper = self._premium_wrapper_payload()

        return {
            "mode": "real",
            "runtime": {
                "autonomy": str(self.runtime.config.autonomy.mode.value),
                "intent": str(intent.get("active", {}).get("id") or intent.get("default") or "recon_only"),
                "health": str(self.runtime.health_payload().get("status", "ok")).upper(),
                "uptime": "live",
                "cpu": self._metric_ratio(metrics, "cpu"),
                "gpu": self._metric_ratio(metrics, "gpu"),
                "mem": self._memory_ratio(metrics),
                "diskWrites": int(counts.get("events", 0) or 0),
                "netIn": str(network.get("rx_label") or "0 B/s"),
                "netOut": str(network.get("tx_label") or "0 B/s"),
                "gpuMemory": gpu_memory,
                "activeTasks": int(work_status.get("counts", {}).get("active", 0) or 0),
                "queued": int(work_status.get("counts", {}).get("queued", 0) or 0),
                "approvals": len(approval_items),
                "counts": counts,
                "executionMode": execution_mode,
                "runtimeTuning": runtime_tuning,
                "operatorIntent": intent,
                "workStatus": work_status,
                "systemMetrics": metrics,
                "premiumWrapper": premium_wrapper,
                "storage": storage_status,
            },
            "models": model_rows,
            "modelPayload": models,
            "tasks": task_items,
            "approvals": approval_items,
            "events": event_items,
            "scope": self._scope_view(targets),
            "scopePayload": scope,
            "scopeProfiles": scope_profiles,
            "graph": graph,
            "traces": traces,
            "traceMeta": {
                "selectedTarget": selected_target or "",
                "targetOptions": [{"id": "", "label": "All targets"}]
                + [{"id": self._target_handle(item), "label": self._target_handle(item)} for item in all_targets],
                "grouped": True,
                "defaultLimit": 40,
            },
            "geo": geo,
            "plan": plan,
            "notes": notes,
            "interests": interests,
            "caido": self._caido_view(caido_status, records, targets),
            "approvalChat": self._approval_chat_view(approval_items),
            "inquiryChat": self._operator_chat_view(),
            "signals": self._signals_view(audit),
            "credentials": credentials,
            "storage_status": storage_status,
            "selfTest": {"status": "not_run", "checks": [], "summary": {}},
            "api": {
                "generatedAt": datetime.now(timezone.utc).isoformat(),
                "endpoints": {
                    "controlPlane": "/api/control-plane",
                    "tick": "/api/actions/tick",
                    "stopWork": "/api/actions/stop-work",
                    "compact": "/api/actions/compact",
                    "processQueues": "/api/actions/process-queues",
                    "warmModels": "/api/actions/warm-models",
                    "clearModels": "/api/actions/clear-models",
                    "uiCommands": "/api/ui/commands",
                    "ragStatus": "/api/rag/status",
                    "ragConfig": "/api/rag/config",
                    "ragImport": "/api/rag/import",
                    "ragSearch": "/api/rag/search",
                    "ragSynthesize": "/api/rag/synthesize",
                },
            },
        }

    def _system_metrics_payload(self) -> dict[str, Any]:
        metrics = self.runtime.system_metrics_payload(force_refresh=True)
        network = metrics.get("network", {}) if isinstance(metrics.get("network"), dict) else {}
        gpu_metrics = metrics.get("gpu", {}) if isinstance(metrics.get("gpu"), dict) else {}
        return {
            "systemMetrics": metrics,
            "runtime": {
                "cpu": self._metric_ratio(metrics, "cpu"),
                "gpu": self._metric_ratio(metrics, "gpu"),
                "mem": self._memory_ratio(metrics),
                "netIn": str(network.get("rx_label") or "0 B/s"),
                "netOut": str(network.get("tx_label") or "0 B/s"),
                "gpuMemory": self._gpu_memory_payload(gpu_metrics),
            },
        }

    def _models_view(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        roles = payload.get("roles", [])
        if not isinstance(roles, list):
            return []
        ollama = payload.get("ollama", {}) if isinstance(payload.get("ollama"), dict) else {}
        return [
            {
                "route": str(role.get("role", "")),
                "label": str(role.get("label", role.get("role", ""))),
                "model": str(role.get("selected_model") or role.get("default_model") or ""),
                "loaded": bool(ollama.get("ok")),
                "hot": bool(ollama.get("ok")),
                "ctx": int(role.get("context_window", 0) or 0),
                "processor": str(role.get("processor", "")),
                "available": payload.get("available_models", []),
                "metrics": role.get("metrics"),
            }
            for role in roles
            if isinstance(role, dict)
        ]

    def _intent_policy_flags(self, policy: dict[str, Any]) -> dict[str, bool]:
        kerberos = policy.get("kerberos_policy", {}) if isinstance(policy.get("kerberos_policy"), dict) else {}
        credential = policy.get("credential_policy", {}) if isinstance(policy.get("credential_policy"), dict) else {}
        lab = policy.get("lab_policy", {}) if isinstance(policy.get("lab_policy"), dict) else {}
        return {
            "public_poc_research": bool(policy.get("public_poc_research")),
            "searchsploit_allowed": bool(policy.get("searchsploit_allowed")),
            "read_poc_examples": bool(policy.get("read_poc_examples")),
            "poc_applicability_validation": bool(policy.get("poc_applicability_validation")),
            "exploit_code_generation": bool(policy.get("exploit_code_generation")),
            "poc_execution": bool(policy.get("poc_execution")),
            "credential_validation": bool(credential.get("credential_validation_allowed")),
            "credential_guessing": bool(credential.get("credential_guessing_allowed")),
            "credential_spraying": bool(credential.get("credential_spraying_allowed")),
            "hash_cracking": bool(credential.get("hash_cracking_allowed")),
            "kerberos_asrep_roast": bool(kerberos.get("asrep_roast_check_allowed")),
            "kerberos_kerberoast": bool(kerberos.get("kerberoast_check_allowed")),
            "lab_flag_collection": bool(lab.get("lab_flag_collection_allowed")),
            "htb_lab_behavior": bool(lab.get("htb_lab_behavior_allowed")),
            "reverse_shell": bool(lab.get("reverse_shell_allowed")),
        }

    def _selected_target_filter(self, target: str | None, targets: list[dict[str, Any]]) -> str | None:
        selected = str(target or "").strip()
        if not selected or selected == "*":
            return None
        handles = {self._target_handle(item) for item in targets}
        return selected if selected in handles else None

    def _filter_scope_targets(
        self,
        targets: list[dict[str, Any]],
        selected_target: str | None,
    ) -> list[dict[str, Any]]:
        if not selected_target:
            return targets
        return [item for item in targets if self._target_handle(item) == selected_target]

    def _target_id_for_handle(self, handle: str | None, targets: list[dict[str, Any]]) -> str | None:
        if not handle:
            return None
        for item in targets:
            target = item.get("target", {}) if isinstance(item.get("target"), dict) else {}
            if str(target.get("handle") or "") == handle:
                return str(target.get("id") or "") or None
        return None

    def _gpu_memory_payload(self, gpu: dict[str, Any]) -> dict[str, Any]:
        used = gpu.get("memory_used_mb")
        free = gpu.get("memory_free_mb")
        total = gpu.get("memory_total_mb")
        percent = gpu.get("memory_percent")
        try:
            percent_value = float(percent) if percent is not None else 0.0
        except (TypeError, ValueError):
            percent_value = 0.0
        used_label = "unavailable"
        free_label = "unavailable"
        if isinstance(used, (int, float)) and isinstance(total, (int, float)):
            used_label = f"{used:.0f} / {total:.0f} MB"
        if isinstance(free, (int, float)):
            free_label = f"{free:.0f} MB"
        return {
            "percent": max(0.0, min(100.0, percent_value)),
            "used_mb": used,
            "free_mb": free,
            "total_mb": total,
            "used_label": used_label,
            "free_label": free_label,
        }

    def _premium_wrapper_payload(self) -> dict[str, Any]:
        local_wrapper_available = self.runtime.worker_broker.has_runner_for(
            route=ProviderRoute.REMOTE_PREMIUM,
            kind=TaskKind.REVIEW_PREMIUM_ESCALATION,
            role=AgentRole.CLAUDE_REVIEWER,
            runner_id="agent-chat-premium-runner",
        )
        remote_enabled = bool(self.runtime.config.autonomy.allow_remote_premium)
        if local_wrapper_available:
            status = "local wrapper"
            label = "agent_chat_api wrapper"
            detail = (
                "Claude/GPT review tasks route through agent_chat_api; wrapper-backed reviews "
                "are not blocked by the remote premium flag or daily remote budget gate."
            )
            tone = "cyan"
        elif remote_enabled:
            status = "remote enabled"
            label = "remote_premium"
            detail = "Claude/GPT review tasks use the configured remote premium route."
            tone = "green"
        else:
            status = "disabled"
            label = "remote_premium"
            detail = "Claude/GPT review tasks require either the local wrapper runner or remote premium approval."
            tone = "gray"
        return {
            "status": status,
            "label": label,
            "detail": detail,
            "tone": tone,
            "provider_route": ProviderRoute.REMOTE_PREMIUM.value,
            "task_kind": TaskKind.REVIEW_PREMIUM_ESCALATION.value,
            "agent_role": AgentRole.CLAUDE_REVIEWER.value,
            "runner_id": "agent-chat-premium-runner" if local_wrapper_available else "",
            "local_chat_wrapper": "agent_chat_api" if local_wrapper_available else "",
            "local_wrapper_available": local_wrapper_available,
            "remote_premium_flag_enabled": remote_enabled,
            "remote_premium_policy_gate_bypassed_for_wrapper": local_wrapper_available,
            "remote_premium_budget_gate_bypassed_for_wrapper": local_wrapper_available,
        }

    def _tasks_view(
        self,
        dashboard: dict[str, Any],
        work_status: dict[str, Any],
        targets: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        by_id: dict[str, dict[str, Any]] = {}
        for group in ("active", "queued", "waiting", "recent"):
            for item in work_status.get(group, []) if isinstance(work_status.get(group, []), list) else []:
                if not isinstance(item, dict):
                    continue
                task_id = str(item.get("task_id") or item.get("run_id") or "")
                if not task_id:
                    continue
                by_id[task_id] = {
                    "id": task_id,
                    "kind": str(item.get("task_kind") or item.get("kind") or "task"),
                    "route": str(item.get("route") or ""),
                    "status": self._task_status_for_gui(str(item.get("status") or "")),
                    "target": str(item.get("target") or "*"),
                    "model": str(item.get("model") or ""),
                    "title": str(item.get("title") or item.get("summary") or task_id),
                    "ms": 0,
                    "raw": item,
                }
        target_lookup = self._target_lookup(targets)
        for task in dashboard.get("tasks", []) if isinstance(dashboard.get("tasks", []), list) else []:
            if not isinstance(task, dict):
                continue
            task_id = str(task.get("id") or "")
            if not task_id:
                continue
            target = target_lookup.get(str(task.get("target_id") or ""), "*")
            by_id.setdefault(
                task_id,
                {
                    "id": task_id,
                    "kind": str(task.get("kind") or "task"),
                    "route": str(task.get("provider_route") or ""),
                    "status": self._task_status_for_gui(str(task.get("status") or "")),
                    "target": target,
                    "model": str(task.get("provider_model") or ""),
                    "title": str(task.get("title") or task.get("summary") or task_id),
                    "ms": 0,
                    "raw": task,
                },
        )
        items = [item for item in by_id.values() if not self._hide_task_item(item)]
        for item in items:
            self._decorate_task_wrapper(item)
            hint = self._task_hint(item)
            if hint:
                item["hint"] = hint
        return self._group_task_items(items)[:100]

    def _decorate_task_wrapper(self, item: dict[str, Any]) -> None:
        raw = item.get("raw", {}) if isinstance(item.get("raw"), dict) else {}
        metadata = raw.get("metadata", {}) if isinstance(raw.get("metadata"), dict) else {}
        wrapper = str(metadata.get("local_chat_wrapper") or "")
        local_wrapper = bool(metadata.get("remote_premium_local_wrapper"))
        if not wrapper and local_wrapper:
            wrapper = "agent_chat_api"
        item["local_chat_wrapper"] = wrapper
        item["remote_premium_local_wrapper"] = local_wrapper
        if wrapper and local_wrapper:
            item["wrapper_label"] = f"{wrapper} wrapper"
            item["wrapper_detail"] = (
                "Claude/GPT review is routed through the local chat wrapper; "
                "remote premium flag and budget gates do not block this task."
            )

    def _hide_task_item(self, item: dict[str, Any]) -> bool:
        raw = item.get("raw", {}) if isinstance(item.get("raw"), dict) else {}
        metadata = raw.get("metadata", {}) if isinstance(raw.get("metadata"), dict) else {}
        if raw.get("invalid_target") or metadata.get("invalid_target"):
            return True
        if (
            item.get("target") in {"", "*"}
            and item.get("kind") == TaskKind.RECON_SCAN.value
            and item.get("status") in {"blocked", "failed"}
        ):
            return True
        return False

    def _task_hint(self, item: dict[str, Any]) -> str:
        if (
            item.get("status") == "queued"
            and item.get("route") == "local_compact"
            and item.get("model") == "phi4-reasoning"
        ):
            return "Missing local model hint: phi4-reasoning is selected for local_compact; warm/install it or change the role."
        return ""

    def _group_task_items(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        grouped: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
        for item in items:
            if item.get("status") != "done":
                continue
            key = self._task_group_key(item)
            grouped.setdefault(key, []).append(item)

        result: list[dict[str, Any]] = []
        emitted: set[tuple[str, str, str, str]] = set()
        for item in items:
            if item.get("status") != "done":
                result.append(item)
                continue
            key = self._task_group_key(item)
            members = grouped.get(key, [])
            if len(members) <= 1:
                result.append(item)
                continue
            if key in emitted:
                continue
            emitted.add(key)
            first = members[0]
            result.append(
                {
                    **first,
                    "id": f"group:{key[0]}:{key[1]}:{key[2]}:{key[3]}",
                    "title": f"{first.get('kind', 'task')} completed {len(members)} times",
                    "grouped": True,
                    "grouped_count": len(members),
                    "raw": {"grouped_task_ids": [member.get("id") for member in members], "sample": first.get("raw", {})},
                }
            )
        return result

    def _task_group_key(self, item: dict[str, Any]) -> tuple[str, str, str, str]:
        raw = item.get("raw", {}) if isinstance(item.get("raw"), dict) else {}
        metadata = raw.get("metadata", {}) if isinstance(raw.get("metadata"), dict) else {}
        generation = str(raw.get("active_ip_generation") or metadata.get("active_ip_generation") or "")
        return (
            str(item.get("target") or "*"),
            str(item.get("kind") or "task"),
            str(item.get("route") or ""),
            generation,
        )

    def _approvals_view(self, work_status: dict[str, Any], tasks: list[dict[str, Any]]) -> list[dict[str, Any]]:
        pending = []
        waiting = work_status.get("waiting", []) if isinstance(work_status.get("waiting", []), list) else []
        for item in waiting:
            if not isinstance(item, dict):
                continue
            task_id = str(item.get("task_id") or "")
            if not task_id:
                continue
            pending.append(
                {
                    "id": task_id,
                    "risk": "med",
                    "task": task_id,
                    "title": str(item.get("title") or "Approval required"),
                    "detail": str(item.get("summary") or "Task is waiting for operator approval."),
                    "reason": str(item.get("worker_contract") or "Runtime policy requires explicit operator decision."),
                    "target": str(item.get("target") or "*"),
                    "primitive": str(item.get("task_kind") or "task"),
                    "limits": "bounded by active operator intent",
                }
            )
        if pending:
            return pending[:50]
        return [
            {
                "id": item["id"],
                "risk": "low",
                "task": item["id"],
                "title": item["title"],
                "detail": item.get("raw", {}).get("summary") or item["title"],
                "reason": "No pending approval; shown for inspection only.",
                "target": item.get("target", "*"),
                "primitive": item.get("kind", "task"),
                "limits": "not blocked",
            }
            for item in tasks
            if item.get("status") == "await_approval"
        ][:50]

    def _events_view(self, audit: dict[str, Any]) -> list[dict[str, str]]:
        events: list[dict[str, str]] = []
        for item in audit.get("recent_events", []) if isinstance(audit.get("recent_events", []), list) else []:
            if not isinstance(item, dict):
                continue
            events.append(
                {
                    "t": self._time_label(item.get("created_at")),
                    "lvl": self._event_level(str(item.get("type", ""))),
                    "msg": str(item.get("summary") or item.get("type") or "event"),
                }
            )
        for item in audit.get("recent_runtime_events", []) if isinstance(audit.get("recent_runtime_events", []), list) else []:
            if not isinstance(item, dict):
                continue
            events.append(
                {
                    "t": self._time_label(item.get("created_at")),
                    "lvl": "info",
                    "msg": str(item.get("signal") or "runtime event"),
                }
            )
        return events[:80]

    def _scope_view(self, targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
        rows = []
        for item in targets:
            target = item.get("target", {}) if isinstance(item.get("target"), dict) else {}
            counts = item.get("counts", {}) if isinstance(item.get("counts"), dict) else {}
            assets = item.get("assets", []) if isinstance(item.get("assets"), list) else []
            rows.append(
                {
                    "handle": str(target.get("handle") or ""),
                    "profile": str(target.get("profile") or ""),
                    "ip": str(target.get("metadata", {}).get("active_ip") or self._first_asset(assets, "ip") or ""),
                    "assets": int(counts.get("assets", len(assets)) or 0),
                    "evidence": int(counts.get("evidence", 0) or 0),
                    "findings": int(counts.get("findings", 0) or 0),
                    "status": "active" if target.get("in_scope", True) else "paused",
                }
            )
        return rows

    def _graph_view(self, targets: list[dict[str, Any]], records: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []
        x = 180
        y = 90
        for index, item in enumerate(targets):
            target = item.get("target", {}) if isinstance(item.get("target"), dict) else {}
            handle = str(target.get("handle") or "")
            if not handle:
                continue
            node_id = f"target_{index}"
            nodes.append({"id": node_id, "kind": "domain", "label": handle, "sub": str(target.get("profile") or ""), "x": x, "y": y})
            assets = item.get("assets", []) if isinstance(item.get("assets"), list) else []
            for asset_index, asset in enumerate(assets[:12]):
                if not isinstance(asset, dict):
                    continue
                kind = "host" if asset.get("asset_type") == "ip" else "svc" if asset.get("asset_type") in {"url", "webapp"} else "domain"
                asset_id = f"{node_id}_asset_{asset_index}"
                nodes.append(
                    {
                        "id": asset_id,
                        "kind": kind,
                        "label": str(asset.get("asset") or ""),
                        "sub": str(asset.get("asset_type") or "asset"),
                        "x": x + 220 + (asset_index % 4) * 150,
                        "y": y + (asset_index // 4) * 95,
                    }
                )
                edges.append({"a": node_id, "b": asset_id, "label": "scope"})
            x += 150
            y += 90
        for index, finding in enumerate(records.get("findings", []) if isinstance(records.get("findings", []), list) else []):
            if not isinstance(finding, dict):
                continue
            node_id = f"finding_{index}"
            nodes.append(
                {
                    "id": node_id,
                    "kind": "finding",
                    "label": str(finding.get("title") or finding.get("id") or "finding"),
                    "sub": str(finding.get("severity") or finding.get("status") or ""),
                    "x": 280 + (index % 5) * 180,
                    "y": 440 + (index // 5) * 90,
                }
            )
        return {"nodes": nodes, "edges": edges}

    def _traces_view(
        self,
        audit: dict[str, Any],
        tasks: list[dict[str, Any]],
        *,
        selected_target: str | None = None,
    ) -> list[dict[str, Any]]:
        tasks_by_id = {str(item.get("id") or ""): item for item in tasks}
        grouped: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
        recent = audit.get("recent_traces", []) if isinstance(audit.get("recent_traces", []), list) else []
        for index, trace in enumerate(recent):
            if not isinstance(trace, dict):
                continue
            metadata = trace.get("metadata", {}) if isinstance(trace.get("metadata"), dict) else {}
            task_id = str(trace.get("task_id") or "")
            task = tasks_by_id.get(task_id, {})
            target = str(metadata.get("target") or task.get("target") or "*")
            if selected_target and target != selected_target:
                continue
            kind = str(metadata.get("task_type") or metadata.get("summary_key") or metadata.get("stage") or trace.get("role") or "trace")
            status = self._trace_status_for_gui(str(trace.get("status") or "pass"))
            summary = str(trace.get("summary") or metadata.get("summary") or "Runtime trace")
            route = str(metadata.get("route") or metadata.get("provider_route") or task.get("route") or "")
            model = str(metadata.get("model") or task.get("model") or "")
            created_at = str(trace.get("created_at") or "")
            key = (target, task_id, kind, summary, status)
            if key not in grouped:
                grouped[key] = {
                    "id": str(trace.get("id") or f"trace_{index}"),
                    "kind": kind,
                    "status": status,
                    "time": self._time_label(created_at),
                    "summary": summary,
                    "task": task_id,
                    "target": target,
                    "route": route,
                    "model": model,
                    "count": 1,
                    "first_at": created_at,
                    "last_at": created_at,
                    "latest_status": status,
                    "repeated": False,
                }
            else:
                item = grouped[key]
                item["count"] = int(item.get("count", 1) or 1) + 1
                item["last_at"] = max(str(item.get("last_at") or ""), created_at)
                item["time"] = self._time_label(item["last_at"])
                item["latest_status"] = status
                item["repeated"] = True
        children = sorted(grouped.values(), key=lambda item: str(item.get("last_at") or ""), reverse=True)[:40]
        if not children:
            children = [
                {
                    "id": f"task_trace_{index}",
                    "kind": item.get("kind", "task"),
                    "status": self._trace_status_for_gui(item.get("status", "queued")),
                    "time": "live",
                    "summary": item.get("title", "Task"),
                    "task": item.get("id", ""),
                    "target": item.get("target", "*"),
                    "route": item.get("route", ""),
                    "model": item.get("model", ""),
                    "count": 1,
                }
                for index, item in enumerate(tasks[:16])
                if not selected_target or item.get("target") == selected_target
            ]
        active = [item for item in children if item.get("status") == "run"]
        idle_reason = "No active run for selected target." if selected_target else "No active run exists."
        if not children:
            children = [{
                "id": "trace_empty",
                "kind": "workflow.idle",
                "status": "queued",
                "time": "idle",
                "summary": idle_reason,
                "task": "",
                "target": selected_target or "*",
                "route": "",
                "model": "",
                "count": 1,
            }]
        return [
            {
                "id": "tr_root",
                "kind": "workflow.runtime",
                "status": "run" if active else "queued",
                "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                "summary": f"Active runtime trace: {len(active)} running" if active else f"Idle/stale: {idle_reason}",
                "route": "",
                "model": "",
                "target": selected_target or "*",
                "active": bool(active),
                "idle_reason": None if active else idle_reason,
                "children": children,
            }
        ]

    def _plan_view(
        self,
        intent: dict[str, Any],
        dashboard: dict[str, Any],
        skills: dict[str, Any],
        work_status: dict[str, Any],
        records: dict[str, Any],
    ) -> dict[str, Any]:
        active_intent = intent.get("active", {}) if isinstance(intent.get("active"), dict) else {}
        policy = active_intent.get("policy", {}) if isinstance(active_intent.get("policy"), dict) else {}
        task_counts = work_status.get("counts", {}) if isinstance(work_status.get("counts"), dict) else {}
        total_tasks = int(task_counts.get("active", 0) or 0) + int(task_counts.get("queued", 0) or 0) + int(task_counts.get("waiting", 0) or 0)
        return {
            "methodology": {
                "id": str(dashboard.get("sessions", [{}])[0].get("methodology", "runtime") if dashboard.get("sessions") else "runtime"),
                "label": "Runtime Methodology",
                "description": "Live methodology state derived from runtime tasks and target progress.",
                "phases": [
                    {"id": "active", "label": "Active", "status": "active" if total_tasks else "done", "tasks": total_tasks, "done": 0},
                    {"id": "waiting", "label": "Waiting", "status": "active" if task_counts.get("waiting") else "done", "tasks": int(task_counts.get("waiting", 0) or 0), "done": 0},
                    {"id": "queued", "label": "Queued", "status": "active" if task_counts.get("queued") else "done", "tasks": int(task_counts.get("queued", 0) or 0), "done": 0},
                    {"id": "complete", "label": "Complete", "status": "done", "tasks": len(records.get("evidence", []) or []), "done": len(records.get("evidence", []) or [])},
                ],
            },
            "intent": {
                "id": str(active_intent.get("id") or "recon_only"),
                "label": str(active_intent.get("label") or active_intent.get("id") or "Recon Only"),
                "flags": self._intent_policy_flags(policy),
                "policy": policy,
            },
            "autonomy": str(self.runtime.config.autonomy.mode.value),
            "autonomyModes": ["manual", "assisted", "supervised", "supervised_auto", "high_autonomy"],
            "pinnedAssets": self._pinned_assets_view(records),
            "playbooks": self._playbooks_view(skills),
            "skills": self._skills_view(skills),
            "criticalThinking": self._critical_thinking_view(work_status),
        }

    def _notes_view(
        self,
        targets: list[dict[str, Any]],
        findings_context: dict[str, Any],
        credentials: dict[str, Any],
        audit: dict[str, Any],
    ) -> dict[str, Any]:
        credential_services = credentials.get("services", {}) if isinstance(credentials.get("services"), dict) else {}
        notion_fields = credential_services.get("notion", {}) if isinstance(credential_services.get("notion"), dict) else {}
        notion_configured = any(
            isinstance(field, dict) and field.get("configured")
            for field in notion_fields.values()
        )
        target_rows = []
        folders = []
        pages: dict[str, dict[str, str]] = {}
        context_targets = findings_context.get("targets", []) if isinstance(findings_context.get("targets", []), list) else []
        context_by_id = {
            str(item.get("target", {}).get("id") or item.get("target", {}).get("handle")): item.get("workspace", {})
            for item in context_targets
            if isinstance(item, dict) and isinstance(item.get("target"), dict)
        }
        for index, item in enumerate(targets):
            target = item.get("target", {}) if isinstance(item.get("target"), dict) else {}
            handle = str(target.get("handle") or "")
            if not handle:
                continue
            target_rows.append(
                {
                    "id": handle,
                    "label": str(target.get("display_name") or handle),
                    "profile": str(target.get("profile") or ""),
                    "active": index == 0,
                }
            )
            root_id = f"{handle}_root"
            page_id = f"{handle}_findings"
            folders.append(
                {
                    "id": root_id,
                    "label": f"{handle} Workspace",
                    "target": handle,
                    "kind": "target-root",
                    "synced": False,
                    "url": "#",
                    "children": [
                        {"id": page_id, "label": "Findings Context", "kind": "findings", "synced": False, "url": "#"},
                    ],
                }
            )
            workspace = context_by_id.get(str(target.get("id")), {})
            pages[page_id] = {
                "title": f"{handle} Findings Context",
                "body": self._workspace_body(target, workspace),
            }
        if not target_rows:
            pages["workspace_empty"] = {
                "title": "Findings Context",
                "body": "No targets are currently registered in the runtime.",
            }
        return {
            "targets": target_rows,
            "syncStatus": {
                "ok": notion_configured,
                "lastSync": self._time_label((audit.get("recent_sync_jobs") or [{}])[0].get("updated_at") if audit.get("recent_sync_jobs") else None),
                "pendingJobs": 0,
                "failedJobs": len(audit.get("recent_sync_jobs", []) or []),
                "configured": notion_configured,
            },
            "folders": folders,
            "pages": pages,
        }

    def _interests_view(self, records: dict[str, Any], targets: list[dict[str, Any]]) -> dict[str, Any]:
        surfaces = []
        for index, item in enumerate(targets):
            target = item.get("target", {}) if isinstance(item.get("target"), dict) else {}
            assets = item.get("assets", []) if isinstance(item.get("assets"), list) else []
            handle = str(target.get("handle") or "")
            for asset in assets[:20]:
                if not isinstance(asset, dict):
                    continue
                surfaces.append(
                    {
                        "id": str(asset.get("id") or f"srf_{index}_{len(surfaces)}"),
                        "target": handle,
                        "kind": str(asset.get("asset_type") or "asset"),
                        "ports": str(asset.get("metadata", {}).get("ports") or "*"),
                        "severity": "info",
                        "status": "active" if target.get("in_scope", True) else "paused",
                        "desc": str(asset.get("asset") or ""),
                    }
                )
        findings = [
            {
                "id": str(item.get("id") or ""),
                "severity": str(item.get("severity") or "info"),
                "title": str(item.get("title") or "Finding"),
                "status": str(item.get("verification_status") or item.get("status") or "unverified"),
                "evidence": item.get("evidence_ids", []) if isinstance(item.get("evidence_ids", []), list) else [],
                "desc": str(item.get("summary") or item.get("description") or ""),
            }
            for item in records.get("findings", []) if isinstance(item, dict)
        ]
        pocs = [
            {
                "id": str(item.get("id") or ""),
                "edb": str(item.get("metadata", {}).get("edb") or "N/A"),
                "title": str(item.get("title") or item.get("summary") or "Interest"),
                "platform": str(item.get("metadata", {}).get("platform") or ""),
                "status": str(item.get("status") or "open"),
                "gated": bool(item.get("metadata", {}).get("gated", False)),
                "applicability": str(item.get("summary") or item.get("description") or ""),
                "evidence": item.get("evidence_ids", []) if isinstance(item.get("evidence_ids", []), list) else [],
                "generated": False,
                "downloadable": False,
            }
            for item in records.get("interests", []) if isinstance(item, dict)
        ]
        artifacts = [
            {
                "id": str(item.get("id") or ""),
                "kind": str(item.get("kind") or "artifact"),
                "task": str(item.get("task_id") or ""),
                "title": str(item.get("title") or item.get("path") or "Artifact"),
                "target": str(item.get("target_id") or ""),
                "size": str(item.get("size") or ""),
                "downloadable": False,
            }
            for item in records.get("artifacts", []) if isinstance(item, dict)
        ]
        return {"surfaces": surfaces, "findings": findings, "pocs": pocs, "artifacts": artifacts}

    def _caido_view(self, status: dict[str, Any], records: dict[str, Any], targets: list[dict[str, Any]]) -> dict[str, Any]:
        scope_rows = self._scope_view(targets)
        host = scope_rows[0]["handle"] if scope_rows else ""
        presets_payload = self.runtime.caido_httpql_presets()
        requests = [
            {
                "id": str(item.get("id") or f"req_{index}"),
                "caidoRequestId": str(item.get("metadata", {}).get("caido_request_id") or ""),
                "method": str(item.get("metadata", {}).get("method") or item.get("type") or "GET"),
                "host": str(item.get("metadata", {}).get("host") or host),
                "path": str(item.get("metadata", {}).get("path") or item.get("title") or "/"),
                "status": int(item.get("metadata", {}).get("status_code", 0) or 0),
                "length": len(str(item.get("metadata", {}).get("response_snippet") or "")),
                "time": self._time_label(item.get("created_at")),
                "source": "imported",
                "mime": str(item.get("metadata", {}).get("content_type") or ""),
                "requestSnippet": str(item.get("metadata", {}).get("request_snippet") or ""),
                "responseSnippet": str(item.get("metadata", {}).get("response_snippet") or ""),
            }
            for index, item in enumerate(records.get("evidence", []) if isinstance(records.get("evidence", []), list) else [])
            if isinstance(item, dict) and str(item.get("type", "")).lower() == "http_replay"
        ][:50]
        return {
            "connection": status,
            "requests": requests,
            "replays": [],
            "savedFilters": presets_payload.get("presets", []),
            "targetOptions": presets_payload.get("targets", []),
        }

    def _geo_view(self, targets: list[dict[str, Any]], caido_status: dict[str, Any], models: dict[str, Any]) -> dict[str, Any]:
        pins = [
            {
                "id": "g_self",
                "kind": "self",
                "label": "operator",
                "city": "local runtime",
                "country": "control-plane",
                "lat": 0.0,
                "lon": 0.0,
                "asn": "local",
                "org": "Primordial",
                "status": "live",
                "geolocated": False,
            }
        ]
        for index, row in enumerate(self._scope_view(targets)):
            lat, lon = self._synthetic_map_coordinate(index)
            pins.append(
                {
                    "id": f"g_target_{index}",
                    "kind": "target",
                    "label": row["handle"] if not row["ip"] else f"{row['handle']} ({row['ip']})",
                    "city": "unresolved",
                    "country": "scope",
                    "lat": lat,
                    "lon": lon,
                    "asn": "scope",
                    "org": row["profile"] or "scoped target",
                    "status": row["status"],
                    "geolocated": False,
                }
            )
        if caido_status.get("configured"):
            pins.append(
                {
                    "id": "g_caido",
                    "kind": "tool",
                    "label": "caido",
                    "city": "localhost",
                    "country": "control-plane",
                    "lat": 0.08,
                    "lon": -0.08,
                    "asn": "local",
                    "org": "Caido",
                    "status": "live" if caido_status.get("ok") else "idle",
                    "geolocated": False,
                }
            )
        if models.get("ollama", {}).get("ok"):
            pins.append(
                {
                    "id": "g_ollama",
                    "kind": "tool",
                    "label": "ollama",
                    "city": "localhost",
                    "country": "control-plane",
                    "lat": -0.08,
                    "lon": 0.08,
                    "asn": "local",
                    "org": "Ollama",
                    "status": "live",
                    "geolocated": False,
                }
            )
        return {
            "pins": pins,
            "traces": [{"from": "g_self", "to": pin["id"], "kind": "ok", "label": "scope"} for pin in pins if pin["id"] != "g_self"],
            "asns": [{"num": "local", "org": "Local runtime", "country": "local", "refs": len(pins), "role": "operator"}],
        }

    def _synthetic_map_coordinate(self, index: int) -> tuple[float, float]:
        offsets = [
            (0.12, 0.0),
            (0.0, 0.12),
            (-0.12, 0.0),
            (0.0, -0.12),
            (0.12, 0.12),
            (-0.12, 0.12),
            (-0.12, -0.12),
            (0.12, -0.12),
        ]
        lat, lon = offsets[index % len(offsets)]
        ring = index // len(offsets)
        if ring:
            lat += min(1.0, ring * 0.08)
            lon -= min(1.0, ring * 0.08)
        return lat, lon

    def _approval_chat_view(self, approvals: list[dict[str, Any]]) -> list[dict[str, str]]:
        if not approvals:
            return [{"who": "system", "t": self._time_label(None), "text": "No pending approvals."}]
        return [
            {
                "who": "system",
                "t": self._time_label(None),
                "text": f"Approval pending: {item['title']} ({item['id']})",
            }
            for item in approvals[:8]
        ]

    def _operator_chat_view(self) -> list[dict[str, str]]:
        try:
            messages = self.runtime.operator_chat_payload(limit=20).get("messages", [])
        except Exception:
            messages = []
        rows = []
        for item in messages if isinstance(messages, list) else []:
            if not isinstance(item, dict):
                continue
            rows.append(
                {
                    "who": "me" if item.get("role") == "operator" else "agent",
                    "t": self._time_label(item.get("created_at")),
                    "text": str(item.get("body") or ""),
                    "model": str(item.get("model") or ""),
                }
            )
        return rows or [{"who": "system", "t": self._time_label(None), "text": "Operator chat is ready."}]

    def _signals_view(self, audit: dict[str, Any]) -> list[str]:
        signals = [
            str(item.get("signal"))
            for item in audit.get("recent_runtime_events", []) if isinstance(item, dict) and item.get("signal")
        ]
        return signals[:20]

    def _skills_view(self, skills: dict[str, Any]) -> list[dict[str, Any]]:
        rows = []
        for item in skills.get("skills", []) if isinstance(skills.get("skills", []), list) else []:
            if not isinstance(item, dict):
                continue
            rows.append(
                {
                    "id": str(item.get("id") or item.get("name") or ""),
                    "title": str(item.get("title") or item.get("name") or item.get("id") or "Skill"),
                    "summary": str(item.get("summary") or item.get("description") or ""),
                    "tags": item.get("tags", []) if isinstance(item.get("tags", []), list) else [],
                }
            )
        return rows

    def _playbooks_view(self, skills: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            {
                "id": "runtime",
                "label": "Runtime Planning",
                "desc": "Live workflow planner and policy-gated task execution.",
                "status": "active",
                "tasks": [item["id"] for item in self._skills_view(skills)[:6]],
            }
        ]

    def _pinned_assets_view(self, records: dict[str, Any]) -> list[dict[str, Any]]:
        pins = []
        for kind in ("evidence", "interests", "findings", "artifacts"):
            for item in records.get(kind, []) if isinstance(records.get(kind, []), list) else []:
                if not isinstance(item, dict):
                    continue
                pins.append(
                    {
                        "id": str(item.get("id") or f"pin_{len(pins)}"),
                        "kind": "interest" if kind == "interests" else kind.rstrip("s"),
                        "ref": str(item.get("id") or ""),
                        "label": str(item.get("title") or item.get("summary") or item.get("type") or kind),
                        "target": str(item.get("target_id") or "*"),
                        "pinned": self._time_label(item.get("created_at")),
                    }
                )
        return pins[:24]

    def _critical_thinking_view(self, work_status: dict[str, Any]) -> list[dict[str, str]]:
        blockers = work_status.get("blockers", []) if isinstance(work_status.get("blockers", []), list) else []
        rows = []
        for index, blocker in enumerate(blockers):
            if not isinstance(blocker, dict):
                continue
            rows.append(
                {
                    "id": str(blocker.get("kind") or f"ct_{index}"),
                    "prompt": str(blocker.get("summary") or "Review runtime blocker."),
                    "target": str(blocker.get("target") or "*"),
                    "phase": "analysis",
                    "status": "open",
                }
            )
        return rows or [
            {
                "id": "ct_scope",
                "prompt": "What evidence is missing before the next runtime action?",
                "target": "*",
                "phase": "recon",
                "status": "open",
            }
        ]

    def _workspace_body(self, target: dict[str, Any], workspace: dict[str, Any]) -> str:
        lines = [
            f"# {target.get('handle', 'Target')}",
            f"Profile: {target.get('profile', '')}",
            f"Findings path: {workspace.get('findings_path', 'not generated') if isinstance(workspace, dict) else 'not generated'}",
            f"Guidance path: {workspace.get('guidance_path', 'not generated') if isinstance(workspace, dict) else 'not generated'}",
        ]
        if isinstance(workspace, dict) and workspace.get("summary"):
            lines.extend(["", str(workspace["summary"])])
        return "\n".join(lines)

    def _target_lookup(self, targets: list[dict[str, Any]]) -> dict[str, str]:
        lookup = {}
        for item in targets:
            target = item.get("target", {}) if isinstance(item.get("target"), dict) else {}
            lookup[str(target.get("id") or "")] = str(target.get("handle") or "")
        return lookup

    def _target_handle(self, item: dict[str, Any]) -> str:
        target = item.get("target", {}) if isinstance(item.get("target"), dict) else {}
        return str(target.get("handle") or "").strip()

    def _first_asset(self, assets: list[Any], asset_type: str) -> str:
        for item in assets:
            if isinstance(item, dict) and item.get("asset_type") == asset_type:
                return str(item.get("asset") or "")
        return ""

    def _metric_ratio(self, metrics: dict[str, Any], key: str) -> float:
        payload = metrics.get(key, {}) if isinstance(metrics, dict) else {}
        if not isinstance(payload, dict):
            return 0.0
        for field_name in ("load_ratio", "utilization_ratio", "usage_ratio"):
            value = payload.get(field_name)
            if isinstance(value, int | float):
                return max(0.0, min(1.0, float(value)))
        percent = payload.get("percent")
        if isinstance(percent, int | float):
            return max(0.0, min(1.0, float(percent) / 100.0))
        return 0.0

    def _memory_ratio(self, metrics: dict[str, Any]) -> float:
        cpu = metrics.get("cpu", {}) if isinstance(metrics, dict) else {}
        if isinstance(cpu, dict):
            memory = cpu.get("memory", {})
            if isinstance(memory, dict):
                percent = memory.get("percent")
                if isinstance(percent, int | float):
                    return max(0.0, min(1.0, float(percent) / 100.0))
            percent = cpu.get("memory_percent")
            if isinstance(percent, int | float):
                return max(0.0, min(1.0, float(percent) / 100.0))
        return 0.0

    def _task_status_for_gui(self, status: str) -> str:
        normalized = status.lower()
        if normalized in {"running", "claimed"}:
            return "running"
        if normalized in {"pending", "queued"}:
            return "queued"
        if normalized in {"needs_approval", "waiting", "await_approval"}:
            return "await_approval"
        if normalized in {"completed", "done", "succeeded"}:
            return "done"
        if normalized in {"failed", "denied"}:
            return "failed"
        return normalized or "queued"

    def _trace_status_for_gui(self, status: str) -> str:
        normalized = self._task_status_for_gui(status)
        if normalized == "running":
            return "run"
        if normalized == "done":
            return "pass"
        if normalized == "failed":
            return "fail"
        if normalized == "await_approval":
            return "gated"
        return "queued"

    def _event_level(self, event_type: str) -> str:
        lowered = event_type.lower()
        if any(token in lowered for token in ("failed", "error", "denied")):
            return "err"
        if any(token in lowered for token in ("approval", "waiting", "stale")):
            return "warn"
        if any(token in lowered for token in ("completed", "success", "bootstrap", "scope")):
            return "ok"
        return "info"

    def _time_label(self, value: Any) -> str:
        if not value:
            return datetime.now(timezone.utc).strftime("%H:%M:%S")
        try:
            return datetime.fromisoformat(str(value)).strftime("%H:%M:%S")
        except ValueError:
            return str(value)
