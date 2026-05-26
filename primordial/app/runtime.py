from __future__ import annotations

import ipaddress
import hashlib
import json
import os
from pathlib import Path
import re
from threading import RLock
import shutil
import subprocess
import sys
import time
from urllib import parse as urlparse

from primordial.adapters.caido import CaidoIntegrationService
from primordial.adapters.discord import DiscordNotificationService, validate_discord_webhook_url
from primordial.adapters.notion import NotionSyncService
from primordial.core.config import AppConfig
from primordial.core.context import ContextEnvelope, ContextSinkValidator, is_operational_context_purpose
from primordial.core.context.normalization import metadata_list_value, metadata_value
from primordial.core.credentials import CredentialStore
from primordial.core.domain.enums import (
    AgentRole,
    ArtifactKind,
    EvidenceType,
    EventType,
    InterestStatus,
    MethodologyPhase,
    MethodologyName,
    ProviderRoute,
    RiskTier,
    ScopeProfile,
    TaskKind,
    TaskRunStatus,
    TaskStatus,
    VerificationStatus,
)
from primordial.core.domain.models import (
    DashboardSnapshot,
    ArtifactRecord,
    DocumentChunk,
    EventRecord,
    EvidenceRecord,
    Finding,
    Interest,
    Note,
    OperatorMessage,
    ScopeAsset,
    Session,
    Target,
    Task,
    json_ready,
    utc_now,
)
from primordial.core.events.bus import EventBus, RuntimeSignal
from primordial.core.evidence import CredentialedAccessSurface, classify_credentialed_access_surface
from primordial.core.environment import EnvironmentClassification, EnvironmentClassifier
from primordial.core.findings_context import FindingsContextService
from primordial.core.intent import OperatorIntentRegistry
from primordial.core.intent.models import OperatorIntentPolicy
from primordial.core.modules.registry import ModuleRegistry
from primordial.core.orchestration.policy import PolicyEngine
from primordial.core.orchestration.verifier import BehaviorVerifier
from primordial.core.orchestration.workflow import WorkflowOrchestrator
from primordial.core.primitives.catalog import PrimitiveCatalog
from primordial.core.providers.router import ProviderRouter
from primordial.core.providers.agent_chat import AgentChatClient, AgentChatPremiumReviewRunner, AgentChatSettings
from primordial.core.providers.lmstudio import LMStudioClient
from primordial.core.providers.lmstudio_tuning import LMStudioPerformanceTuner
from primordial.core.providers.ollama import OllamaClient, OllamaModelListResult
from primordial.core.providers.model_eval import ModelEvaluationService
from primordial.core.providers.wrapper_prompts import WRAPPER_ROLE_PERSONALITY_PROMPTS, build_wrapper_system_prompt
from primordial.core.rag import DocumentIngestionService, RagContextBroker
from primordial.core.rag.citations import disallowed_rag_synthesis_model, validate_rag_citations
from primordial.core.rag.embeddings import embedding_provider_from_config
from primordial.core.rag.importer import RagChunkImporter, RagImportOptions
from primordial.core.rag.vuln_sync import VulnFeedSyncer, VulnSyncOptions
from primordial.core.rag.vuln_hints import vulnerability_hints_from_results
from primordial.core.recovery.crash_journal import CrashJournal
from primordial.core.recovery.resume_tracker import ResumeTracker
from primordial.core.providers.scheduler import ModelScheduler
from primordial.core.skills import RuntimeSkillRegistry
from primordial.core.storage.runtime import RuntimeStore, _SCHEMA_VERSION
from primordial.core.validation import build_default_validation_registry
from primordial.core.workers import InProcessWorkerRunner, WorkerBroker, WorkerContract
from primordial.modes.security.module import SecurityModeServices, build_security_mode_services


class PrimordialRuntime:
    EXECUTION_MODE_SETTING = "execution_mode"
    EXECUTION_MODE_INTERVAL_SETTING = "execution_mode_interval_seconds"
    EXECUTION_MODES = {"tick", "continuous"}
    DEFAULT_EXECUTION_INTERVAL_SECONDS = 30
    RUNTIME_TUNING_SETTING = "runtime_tuning"
    MODEL_WRAPPER_MODE_SETTING = "model_wrapper_mode"
    AGENT_CHAT_PROCESS_SETTING = "agent_chat_api_process"
    RAG_LAST_IMPORT_SETTING = "rag_last_import"
    RAG_LAST_VULN_SYNC_SETTING = "rag_last_vuln_sync"
    DEFAULT_WRAPPER_PRESET = "claude_sonnet"
    WRAPPER_EFFORTS = {"low", "medium", "high", "xhigh"}
    WRAPPER_PRESETS = {
        "claude_sonnet": {
            "label": "Claude Sonnet",
            "provider": "claude",
            "model": "sonnet",
            "effort": None,
        },
        "codex_gpt55_high": {
            "label": "GPT 5.5 High",
            "provider": "codex",
            "model": "gpt-5.5",
            "effort": "high",
        },
    }
    DEFAULT_WORKER_AI_TIMEOUT_SECONDS_GPU = 120
    DEFAULT_WORKER_AI_TIMEOUT_SECONDS_CPU = 300
    DEFAULT_STALE_RUN_TIMEOUT_SECONDS = 3600
    DEFAULT_MIN_FREE_CPU_RAM_MB = 2048
    DEFAULT_MIN_FREE_GPU_RAM_MB = 368
    MIN_GPU_AI_TIMEOUT_SECONDS = 15
    MIN_CPU_AI_TIMEOUT_SECONDS = 30
    MIN_STALE_RUN_TIMEOUT_SECONDS = 60
    MIN_FREE_CPU_RAM_MB = 0
    MIN_FREE_GPU_RAM_MB = 0
    METRICS_CACHE_TTL_SECONDS = 2.0
    WORKER_AI_TIMEOUT_SECONDS_GPU = 120
    WORKER_AI_TIMEOUT_SECONDS_CPU = 300
    SCOPE_PROFILE_PRESETS_SETTING = "scope_profile_presets"

    MODEL_ROLE_CONFIG = {
        "local_fast": {
            "label": "Orchestrator",
            "description": "Primary planning, orchestration, and broad analysis model.",
            "processor": "gpu",
            "default_model": "gemma4:e4b",
            "topology_field": "local_fast",
        },
        "local_deep": {
            "label": "Deep Reasoning",
            "description": "Harder reasoning, chain review, and subtle hypothesis analysis.",
            "processor": "gpu",
            "default_model": "deepseek-r1:8b",
            "topology_field": "local_deep",
        },
        "local_code": {
            "label": "Code / PoC Work",
            "description": "Mission-critical code, exploit research, and PoC adaptation work.",
            "processor": "cpu",
            "default_model": "qwen3-coder-next:q4_K_M",
            "topology_field": "local_code",
        },
        "local_compact": {
            "label": "Compact / Verifier",
            "description": "Memory compaction, cheap verification, and background classification.",
            "processor": "cpu",
            "default_model": "phi4-reasoning",
            "topology_field": "local_compact",
        },
    }

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.store = RuntimeStore(config.database_url, schema=config.database_schema)
        self.credentials = CredentialStore(config.credentials_path)
        self.catalog = PrimitiveCatalog()
        self.environment_classifier = self._load_environment_classifier(config.project_root)
        self.operator_intents = OperatorIntentRegistry(config.catalog_dir / "intents")
        self.event_bus = EventBus()
        self.modules = ModuleRegistry(self.event_bus)
        self.crash_journal = CrashJournal(config.crash_journal_path)
        self.policy = PolicyEngine(
            config.autonomy,
            credentials_status_loader=self.credentials_payload,
            daily_remote_cost_loader=self.store.get_daily_remote_cost_usd,
        )
        self.router = ProviderRouter(config.topology)
        self.agent_chat = AgentChatClient(
            AgentChatSettings(
                base_url=config.agent_chat_base_url,
                api_key=config.agent_chat_api_key,
                provider=config.agent_chat_provider,
                model=config.agent_chat_model,
                timeout_seconds=config.agent_chat_timeout_seconds,
                cwd=config.agent_chat_cwd,
                safe_guard=config.agent_chat_safe_guard,
                codex_sandbox=config.agent_chat_codex_sandbox,
                claude_permission_mode=config.agent_chat_claude_permission_mode,
            )
        )
        self.ollama = OllamaClient()
        self.rag_embedding_provider = embedding_provider_from_config(config.rag.embeddings)
        self.model_scheduler = ModelScheduler(config.autonomy)
        self.verifier = BehaviorVerifier()
        self.validation = build_default_validation_registry()
        self.skills = RuntimeSkillRegistry(config.skills_dir)
        self.findings_context = FindingsContextService(config.findings_dir, config.notion_exports_dir)
        self.rag = DocumentIngestionService(
            self.store,
            config.artifacts_dir,
            embedding_provider=self.rag_embedding_provider,
        )
        self.rag_context_broker = RagContextBroker(self.rag)
        self.resume_tracker = ResumeTracker(self.store, self.event_bus)
        self._last_recovery_status: dict[str, object] = {
            "previous_unclean_shutdown": False,
            "backoff_applied_seconds": 0.0,
            "recovered_runs": 0,
            "resumed_tasks": 0,
        }
        self.worker_broker = WorkerBroker(self.event_bus)
        self._metrics_lock = RLock()
        self._cpu_sample: tuple[int, int] | None = None
        self._network_sample: tuple[int, int, float] | None = None
        self._system_metrics_cache: dict[str, object] | None = None
        self._system_metrics_cache_at = 0.0
        self._register_modules()
        self._register_worker_runners()
        self.workflow = WorkflowOrchestrator(
            store=self.store,
            policy_engine=self.policy,
            provider_router=self.router,
            model_scheduler=self.model_scheduler,
            memory_service_loader=lambda: self.security.memory_service,
            verifier=self.verifier,
            primitive_resolver_loader=lambda: self.security.primitive_executor,
            worker_broker=self.worker_broker,
            validation_registry=self.validation,
            resume_tracker=self.resume_tracker,
            autonomy=config.autonomy,
            checkpoints_dir=config.checkpoints_dir,
            credentials_status_loader=self.credentials_payload,
            active_intent_policy_loader=self.intent_policy,
            active_intent_id_loader=lambda: self.active_operator_intent().id,
            rag_context_builder=self.build_rag_context_pack,
            resource_status_loader=lambda: self.system_metrics_payload(force_refresh=True),
            resource_reserve_loader=self.resource_reserve_payload,
            event_bus=self.event_bus,
        )

    @classmethod
    def from_env(cls) -> "PrimordialRuntime":
        return cls(AppConfig.from_env())

    def initialize(self) -> None:
        self.config.ensure_directories()
        self.credentials.initialize()
        self.skills.initialize()
        self.findings_context.initialize()
        self._load_operator_intents()
        recovery = self.crash_journal.startup()
        self.store.initialize()
        self._apply_persisted_model_roles()
        for manifest in self.catalog.load_directory(self.config.manifests_dir):
            self.store.insert_primitive(manifest)
        self.export_operator_chat_logs()
        if recovery.previous_unclean_shutdown:
            self.event_bus.emit(
                RuntimeSignal.CRASH_RECOVERY_DETECTED,
                {"backoff_seconds": recovery.backoff_applied_seconds},
            )
        self.event_bus.emit(
            RuntimeSignal.CRASH_JOURNAL_MARKED,
            {"path": str(self.config.crash_journal_path)},
        )
        purged_external_records = self.store.purge_synthetic_external_records()
        if any(purged_external_records.values()):
            self.store.insert_event(
                EventRecord(
                    type=EventType.SYNC_FAILED,
                    summary="Removed legacy synthetic external sync records",
                    metadata=purged_external_records,
                )
            )
        self._recover_runtime_state()
        self._apply_runtime_tuning()
        self._validate_topology_models()
        repair = self.repair_execution_state()
        self._last_recovery_status = {
            "previous_unclean_shutdown": recovery.previous_unclean_shutdown,
            "backoff_applied_seconds": recovery.backoff_applied_seconds,
            **repair,
        }
        for target in self.store.list_targets():
            self.findings_context.ensure_target(target)
        self.store.insert_event(
            EventRecord(
                type=EventType.BOOTSTRAP,
                summary="Primordial runtime initialized",
                metadata={
                    "autonomy_mode": self.config.autonomy.mode.value,
                    "operator_intent": self.active_operator_intent().id,
                    "previous_unclean_shutdown": recovery.previous_unclean_shutdown,
                    "active_modules": self.modules.active_modules(),
                },
            )
        )

    @property
    def notion(self) -> NotionSyncService:
        return self.modules.get("notion")

    @property
    def discord(self) -> DiscordNotificationService:
        return self.modules.get("discord")

    @property
    def caido(self) -> CaidoIntegrationService:
        return self.modules.get("caido")

    @property
    def security(self) -> SecurityModeServices:
        return self.modules.get("security")

    @property
    def memory(self):
        return self.security.memory_service

    @property
    def executor(self):
        return self.security.primitive_executor

    def start_session(
        self,
        methodology: MethodologyName = MethodologyName.WEB_APP_CORE,
        profile: ScopeProfile = ScopeProfile.HACKERONE,
        title: str = "Default Primordial Session",
        environment_classification: EnvironmentClassification | None = None,
    ) -> Session:
        previous_session = self.store.get_active_session()
        previous_intent = None
        if previous_session is not None:
            previous_intent = previous_session.metadata.get("operator_intent_id")
        classification = environment_classification or self._classify_environment(profile=profile.value)
        default_intent = self._default_operator_intent_for_environment(classification)
        selected_intent = str(previous_intent) if previous_intent and previous_intent != OperatorIntentRegistry.DEFAULT_INTENT_ID else default_intent
        self.store.pause_active_sessions()
        session = Session(
            methodology=methodology,
            profile=profile,
            autonomy_mode=self.config.autonomy.mode.value,
            title=title,
            metadata={
                "operator_intent_id": selected_intent,
                "environment_classification": classification.as_payload(),
            },
        )
        self.store.insert_session(session)
        self.store.insert_event(
            EventRecord(
                type=EventType.SESSION_STARTED,
                summary=f"Session started: {title}",
                metadata={
                    "methodology": methodology.value,
                    "profile": profile.value,
                    "operator_intent": self.active_operator_intent().id,
                },
            )
        )
        return session

    def operator_intent_payload(self) -> dict[str, object]:
        self._load_operator_intents()
        active = self.active_operator_intent()
        return {
            "active": active.as_payload(),
            "intents": [intent.as_payload() for intent in self.operator_intents.all()],
            "default": OperatorIntentRegistry.DEFAULT_INTENT_ID,
        }

    def active_operator_intent(self):
        self._load_operator_intents()
        session = self.store.get_active_session()
        intent_id = None
        if session is not None:
            intent_id = session.metadata.get("operator_intent_id")
        try:
            return self.operator_intents.get(str(intent_id) if intent_id else None)
        except KeyError:
            return self.operator_intents.get(OperatorIntentRegistry.DEFAULT_INTENT_ID)

    def intent_policy(self) -> OperatorIntentPolicy:
        return self.active_operator_intent().policy

    def set_operator_intent(self, intent_id: str) -> dict[str, object]:
        self._load_operator_intents()
        intent = self.operator_intents.get(intent_id)
        session = self.store.get_active_session() or self.start_session()
        session.metadata["operator_intent_id"] = intent.id
        session.updated_at = utc_now()
        self.store.insert_session(session)
        self.store.insert_event(
            EventRecord(
                type=EventType.BOOTSTRAP,
                summary=f"Operator intent set: {intent.id}",
                metadata={"operator_intent": intent.as_payload(), "session_id": session.id},
            )
        )
        return self.operator_intent_payload()

    def update_runtime_control(
        self,
        *,
        mode: str,
        interval_seconds: int | None = None,
        intent_id: str,
    ) -> dict[str, object]:
        selected_mode = str(mode).strip().lower()
        if selected_mode not in self.EXECUTION_MODES:
            raise ValueError(f"unsupported execution mode: {mode}")
        self._load_operator_intents()
        intent = self.operator_intents.get(intent_id)
        execution_mode = self.update_execution_mode(selected_mode, interval_seconds=interval_seconds)
        operator_intent = self.set_operator_intent(intent.id)
        return {
            "execution_mode": execution_mode,
            "operator_intent": operator_intent,
        }

    def _load_operator_intents(self) -> None:
        if self.operator_intents.all():
            return
        configured_dir = self.config.catalog_dir / "intents"
        if not any(configured_dir.glob("*.yaml")):
            self.operator_intents = OperatorIntentRegistry(Path(__file__).resolve().parents[2] / "catalog" / "intents")
        self.operator_intents.load()

    def import_scope(self, path: Path, profile: ScopeProfile | str | None = None) -> dict[str, object]:
        payload = self._load_scope_payload(path)
        return self.import_scope_payload(payload, profile=profile, source_name=path.name)

    def import_scope_payload(
        self,
        payload: dict[str, object],
        profile: ScopeProfile | str | None = None,
        source_name: str = "operator payload",
    ) -> dict[str, object]:
        if not isinstance(payload, dict):
            raise ValueError("scope payload must be an object")
        raw_profile = str(profile or payload.get("profile", ScopeProfile.HACKERONE.value))
        try:
            payload_profile = self.resolve_scope_profile(raw_profile)
        except ValueError:
            if not self.environment_classifier.has_profile_upgrade(raw_profile):
                raise
            payload_profile = ScopeProfile.HACKERONE
        environment_classification = self._classify_environment(
            profile=raw_profile,
            resolved_profile=payload_profile.value,
            payload=payload,
        )
        targets = payload.get("targets", [])
        if not isinstance(targets, list):
            raise ValueError("scope payload targets must be a list")
        session = self.store.get_active_session() or self.start_session(
            profile=payload_profile,
            environment_classification=environment_classification,
        )
        self._ensure_profile_default_operator_intent(payload_profile, classification=environment_classification)
        session = self.store.get_active_session() or session
        imported_targets = 0
        imported_assets = 0
        for target_payload in targets:
            if not isinstance(target_payload, dict):
                raise ValueError("each scope target must be an object")
            handle = str(target_payload.get("handle", "")).strip()
            if not handle:
                raise ValueError("each scope target requires a handle")
            raw_assets = target_payload.get("assets", [handle])
            if not isinstance(raw_assets, list):
                raise ValueError(f"assets for {handle} must be a list")
            normalized_assets = []
            for asset_payload in raw_assets or [handle]:
                if isinstance(asset_payload, dict):
                    raw_asset = str(asset_payload["asset"])
                    normalized_assets.append(
                        {
                            "asset": raw_asset,
                            "asset_type": str(asset_payload.get("asset_type", self._infer_asset_type(raw_asset))),
                            "metadata": dict(asset_payload.get("metadata", {})),
                        }
                    )
                else:
                    raw_asset = str(asset_payload)
                    normalized_assets.append(
                        {
                            "asset": raw_asset,
                            "asset_type": self._infer_asset_type(raw_asset),
                            "metadata": {},
                        }
                    )
            self.register_target(
                handle=handle,
                display_name=str(target_payload.get("display_name", handle)),
                profile=payload_profile,
                assets=normalized_assets,
                in_scope=bool(target_payload.get("in_scope", True)),
                metadata=dict(target_payload.get("metadata", {})),
                emit_event=False,
            )
            imported_targets += 1
            imported_assets += len(normalized_assets)
        self.store.insert_event(
            EventRecord(
                type=EventType.SCOPE_IMPORTED,
                summary=f"Imported scope from {source_name}",
                metadata={
                    "profile": payload_profile.value,
                    "session_id": session.id,
                    "targets_imported": imported_targets,
                    "assets_imported": imported_assets,
                    "environment_classification": environment_classification.as_payload(),
                },
            )
        )
        return {
            "source": source_name,
            "profile": payload_profile.value,
            "session_id": session.id,
            "targets_imported": imported_targets,
            "assets_imported": imported_assets,
            "environment_classification": environment_classification.as_payload(),
        }

    def run_tick(self, max_executions: int = 3):
        report = self.workflow.tick(max_executions=max_executions)
        self.process_external_queues()
        return report

    def repair_execution_state(self) -> dict[str, int]:
        recovered_runs = self.workflow.recover_stale_execution_state(limit=500)
        resumed_tasks = self.resume_tracker.resume_due_tasks(limit=200)
        return {"recovered_runs": recovered_runs, "resumed_tasks": resumed_tasks}

    def approve_all_safe_tasks(self, *, limit: int = 200, run_tick: bool = False) -> dict[str, object]:
        outcome = self.workflow.approve_all_safe_tasks(limit=limit)
        if run_tick and outcome.get("approved_count"):
            report = self.run_tick(max_executions=1)
            outcome["tick_summary"] = report.summary
        return outcome

    def execution_mode_payload(self) -> dict[str, object]:
        mode = str(self.store.get_setting(self.EXECUTION_MODE_SETTING, "tick")).strip().lower()
        if mode not in self.EXECUTION_MODES:
            mode = "tick"
        interval = self.store.get_setting(
            self.EXECUTION_MODE_INTERVAL_SETTING,
            self.DEFAULT_EXECUTION_INTERVAL_SECONDS,
        )
        try:
            interval_seconds = max(2, int(interval))
        except (TypeError, ValueError):
            interval_seconds = self.DEFAULT_EXECUTION_INTERVAL_SECONDS
        return {
            "mode": mode,
            "continuous": mode == "continuous",
            "interval_seconds": interval_seconds,
            "available_modes": ["tick", "continuous"],
        }

    def runtime_tuning_payload(self) -> dict[str, object]:
        raw = self.store.get_setting(self.RUNTIME_TUNING_SETTING, {})
        if not isinstance(raw, dict):
            raw = {}
        gpu_timeout = self._bounded_int(
            raw.get("gpu_ai_timeout_seconds"),
            default=self.DEFAULT_WORKER_AI_TIMEOUT_SECONDS_GPU,
            minimum=self.MIN_GPU_AI_TIMEOUT_SECONDS,
        )
        cpu_timeout = self._bounded_int(
            raw.get("cpu_ai_timeout_seconds"),
            default=self.DEFAULT_WORKER_AI_TIMEOUT_SECONDS_CPU,
            minimum=self.MIN_CPU_AI_TIMEOUT_SECONDS,
        )
        stale_timeout = self._bounded_int(
            raw.get("stale_run_timeout_seconds"),
            default=self.DEFAULT_STALE_RUN_TIMEOUT_SECONDS,
            minimum=self.MIN_STALE_RUN_TIMEOUT_SECONDS,
        )
        min_free_cpu_ram = self._bounded_int(
            raw.get("min_free_cpu_ram_mb"),
            default=self.DEFAULT_MIN_FREE_CPU_RAM_MB,
            minimum=self.MIN_FREE_CPU_RAM_MB,
        )
        min_free_gpu_ram = self._bounded_int(
            raw.get("min_free_gpu_ram_mb"),
            default=self.DEFAULT_MIN_FREE_GPU_RAM_MB,
            minimum=self.MIN_FREE_GPU_RAM_MB,
        )
        return {
            "gpu_ai_timeout_seconds": gpu_timeout,
            "cpu_ai_timeout_seconds": cpu_timeout,
            "stale_run_timeout_seconds": stale_timeout,
            "min_free_cpu_ram_mb": min_free_cpu_ram,
            "min_free_gpu_ram_mb": min_free_gpu_ram,
            "defaults": {
                "gpu_ai_timeout_seconds": self.DEFAULT_WORKER_AI_TIMEOUT_SECONDS_GPU,
                "cpu_ai_timeout_seconds": self.DEFAULT_WORKER_AI_TIMEOUT_SECONDS_CPU,
                "stale_run_timeout_seconds": self.DEFAULT_STALE_RUN_TIMEOUT_SECONDS,
                "min_free_cpu_ram_mb": self.DEFAULT_MIN_FREE_CPU_RAM_MB,
                "min_free_gpu_ram_mb": self.DEFAULT_MIN_FREE_GPU_RAM_MB,
            },
            "minimums": {
                "gpu_ai_timeout_seconds": self.MIN_GPU_AI_TIMEOUT_SECONDS,
                "cpu_ai_timeout_seconds": self.MIN_CPU_AI_TIMEOUT_SECONDS,
                "stale_run_timeout_seconds": self.MIN_STALE_RUN_TIMEOUT_SECONDS,
                "min_free_cpu_ram_mb": self.MIN_FREE_CPU_RAM_MB,
                "min_free_gpu_ram_mb": self.MIN_FREE_GPU_RAM_MB,
            },
        }

    def resource_reserve_payload(self) -> dict[str, object]:
        tuning = self.runtime_tuning_payload()
        return {
            "min_free_cpu_ram_mb": int(tuning["min_free_cpu_ram_mb"]),
            "min_free_gpu_ram_mb": int(tuning["min_free_gpu_ram_mb"]),
        }

    def update_runtime_tuning(
        self,
        *,
        gpu_ai_timeout_seconds: int | None = None,
        cpu_ai_timeout_seconds: int | None = None,
        stale_run_timeout_seconds: int | None = None,
        min_free_cpu_ram_mb: int | None = None,
        min_free_gpu_ram_mb: int | None = None,
    ) -> dict[str, object]:
        current = self.runtime_tuning_payload()
        updated = {
            "gpu_ai_timeout_seconds": self._bounded_int(
                gpu_ai_timeout_seconds,
                default=int(current["gpu_ai_timeout_seconds"]),
                minimum=self.MIN_GPU_AI_TIMEOUT_SECONDS,
            ),
            "cpu_ai_timeout_seconds": self._bounded_int(
                cpu_ai_timeout_seconds,
                default=int(current["cpu_ai_timeout_seconds"]),
                minimum=self.MIN_CPU_AI_TIMEOUT_SECONDS,
            ),
            "stale_run_timeout_seconds": self._bounded_int(
                stale_run_timeout_seconds,
                default=int(current["stale_run_timeout_seconds"]),
                minimum=self.MIN_STALE_RUN_TIMEOUT_SECONDS,
            ),
            "min_free_cpu_ram_mb": self._bounded_int(
                min_free_cpu_ram_mb,
                default=int(current["min_free_cpu_ram_mb"]),
                minimum=self.MIN_FREE_CPU_RAM_MB,
            ),
            "min_free_gpu_ram_mb": self._bounded_int(
                min_free_gpu_ram_mb,
                default=int(current["min_free_gpu_ram_mb"]),
                minimum=self.MIN_FREE_GPU_RAM_MB,
            ),
        }
        self.store.set_setting(self.RUNTIME_TUNING_SETTING, updated)
        self._apply_runtime_tuning()
        payload = self.runtime_tuning_payload()
        self.store.insert_event(
            EventRecord(
                type=EventType.BOOTSTRAP,
                summary="Runtime tuning updated",
                metadata=payload,
            )
        )
        return payload

    def system_metrics_payload(self, *, force_refresh: bool = False) -> dict[str, object]:
        with self._metrics_lock:
            now = time.monotonic()
            if (
                not force_refresh
                and self._system_metrics_cache is not None
                and (now - self._system_metrics_cache_at) < self.METRICS_CACHE_TTL_SECONDS
            ):
                return dict(self._system_metrics_cache)
            payload = {
                "updated_at": utc_now().isoformat(),
                "cpu": self._read_cpu_metrics(),
                "gpu": self._read_gpu_metrics(),
                "network": self._read_network_metrics(now),
            }
            self._system_metrics_cache = payload
            self._system_metrics_cache_at = now
            return dict(payload)

    def update_execution_mode(self, mode: str, *, interval_seconds: int | None = None) -> dict[str, object]:
        selected = str(mode).strip().lower()
        if selected not in self.EXECUTION_MODES:
            raise ValueError(f"unsupported execution mode: {mode}")
        self.store.set_setting(self.EXECUTION_MODE_SETTING, selected)
        if interval_seconds is not None:
            self.store.set_setting(self.EXECUTION_MODE_INTERVAL_SETTING, max(2, int(interval_seconds)))
        payload = self.execution_mode_payload()
        self.store.insert_event(
            EventRecord(
                type=EventType.BOOTSTRAP,
                summary=f"Execution mode set to {payload['mode']}",
                metadata=payload,
            )
        )
        return payload

    def process_external_queues(self) -> dict[str, int]:
        self.sync_findings_context_exports()
        notion_completed = self.notion.process_pending()
        discord_delivered = self.discord.deliver_pending()
        return {"notion_completed": notion_completed, "discord_delivered": discord_delivered}

    def shutdown(self) -> None:
        self.modules.shutdown_all()
        self.crash_journal.shutdown()

    def compact_memory(self) -> int:
        created = 0
        for target in self.store.list_targets():
            created += len(self.memory.compact_target(target.id))
            self.memory.apply_freshness_decay(target.id)
        if created:
            self.store.insert_event(
                EventRecord(
                    type=EventType.MEMORY_COMPACTION,
                    summary=f"Memory compaction created {created} entries",
                )
            )
        self.process_external_queues()
        return created

    def approve_task(self, task_id: str, approved: bool = True):
        task = self.workflow.approve_task(task_id, approved=approved)
        if approved and task is not None and not task.metadata.get("proposal_only"):
            self.run_tick(max_executions=1)
        return task

    def create_ui_command_proposal(
        self,
        command: str,
        payload: dict[str, object] | None = None,
    ) -> dict[str, object]:
        command_name = re.sub(r"[^a-z0-9_.:-]+", "-", str(command).strip().lower()).strip("-")
        if not command_name:
            raise ValueError("command is required")
        body = dict(payload or {})
        target_handle = str(body.get("target") or body.get("target_handle") or "").strip()
        target = self.store.get_target_by_handle(target_handle) if target_handle else None
        intent = self.active_operator_intent()
        title = str(body.get("title") or command_name.replace("-", " ").replace("_", " ").title()).strip()
        summary = str(
            body.get("summary")
            or f"Web console requested `{command_name}`. This is a proposal only and will not execute automatically."
        )
        task = Task(
            target_id=target.id if target else None,
            phase=MethodologyPhase.ANALYSIS,
            kind=TaskKind.ANALYZE_EVIDENCE,
            title=title,
            summary=summary,
            role=AgentRole.ORCHESTRATOR,
            methodology=MethodologyName.WEB_APP_CORE,
            metadata={
                "ui_command": command_name,
                "ui_payload": json_ready(body),
                "proposal_only": True,
                "operator_intent_id": intent.id,
            },
            status=TaskStatus.NEEDS_APPROVAL,
            priority=10,
            risk_tier=RiskTier.MODERATE,
            requires_approval=True,
        )
        self.store.insert_task(task)
        self.store.insert_event(
            EventRecord(
                type=EventType.TASK_NEEDS_APPROVAL,
                summary=f"UI command proposal: {title}",
                target_id=task.target_id,
                task_id=task.id,
                metadata={"ui_command": command_name, "operator_intent_id": intent.id},
            )
        )
        return {
            "proposal": task.as_payload(),
            "target": target.as_payload() if target else None,
            "operator_intent": intent.as_payload(),
        }

    def register_target(
        self,
        *,
        handle: str,
        profile: ScopeProfile,
        display_name: str | None = None,
        assets: list[str | dict[str, object]] | None = None,
        in_scope: bool = True,
        metadata: dict[str, object] | None = None,
        emit_event: bool = True,
    ) -> Target:
        handle = str(handle).strip()
        if not handle:
            raise ValueError("target handle is required")
        display_name = str(display_name or handle).strip() or handle
        existing = self.store.get_target_by_handle(handle, profile)
        if existing is not None:
            target = existing
            target.display_name = display_name or target.display_name
            target.in_scope = in_scope
            merged_metadata = dict(target.metadata)
            if metadata:
                merged_metadata.update(metadata)
            target.metadata = merged_metadata
            target.updated_at = utc_now()
        else:
            target = Target(
                handle=handle,
                display_name=display_name,
                profile=profile,
                in_scope=in_scope,
                metadata=dict(metadata or {}),
            )
        environment_classification = self._classify_environment(
            profile=profile.value,
            target_metadata=metadata or {},
            asset_metadata=self._asset_metadata_from_entries(assets or []),
        )
        self._ensure_profile_default_operator_intent(profile, classification=environment_classification)
        self.store.insert_target(target)
        self.findings_context.ensure_target(target)

        normalized_assets = assets or [handle]
        for asset_entry in normalized_assets:
            if isinstance(asset_entry, dict):
                raw_asset = str(asset_entry["asset"]).strip()
                if not raw_asset:
                    continue
                asset_type = str(asset_entry.get("asset_type", self._infer_asset_type(raw_asset)))
                asset_metadata = dict(asset_entry.get("metadata", {}))
            else:
                raw_asset = str(asset_entry).strip()
                if not raw_asset:
                    continue
                asset_type = self._infer_asset_type(raw_asset)
                asset_metadata = {}
            if self.store.get_scope_asset(target.id, raw_asset) is not None:
                continue
            self.store.insert_scope_asset(
                ScopeAsset(
                    target_id=target.id,
                    asset=raw_asset,
                    asset_type=asset_type,
                    metadata=asset_metadata,
                )
            )

        if emit_event:
            self.store.insert_event(
                EventRecord(
                    type=EventType.SCOPE_UPDATED,
                    summary=f"Registered or updated target: {target.handle}",
                    target_id=target.id,
                    metadata={"profile": profile.value},
                )
            )
        return target

    def update_target_fields(
        self,
        *,
        handle: str,
        profile: ScopeProfile,
        display_name: str | None = None,
        assets: list[str | dict[str, object]] | None = None,
        active_ip: str | None = None,
        in_scope: bool = True,
        metadata: dict[str, object] | None = None,
    ) -> Target:
        handle = str(handle).strip()
        if not handle:
            raise ValueError("target handle is required")
        normalized_assets = list(assets or [handle])
        parsed_active_ip = self._validated_optional_ip(active_ip)
        if parsed_active_ip and not any(
            (item.get("asset") if isinstance(item, dict) else item) == parsed_active_ip
            for item in normalized_assets
        ):
            normalized_assets.append(
                {
                    "asset": parsed_active_ip,
                    "asset_type": "ip",
                    "metadata": {"active": True, "operator_confirmed": True},
                }
            )
        target = self.register_target(
            handle=handle,
            profile=profile,
            display_name=display_name,
            assets=normalized_assets,
            in_scope=in_scope,
            metadata=metadata,
        )
        if parsed_active_ip:
            target = self.set_target_active_ip(target, parsed_active_ip, source="target_update")
        return target

    def set_target_active_ip(self, target: Target | str, ip: str, *, source: str = "operator") -> Target:
        target_record = target if isinstance(target, Target) else self._resolve_target_reference(target)
        if target_record is None:
            raise ValueError("target not found")
        parsed_ip = self._validated_optional_ip(ip)
        if not parsed_ip:
            raise ValueError("active_ip must be a valid IPv4 or IPv6 address")
        previous_ip = str(target_record.metadata.get("active_ip") or "").strip()
        ip_changed = previous_ip != parsed_ip
        generation = int(target_record.metadata.get("active_ip_generation", 0) or 0) + (1 if ip_changed else 0)
        metadata = dict(target_record.metadata)
        metadata.update(
            {
                "active_ip": parsed_ip,
                "operator_confirmed_ip": parsed_ip,
                "operator_confirmed_ip_at": utc_now().isoformat(),
                "active_ip_generation": generation,
                "stale_evidence_before": utc_now().isoformat()
                if ip_changed
                else metadata.get("stale_evidence_before", utc_now().isoformat()),
                "active_ip_source": source,
            }
        )
        updated = self.register_target(
            handle=target_record.handle,
            profile=target_record.profile,
            display_name=target_record.display_name,
            assets=[
                {
                    "asset": parsed_ip,
                    "asset_type": "ip",
                    "metadata": {
                        "active": True,
                        "operator_confirmed": True,
                        "active_ip_generation": generation,
                        "source": source,
                    },
                }
            ],
            in_scope=target_record.in_scope,
            metadata=metadata,
            emit_event=False,
        )
        if ip_changed:
            self.store.insert_note(
                Note(
                    target_id=updated.id,
                    title="Operator-confirmed active target IP",
                    body=(
                        f"Active IP for `{updated.handle}` is `{parsed_ip}`. "
                        "Prior recon evidence may still reference older IPs and should be treated as historical "
                        "until refreshed recon tasks complete."
                    ),
                    confidence=1.0,
                    freshness=1.0,
                    metadata={
                        "class": "operator_correction",
                        "active_ip": parsed_ip,
                        "previous_ip": previous_ip,
                        "active_ip_generation": generation,
                        "source": source,
                    },
                )
            )
            # Supersede EPISODIC memory entries from the previous generation so stale
            # IP-specific facts don't contaminate current-generation reasoning.
            self.memory.supersede_stale_generation_entries(updated.id, str(generation))
        self.store.insert_event(
            EventRecord(
                type=EventType.SCOPE_UPDATED,
                summary=(
                    f"Active IP set for {updated.handle}: {parsed_ip}"
                    if ip_changed
                    else f"Active IP confirmed for {updated.handle}: {parsed_ip}"
                ),
                target_id=updated.id,
                metadata={
                    "active_ip": parsed_ip,
                    "previous_ip": previous_ip,
                    "active_ip_generation": generation,
                    "source": source,
                },
            )
        )
        return updated

    def replace_target_scope_assets(
        self,
        *,
        handle: str,
        display_name: str,
        profile: ScopeProfile,
        in_scope: bool,
        active_ip: str | None,
        asset_rows: list[dict[str, object]],
    ) -> Target:
        """Replace all scope assets for a target atomically.

        Each row in asset_rows must contain: asset (str), asset_type (str),
        and optionally ports (str, default "*") and scope_rule (str, default "allow").
        Updating the active IP may create a new generation if the IP changes.
        No ticks are triggered — caller is responsible for orchestration.
        """
        handle = str(handle).strip()
        if not handle:
            raise ValueError("target handle is required")
        display_name = str(display_name or handle).strip() or handle
        parsed_active_ip = self._validated_optional_ip(active_ip) if active_ip else None
        environment_classification = self._classify_environment(
            profile=profile.value,
            asset_metadata=self._asset_metadata_from_entries(asset_rows),
        )
        self._ensure_profile_default_operator_intent(profile, classification=environment_classification)
        normalized_rows: list[dict[str, object]] = []
        for row in asset_rows:
            raw_asset = str(row["asset"]).strip()
            if not raw_asset:
                continue
            normalized_rows.append(
                {
                    "asset": raw_asset,
                    "asset_type": str(row.get("asset_type") or self._infer_asset_type(raw_asset)),
                    "metadata": {
                        "ports": str(row.get("ports") or "*"),
                        "scope_rule": str(row.get("scope_rule") or "allow"),
                        "operator_managed": True,
                    },
                }
            )

        outcome = self.store.replace_target_scope_assets(
            handle=handle,
            display_name=display_name,
            profile=profile,
            in_scope=in_scope,
            active_ip=parsed_active_ip,
            asset_rows=normalized_rows,
        )
        target = outcome["target"]
        if outcome.get("ip_changed"):
            self.memory.supersede_stale_generation_entries(target.id, str(outcome.get("active_ip_generation") or ""))

        self.findings_context.ensure_target(target)
        return target

    def diagnose_payload(self) -> dict[str, object]:
        """Return a human-readable diagnostic snapshot for operator troubleshooting."""
        from primordial.core.domain.enums import TaskStatus, TaskRunStatus

        tasks = self.store.list_tasks(limit=200)
        runs = self.store.list_task_runs(limit=50)
        targets = self.store.list_targets()
        mode = self.execution_mode_payload()
        models = self.models_payload()

        status_counts: dict[str, int] = {}
        for task in tasks:
            key = task.status.value
            status_counts[key] = status_counts.get(key, 0) + 1

        active_runs = [r for r in runs if r.status in {TaskRunStatus.CLAIMED, TaskRunStatus.RUNNING} and r.finished_at is None]
        failed_recent = [r for r in runs if r.status in {TaskRunStatus.FAILED, TaskRunStatus.TIMED_OUT}][:5]

        pending_approvals = [t for t in tasks if t.status == TaskStatus.NEEDS_APPROVAL]
        stuck_running = [t for t in tasks if t.status == TaskStatus.RUNNING]

        ollama_ok = False
        ollama_error = ""
        try:
            import urllib.request
            with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=3) as resp:
                ollama_ok = resp.status == 200
        except Exception as exc:  # noqa: BLE001
            ollama_error = str(exc)

        lines = [
            "=== Primordial System Diagnostics ===",
            f"Ollama reachable: {'yes' if ollama_ok else f'NO - {ollama_error}'}",
            f"Execution mode: {mode['mode']} (interval: {mode['interval_seconds']}s)",
            f"Targets: {len(targets)}  |  Tasks total: {len(tasks)}",
            f"Task status breakdown: {status_counts}",
        ]
        if active_runs:
            lines.append(f"Active runs ({len(active_runs)}):")
            for r in active_runs:
                age = (utc_now() - r.started_at).total_seconds()
                lines.append(f"  - {r.role.value} | {r.model_name} | {r.status.value} | running {age:.0f}s")
        else:
            lines.append("Active runs: none")
        if pending_approvals:
            lines.append(f"Awaiting approval ({len(pending_approvals)}):")
            for t in pending_approvals[:5]:
                lines.append(f"  - [{t.id}] {t.title}")
        if stuck_running:
            lines.append(f"Tasks stuck in RUNNING state (no active run): {len(stuck_running)}")
            lines.append("  -> Run 'repair_execution_state' or restart to recover")
        if failed_recent:
            lines.append("Recent failures:")
            for r in failed_recent:
                lines.append(f"  - {r.role.value} | {r.model_name} | {r.error or 'no error recorded'}")
        roles = models.get("roles", [])
        lines.append("Model routes:")
        for role in roles:
            if isinstance(role, dict):
                lines.append(f"  {role.get('role')}: {role.get('selected_model')} ({role.get('processor')})")
        if not targets:
            lines.append("WARNING: No targets configured — ticks will produce no tasks until scope is added")
        for target in targets:
            assets = self.store.list_scope_assets(target.id)
            lines.append(f"Target '{target.handle}': {len(assets)} scope asset(s) | active_ip={target.metadata.get('active_ip') or 'not set'}")
        return {"lines": lines, "summary": "\n".join(lines)}

    def remove_target(self, handle: str, profile: ScopeProfile | None = None) -> dict[str, object]:
        target = self.store.get_target_by_handle(handle, profile)
        if target is None:
            return {"removed": False, "handle": handle}
        allow_destructive_delete = (
            os.getenv("PRIMORDIAL_ALLOW_DESTRUCTIVE_TARGET_DELETE", "").strip()
            == "I_UNDERSTAND_TARGET_RUNTIME_RECORDS_WILL_BE_DELETED"
        )
        deletion = self.store.delete_target_cascade(
            target.id,
            allow_runtime_record_deletion=allow_destructive_delete,
            deletion_reason=f"operator requested target removal for {target.handle}",
        )
        if deletion.get("blocked"):
            self.store.insert_event(
                EventRecord(
                    type=EventType.SCOPE_UPDATED,
                    summary=f"Blocked destructive target removal: {target.handle}",
                    target_id=target.id,
                    metadata={
                        "profile": target.profile.value,
                        "reason": deletion.get("reason"),
                        "runtime_record_counts": deletion.get("runtime_record_counts", {}),
                    },
                )
            )
            return {
                "removed": False,
                "blocked": True,
                "handle": target.handle,
                "profile": target.profile.value,
                "reason": deletion.get("reason"),
                "runtime_record_counts": deletion.get("runtime_record_counts", {}),
            }
        self._cleanup_deleted_paths(deletion["artifact_paths"] + deletion["checkpoint_paths"])
        self.store.insert_event(
            EventRecord(
                type=EventType.SCOPE_UPDATED,
                summary=f"Removed target: {target.handle}",
                metadata={"profile": target.profile.value, "deleted_counts": deletion["deleted"]},
            )
        )
        return {
            "removed": True,
            "handle": target.handle,
            "profile": target.profile.value,
            "deleted": deletion["deleted"],
        }

    def dashboard(self) -> DashboardSnapshot:
        counts = self.store.count_all()
        return DashboardSnapshot(
            counts=counts,
            sessions=self.store.list_sessions(limit=4),
            targets=self.store.list_targets(),
            tasks=self.store.list_tasks(limit=12),
            task_runs=self.store.list_task_runs(limit=10),
            notes=self.store.list_notes(limit=6),
            interests=self.store.list_interests(limit=6),
            findings=self.store.list_findings(limit=6),
            notifications=self.store.list_notifications(limit=6),
            sync_jobs=self.store.list_external_sync_jobs(limit=6),
            events=self.store.list_events(limit=10),
        )

    def dashboard_payload(self) -> dict[str, object]:
        payload = json_ready(self.dashboard())
        payload["execution_mode"] = self.execution_mode_payload()
        payload["runtime_tuning"] = self.runtime_tuning_payload()
        payload["system_metrics"] = self.system_metrics_payload()
        payload["work_status"] = self.work_status_payload()
        payload["operator_intent"] = self.operator_intent_payload()
        return payload

    def work_status_payload(self, *, limit: int = 8) -> dict[str, object]:
        self.repair_execution_state()
        tasks = self.store.list_tasks(limit=500)
        runs = self.store.list_task_runs(limit=200)
        targets = {target.id: target for target in self.store.list_targets()}
        tasks_by_id = {task.id: task for task in tasks}

        active_run_statuses = {TaskRunStatus.CLAIMED, TaskRunStatus.RUNNING}
        active_runs = [
            run
            for run in runs
            if run.status in active_run_statuses and run.finished_at is None
        ][:limit]
        active_run_task_ids = {run.task_id for run in active_runs}
        running_tasks = [
            task
            for task in tasks
            if task.status == TaskStatus.RUNNING and task.id not in active_run_task_ids
        ][:limit]
        queued_tasks = [task for task in tasks if task.status == TaskStatus.PENDING][:limit]
        waiting_tasks = [
            task
            for task in tasks
            if task.status in {TaskStatus.WAITING, TaskStatus.NEEDS_APPROVAL}
        ][:limit]
        recent_runs = [
            run
            for run in runs
            if run.status not in active_run_statuses or run.finished_at is not None
        ][:limit]

        def target_label(target_id: str | None) -> str | None:
            if not target_id:
                return None
            target = targets.get(target_id)
            return target.handle if target else target_id

        def task_payload(task) -> dict[str, object]:
            return {
                "kind": "task",
                "task_id": task.id,
                "task_kind": task.kind.value,
                "title": task.title,
                "summary": task.summary,
                "status": task.status.value,
                "agent": task.role.value,
                "route": task.provider_route.value if task.provider_route else None,
                "model": task.provider_model,
                "worker_contract": task.metadata.get("worker_contract"),
                "target": target_label(task.target_id),
                "metadata": json_ready(task.metadata),
                "active_ip_generation": task.metadata.get("active_ip_generation"),
                "invalid_target": bool(task.metadata.get("invalid_target")),
                "updated_at": task.updated_at.isoformat(),
            }

        def run_payload(run) -> dict[str, object]:
            task = tasks_by_id.get(run.task_id)
            return {
                "kind": "run",
                "run_id": run.id,
                "task_id": run.task_id,
                "task_kind": task.kind.value if task else None,
                "title": task.title if task else run.trace_summary,
                "summary": run.trace_summary,
                "status": run.status.value,
                "agent": run.role.value,
                "route": run.provider_route.value,
                "model": run.model_name,
                "worker_contract": run.metadata.get("worker_contract"),
                "suitability_score": run.metadata.get("suitability_score"),
                "target": target_label(task.target_id if task else None),
                "metadata": json_ready(task.metadata) if task else {},
                "active_ip_generation": task.metadata.get("active_ip_generation") if task else None,
                "invalid_target": bool(task.metadata.get("invalid_target")) if task else False,
                "started_at": run.started_at.isoformat(),
                "heartbeat_at": run.heartbeat_at.isoformat() if run.heartbeat_at else None,
                "finished_at": run.finished_at.isoformat() if run.finished_at else None,
                "error": run.error,
            }

        active_items = [run_payload(run) for run in active_runs] + [task_payload(task) for task in running_tasks]
        queued_items = [task_payload(task) for task in queued_tasks]
        waiting_items = [task_payload(task) for task in waiting_tasks]
        recent_items = [run_payload(run) for run in recent_runs]
        mode = self.execution_mode_payload()
        blockers = self._work_status_blockers()
        target_states = []
        for target in targets.values():
            state = self._live_methodology_state_payload(target)
            if not state:
                continue
            target_states.append(
                {
                    "target": target.handle,
                    "phase": state.get("phase"),
                    "subphase": state.get("subphase"),
                    "completion": state.get("completion"),
                    "transition_reason": state.get("transition_reason"),
                    "next_unblock_action": state.get("next_unblock_action"),
                    "no_progress_reason": state.get("no_progress_reason"),
                    "candidate_actions": state.get("candidate_actions", []),
                }
            )

        if active_items:
            summary = f"Working on {len(active_items)} active item(s)."
        elif queued_items:
            summary = f"Idle between executions; {len(queued_items)} task(s) are queued."
        elif waiting_items:
            summary = f"Blocked or waiting; {len(waiting_items)} task(s) need approval or resume."
        elif target_states and target_states[0].get("no_progress_reason"):
            summary = "Idle/stalled: " + str(target_states[0]["no_progress_reason"])
        elif blockers:
            summary = "Idle/stalled: " + blockers[0]["summary"]
        elif mode["mode"] == "continuous":
            summary = f"Continuous mode is enabled; waiting for the next {mode['interval_seconds']}s tick."
        else:
            summary = "Idle; no active, queued, or waiting work is currently visible."

        return {
            "summary": summary,
            "is_busy": bool(active_items),
            "updated_at": utc_now().isoformat(),
            "execution_mode": mode,
            "counts": {
                "active": len(active_items),
                "queued": len([task for task in tasks if task.status == TaskStatus.PENDING]),
                "waiting": len(
                    [
                        task
                        for task in tasks
                        if task.status in {TaskStatus.WAITING, TaskStatus.NEEDS_APPROVAL}
                    ]
                ),
            },
            "active": active_items,
            "queued": queued_items,
            "waiting": waiting_items,
            "recent": recent_items,
            "blockers": blockers,
            "target_states": target_states,
        }

    def _work_status_blockers(self) -> list[dict[str, object]]:
        blockers: list[dict[str, object]] = []
        primitives = self.store.list_primitives()
        capabilities = {
            tag.lower()
            for primitive in primitives
            for tag in [primitive.name, *primitive.capability_tags]
        }
        lab_credentials_configured = self._lab_credentials_configured()
        for target in self.store.list_targets():
            evidence = self.store.list_evidence(target_id=target.id, limit=100)
            active_generation = self._target_active_generation(target)
            current_evidence = [
                item
                for item in evidence
                if self._record_matches_active_generation(item, active_generation)
            ]
            interests = self.store.list_interests(target_id=target.id, limit=100)
            findings = self.store.list_findings(target_id=target.id, limit=20)
            if target.metadata.get("active_ip"):
                active_generation = str(target.metadata.get("active_ip_generation", ""))
                has_current_recon = any(
                    item.metadata.get("kind") == "tcp_service_discovery"
                    and str(item.metadata.get("active_ip_generation", "")) == active_generation
                    for item in evidence
                )
                if active_generation and not has_current_recon:
                    blockers.append(
                        {
                            "target": target.handle,
                            "kind": "stale_recon",
                            "summary": (
                                f"`{target.handle}` active IP changed to `{target.metadata['active_ip']}`; "
                                "fresh service discovery has not completed yet."
                            ),
                        }
                    )
                    continue
            has_poc_candidates = any(
                item.metadata.get("kind") == "exploit_research" and int(item.metadata.get("match_count", 0) or 0) > 0
                for item in evidence
            ) or any(item.metadata.get("class") == "exploit_research" for item in interests)
            has_poc_validation = any(item.metadata.get("kind") == "poc_applicability_validation" for item in evidence)
            if has_poc_candidates and not has_poc_validation:
                if self._poc_adaptation_available(capabilities):
                    blockers.append(
                        {
                            "target": target.handle,
                            "kind": "runnable_poc_validation",
                            "summary": f"`{target.handle}` has public PoC candidates waiting for gated applicability validation.",
                        }
                    )
                else:
                    blockers.append(
                        {
                            "target": target.handle,
                            "kind": "missing_poc_validation_primitive",
                            "summary": f"`{target.handle}` has PoC candidates but no PoC applicability primitive is registered.",
                        }
                    )
                continue
            has_credentialed_capability = self._has_any_capability(
                capabilities,
                "credentialed-access-check",
                "smb-session",
                "winrm",
            )
            credential_surface = classify_credentialed_access_surface(current_evidence)
            if has_credentialed_capability and not lab_credentials_configured and credential_surface.eligible:
                blockers.append(
                    {
                        "target": target.handle,
                        "kind": "missing_known_credentials",
                        "summary": (
                            f"`{target.handle}` has evidence-supported Windows SMB/WinRM services, but known username/password are not configured."
                        ),
                    }
                )
                continue
            if not findings and evidence:
                blockers.append(
                    {
                        "target": target.handle,
                        "kind": "no_verified_path",
                        "summary": f"`{target.handle}` has evidence, but no verified finding or runnable exploit path yet.",
                    }
                )
        return blockers[:8]

    def _target_has_remote_admin_surface(self, evidence: list[EvidenceRecord]) -> bool:
        return classify_credentialed_access_surface(evidence).eligible

    def scope_payload(self) -> dict[str, object]:
        targets = self.store.list_targets()
        all_tasks = self.store.list_tasks(limit=500)
        all_evidence = self.store.list_evidence(limit=500)
        all_notes = self.store.list_notes(limit=500)
        all_interests = self.store.list_interests(limit=500)
        all_findings = self.store.list_findings(limit=500)
        scope_targets: list[dict[str, object]] = []
        for target in targets:
            assets = self.store.list_scope_assets(target.id)
            scope_targets.append(
                {
                    "target": target.as_payload(),
                    "assets": [asset.as_payload() for asset in assets],
                    "counts": {
                        "assets": len(assets),
                        "tasks": sum(1 for item in all_tasks if item.target_id == target.id),
                        "evidence": sum(1 for item in all_evidence if item.target_id == target.id),
                        "notes": sum(1 for item in all_notes if item.target_id == target.id),
                        "interests": sum(1 for item in all_interests if item.target_id == target.id),
                        "findings": sum(1 for item in all_findings if item.target_id == target.id),
                    },
                }
            )
        return {
            "targets": scope_targets,
            "totals": {
                "targets": len(targets),
                "in_scope": sum(1 for target in targets if target.in_scope),
                "assets": sum(len(item["assets"]) for item in scope_targets),
            },
        }

    def audit_payload(self, limit: int = 25) -> dict[str, object]:
        return {
            "counts": self.store.count_all(),
            "recent_events": [item.as_payload() for item in self.store.list_events(limit=limit)],
            "recent_traces": [item.as_payload() for item in self.store.list_traces(limit=limit)],
            "recent_checkpoints": [item.as_payload() for item in self.store.list_checkpoints(limit=limit)],
            "recent_notifications": [item.as_payload() for item in self.store.list_notifications(limit=limit)],
            "recent_sync_jobs": [item.as_payload() for item in self.store.list_external_sync_jobs(limit=limit)],
            "recent_runtime_events": [
                {
                    "signal": event.signal.value,
                    "payload": json_ready(event.payload),
                    "created_at": event.created_at.isoformat(),
                }
                for event in self.event_bus.recent(limit=limit)
            ],
        }

    def records_payload(self, limit: int = 25, target_id: str | None = None) -> dict[str, object]:
        target = self.store.get_target(target_id) if target_id else None
        return {
            "evidence": [item.as_payload() for item in self.store.list_evidence(target_id=target_id, limit=limit)],
            "notes": [item.as_payload() for item in self.store.list_notes(target_id=target_id, limit=limit)],
            "interests": [item.as_payload() for item in self.store.list_interests(target_id=target_id, limit=limit)],
            "findings": [item.as_payload() for item in self.store.list_findings(target_id=target_id, limit=limit)],
            "memory_entries": [
                item.as_payload() for item in self.store.list_memory_entries(target_id=target_id, limit=limit)
            ],
            "artifacts": [
                item.as_payload()
                for item in self.store.list_artifacts(limit=limit)
                if target_id is None or item.target_id == target_id
            ],
            "notifications": [item.as_payload() for item in self.store.list_notifications(limit=limit)],
            "sync_jobs": [item.as_payload() for item in self.store.list_external_sync_jobs(limit=limit)],
            "primitives": [item.as_payload() for item in self.store.list_primitives()],
            "operator_messages": [
                item.as_payload() for item in self.store.list_operator_messages(target_id=target_id, limit=limit)
            ],
            "findings_context": (
                self.findings_context.payload_for_target(target, include_guidance=False)
                if target
                else None
            ),
        }

    def operator_chat_payload(self, limit: int = 20, target: str | None = None) -> dict[str, object]:
        target_record = self._resolve_target_reference(target)
        return {
            "target": target_record.as_payload() if target_record else None,
            "messages": [
                item.as_payload()
                for item in reversed(
                    self.store.list_operator_messages(
                        target_id=target_record.id if target_record else None,
                        limit=limit,
                    )
                )
            ],
        }

    def rag_ingest_document(
        self,
        path: str | Path,
        *,
        target: str,
        use_docling: bool = True,
        embed: bool = True,
        corpus_type: str = "operator_note",
        source_trust: str | None = None,
        hint_policy: str | None = None,
        allow_remote_url: bool = False,
    ) -> dict[str, object]:
        target_record = self._resolve_target_reference(target)
        if target_record is None:
            raise ValueError(f"target not found: {target}")
        return self.rag.ingest_path(
            path,
            target=target_record,
            use_docling=use_docling,
            embed=embed,
            corpus_type=corpus_type,
            source_trust=source_trust,
            hint_policy=hint_policy,
            allow_remote_url=allow_remote_url,
        )

    def rag_search(
        self,
        query: str,
        *,
        target: str | None = None,
        limit: int = 5,
        corpus_types: list[str] | None = None,
        filters: dict[str, object] | None = None,
    ) -> dict[str, object]:
        target_record = self._resolve_target_reference(target) if target else None
        if target and target_record is None:
            raise ValueError(f"target not found: {target}")
        results = self.rag.retrieve(
            query,
            target_id=target_record.id if target_record else None,
            limit=limit,
            corpus_types=corpus_types,
            filters=filters,
        )
        payload_results = [item.as_payload() for item in results]
        return {
            "target": target_record.as_payload() if target_record else None,
            "query": query,
            "corpus_types": corpus_types or [],
            "filters": filters or {},
            "results": payload_results,
            "citation_map": self.rag_context_broker.citation_map_for_chunks(payload_results),
        }

    def build_rag_context_pack(
        self,
        query: str,
        *,
        purpose: str,
        role: str | AgentRole | None = None,
        target: str | Target | None = None,
        task: Task | None = None,
        limit: int = 5,
        filters: dict[str, object] | None = None,
    ) -> dict[str, object]:
        target_record: Target | None
        if isinstance(target, Target):
            target_record = target
        elif target:
            target_record = self._resolve_target_reference(str(target))
            if target_record is None:
                raise ValueError(f"target not found: {target}")
        elif task and task.target_id:
            target_record = self.store.get_target(task.target_id)
        else:
            target_record = None
        pack = self.rag_context_broker.build_pack(
            query,
            purpose=purpose,
            role=role,
            target=target_record,
            task=task,
            limit=limit,
            filters=filters,
            operator_intent=self.active_operator_intent().id,
            intent_policy=self.intent_policy(),
        )
        return pack.as_payload()

    def rag_status(self) -> dict[str, object]:
        counts = self.store.rag_status_counts()
        provider = self.rag_embedding_provider
        return {
            "ok": True,
            "configured_embeddings": {
                "provider": provider.provider_name,
                "model": provider.model_name,
                "dimension": provider.dimension,
                "canonical_model_family": getattr(provider, "canonical_model_family", None),
            },
            "configured_synthesis": {
                "provider": self.config.rag.synthesis.provider,
                "model": self.config.rag.synthesis.model,
                "disallowed_models": list(self.config.rag.synthesis.disallowed_models),
            },
            "last_import": self.store.get_setting(self.RAG_LAST_IMPORT_SETTING, {}),
            **counts,
        }

    def rag_vuln_status(self) -> dict[str, object]:
        payload = self.rag_status()
        payload["vuln_intel_chunks"] = self.store.count_document_chunks(metadata_filters={"domain": ["vuln_intel"]})
        payload["last_vuln_sync"] = self.store.get_setting(self.RAG_LAST_VULN_SYNC_SETTING, {})
        manifest_path = self.config.project_root / "primordial-rag-preprocess" / "output" / "vuln" / "manifests" / "vuln_stream_manifest.json"
        status_path = self.config.project_root / "primordial-rag-preprocess" / "output" / "vuln" / "status" / "vuln_sync_status.json"
        payload["vuln_manifest"] = self._read_optional_json(manifest_path)
        payload["vuln_sync_status_file"] = self._read_optional_json(status_path)
        payload["vuln_chunks_dir"] = str(self.config.project_root / "primordial-rag-preprocess" / "output" / "vuln" / "chunks")
        return payload

    def rag_vuln_sync(
        self,
        *,
        since_year: int = 2020,
        embed_all: bool = True,
        sources: list[str] | None = None,
        timeout_seconds: float = 45.0,
        rate_limit_seconds: float | None = None,
        max_nvd_pages: int | None = None,
        max_enrichment_cves: int = 250,
        skip_import: bool = False,
        force: bool = False,
        reembed: bool = False,
        skip_embeddings: bool = False,
        limit: int | None = None,
    ) -> dict[str, object]:
        allowed_sources = {"nvd", "kev", "epss", "cvelist_v5", "osv", "ghsa"}
        selected_sources = {str(source).strip() for source in sources or [] if str(source).strip()}
        if not selected_sources:
            selected_sources = set(allowed_sources)
        unknown = sorted(selected_sources - allowed_sources)
        if unknown:
            raise ValueError(f"unsupported vuln sync source(s): {', '.join(unknown)}")
        options = VulnSyncOptions(
            since_year=max(1999, int(since_year)),
            embed_all=bool(embed_all),
            sources=selected_sources,
            timeout_seconds=max(1.0, float(timeout_seconds)),
            rate_limit_seconds=rate_limit_seconds,
            max_nvd_pages=max_nvd_pages,
            max_enrichment_cves=max(0, int(max_enrichment_cves)),
        )
        syncer = VulnFeedSyncer(self.config.project_root)
        sync = syncer.sync(options)
        chunks_dir = Path(sync.get("chunks_dir") or self.config.project_root / "primordial-rag-preprocess" / "output" / "vuln" / "chunks")
        import_summary = None
        if not skip_import:
            import_summary = self.rag_import_chunks(
                chunks_dir,
                force=force,
                reembed=reembed,
                skip_embeddings=skip_embeddings,
                domains=["vuln_intel"],
                limit=limit,
            )
        result: dict[str, object] = {
            "ok": True,
            "sync": sync,
            "import": import_summary,
            "vuln_intel_chunks": self.store.count_document_chunks(metadata_filters={"domain": ["vuln_intel"]}),
            "chunks_dir": str(chunks_dir),
            "hints_only": True,
        }
        self.store.set_setting(
            self.RAG_LAST_VULN_SYNC_SETTING,
            {
                "completed_at": utc_now().isoformat(),
                "since_year": options.since_year,
                "embed_all": options.embed_all,
                "sources": sorted(selected_sources),
                "source_failures": sync.get("source_failures", {}),
                "preprocess_manifest": sync.get("preprocess_manifest", {}),
                "import": import_summary,
                "vuln_intel_chunks": result["vuln_intel_chunks"],
                "chunks_dir": str(chunks_dir),
            },
        )
        return result

    def _read_optional_json(self, path: Path) -> dict[str, object]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (json.JSONDecodeError, OSError) as exc:
            return {"error": str(exc), "path": str(path)}
        return payload if isinstance(payload, dict) else {"value": payload}

    def rag_config_payload(self) -> dict[str, object]:
        return {
            "ok": True,
            "embeddings": {
                "provider": self.config.rag.embeddings.provider,
                "base_url": self.config.rag.embeddings.base_url,
                "model": self.config.rag.embeddings.model,
                "batch_size": self.config.rag.embeddings.batch_size,
                "timeout_seconds": self.config.rag.embeddings.timeout_seconds,
                "canonical_model_family": self.config.rag.embeddings.canonical_model_family,
            },
            "synthesis": {
                "provider": self.config.rag.synthesis.provider,
                "base_url": self.config.rag.synthesis.base_url,
                "model": self.config.rag.synthesis.model,
                "temperature": self.config.rag.synthesis.temperature,
                "max_tokens": self.config.rag.synthesis.max_tokens,
                "backup_allowed_models": list(self.config.rag.synthesis.backup_allowed_models),
                "disallowed_models": list(self.config.rag.synthesis.disallowed_models),
            },
            "default_chunks_dir": str(self.config.project_root / "primordial-rag-preprocess" / "output" / "chunks"),
            "supported_domains": sorted(self.rag.CORPUS_TYPES),
            "context_pack_purposes": [
                "operator_answer",
                "planner_review",
                "worker_ai_review",
                "rag_synthesis",
                "report_mapping",
                "poc_design",
            ],
            "context_pack_roles": ["local_fast", "local_deep", "local_code", "local_compact", "operator_chat"],
            "supported_filters": [
                "domain",
                "source_file",
                "doc_id",
                "chunk_type",
                "card_type",
                "risk_family",
                "output_mode",
                "source_priority",
                "requires_authorized_scope",
                "vuln_id",
                "cve_id",
                "ghsa_id",
                "osv_id",
                "alias",
                "ecosystem",
                "package",
                "vendor",
                "product",
                "cpe",
                "purl",
                "cwe",
                "cvss_severity",
                "kev",
                "epss_probability",
                "epss_percentile",
                "fixed_version_known",
                "asset_match",
                "watchlist_match",
                "source_kind",
                "safety_level",
            ],
            "allowed_use_modes": [
                "authorized_bug_bounty",
                "ctf",
                "local_lab",
                "defensive_assessment",
                "academic_study",
            ],
        }

    def rag_import_chunks(
        self,
        chunks_dir: str | Path | None = None,
        *,
        dry_run: bool = False,
        force: bool = False,
        reembed: bool = False,
        skip_embeddings: bool = False,
        domains: list[str] | None = None,
        source_files: list[str] | None = None,
        doc_ids: list[str] | None = None,
        limit: int | None = None,
    ) -> dict[str, object]:
        importer = RagChunkImporter(
            self.store,
            self.rag_embedding_provider,
            batch_size=self.config.rag.embeddings.batch_size,
        )
        options = RagImportOptions(
            chunks_dir=Path(chunks_dir or self.config.project_root / "primordial-rag-preprocess" / "output" / "chunks"),
            dry_run=dry_run,
            force=force,
            reembed=reembed,
            skip_embeddings=skip_embeddings,
            domains={str(item).strip() for item in domains or [] if str(item).strip()},
            source_files={str(item).strip() for item in source_files or [] if str(item).strip()},
            doc_ids={str(item).strip() for item in doc_ids or [] if str(item).strip()},
            limit=limit,
        )
        summary = importer.import_chunks(options).as_payload()
        self._record_rag_import_summary(summary, options=options)
        return summary

    def _record_rag_import_summary(self, summary: dict[str, object], *, options: RagImportOptions) -> None:
        compact = {
            "completed_at": utc_now().isoformat(),
            "chunks_dir": str(options.chunks_dir),
            "dry_run": options.dry_run,
            "force": options.force,
            "reembed": options.reembed,
            "skip_embeddings": options.skip_embeddings,
            "domains": sorted(options.domains),
            "source_files": sorted(options.source_files),
            "doc_ids": sorted(options.doc_ids),
            "limit": options.limit,
            "files_seen": summary.get("files_seen", 0),
            "records_seen": summary.get("records_seen", 0),
            "chunks_inserted": summary.get("chunks_inserted", 0),
            "chunks_updated": summary.get("chunks_updated", 0),
            "chunks_skipped": summary.get("chunks_skipped", 0),
            "embeddings_inserted": summary.get("embeddings_inserted", 0),
            "embeddings_updated": summary.get("embeddings_updated", 0),
            "embeddings_skipped": summary.get("embeddings_skipped", 0),
            "failures": summary.get("failures", 0),
            "embedding_provider": summary.get("embedding_provider"),
            "embedding_model": summary.get("embedding_model"),
            "failed_record_ids": list(summary.get("failed_record_ids", []) if isinstance(summary.get("failed_record_ids"), list) else [])[:100],
            "errors": list(summary.get("errors", []) if isinstance(summary.get("errors"), list) else [])[:20],
        }
        self.store.set_setting(self.RAG_LAST_IMPORT_SETTING, compact)

    def rag_chunk_inspect(self, chunk_id: str) -> dict[str, object]:
        normalized = chunk_id.strip()
        if normalized.startswith("rag:"):
            normalized = normalized[4:]
        chunk = self.store.get_document_chunk(normalized)
        if chunk is None:
            citation_id = chunk_id.strip()
            if citation_id and not citation_id.startswith("rag:"):
                citation_id = f"rag:{citation_id}"
            matches = self.store.list_document_chunks(metadata_filters={"citation_id": [citation_id]}, limit=2)
            chunk = matches[0] if matches else None
        if chunk is None:
            raise ValueError(f"RAG chunk not found: {chunk_id}")
        embedding = self.store.get_record_embedding(
            record_type="document_chunk",
            record_id=chunk.id,
            embedding_model=self.rag_embedding_provider.model_name,
        )
        return {
            "chunk": {**chunk.as_payload(), "citation_id": self._rag_chunk_citation_id(chunk)},
            "embedding": embedding.as_payload() if embedding else None,
        }

    def _rag_chunk_citation_id(self, chunk: DocumentChunk) -> str:
        citation_id = str(chunk.metadata.get("citation_id") or "").strip()
        if not citation_id or citation_id in {"rag:None", "rag:null", "rag:unknown"}:
            citation_id = chunk.id
        return citation_id if citation_id.startswith("rag:") else f"rag:{citation_id}"

    def _rag_payload_citation_id(self, item: dict[str, object]) -> str:
        citation_id = str(item.get("citation_id") or "").strip()
        if not citation_id or citation_id in {"rag:None", "rag:null", "rag:unknown"}:
            citation_id = str(item.get("chunk_id") or item.get("id") or "unknown").strip() or "unknown"
        return citation_id if citation_id.startswith("rag:") else f"rag:{citation_id}"

    def rag_source_profile(self, doc_id: str, *, limit: int = 50) -> dict[str, object]:
        clean = str(doc_id or "").strip()
        if not clean:
            raise ValueError("doc_id is required")
        total = self.store.count_document_chunks(metadata_filters={"doc_id": [clean]})
        chunks = self.store.list_document_chunks(metadata_filters={"doc_id": [clean]}, limit=max(1, limit))
        if not chunks:
            raise ValueError(f"RAG source not found: {doc_id}")
        metadata_rows = [chunk.metadata for chunk in chunks if isinstance(chunk.metadata, dict)]
        first = metadata_rows[0] if metadata_rows else {}
        sections = []
        for metadata in metadata_rows:
            section = str(metadata.get("section") or "").strip()
            if section and section not in sections:
                sections.append(section)
        domains = sorted(
            {
                str(metadata.get("domain") or metadata.get("corpus_type") or "").strip()
                for metadata in metadata_rows
                if str(metadata.get("domain") or metadata.get("corpus_type") or "").strip()
            }
        )
        source_files = sorted(
            {
                str(metadata.get("source_file") or metadata.get("source_path") or "").strip()
                for metadata in metadata_rows
                if str(metadata.get("source_file") or metadata.get("source_path") or "").strip()
            }
        )
        page_values = []
        for metadata in metadata_rows:
            for key in ("page_start", "page_end"):
                try:
                    if metadata.get(key) is not None:
                        page_values.append(int(metadata[key]))
                except (TypeError, ValueError):
                    continue
        sample_chunks = []
        for chunk in chunks[: max(1, min(limit, 25))]:
            metadata = chunk.metadata if isinstance(chunk.metadata, dict) else {}
            text = chunk.text
            if len(text) > 900:
                text = text[:900].rstrip() + "\n...TRUNCATED_RAG_CHUNK..."
            sample_chunks.append(
                {
                    "chunk_id": chunk.id,
                    "citation_id": self._rag_chunk_citation_id(chunk),
                    "title": chunk.title,
                    "section": metadata.get("section"),
                    "page_start": metadata.get("page_start"),
                    "page_end": metadata.get("page_end"),
                    "chunk_index": chunk.chunk_index,
                    "text": text,
                }
            )
        return {
            "ok": True,
            "doc_id": clean,
            "chunk_count": total,
            "returned_chunks": len(chunks),
            "title": first.get("title") or first.get("source_file") or chunks[0].title,
            "source_file": source_files[0] if source_files else first.get("source_file"),
            "source_files": source_files,
            "source_sha256": chunks[0].source_sha256,
            "source_type": first.get("source_type"),
            "domains": domains,
            "profile": first.get("profile") if isinstance(first.get("profile"), dict) else {},
            "sections": sections[:200],
            "page_start": min(page_values) if page_values else None,
            "page_end": max(page_values) if page_values else None,
            "sample_chunks": sample_chunks,
        }

    def rag_eval_probes(
        self,
        queries: list[str],
        *,
        target: str | None = None,
        limit: int = 5,
        corpus_types: list[str] | None = None,
        filters: dict[str, object] | None = None,
    ) -> dict[str, object]:
        clean_queries = [query.strip() for query in queries if str(query).strip()]
        results = []
        for query in clean_queries:
            search = self.rag_search(
                query,
                target=target,
                limit=limit,
                corpus_types=corpus_types,
                filters=filters,
            )
            rows = search.get("results", [])
            top = rows if isinstance(rows, list) else []
            results.append(
                {
                    "query": query,
                    "result_count": len(top),
                    "top_citations": [self._rag_payload_citation_id(item) for item in top[:5] if isinstance(item, dict)],
                    "top_results": top[:3],
                }
            )
        return {
            "ok": True,
            "mode": "retrieval_only",
            "query_count": len(clean_queries),
            "limit": limit,
            "target": target,
            "corpus_types": corpus_types or [],
            "filters": filters or {},
            "results": results,
        }

    def synthesize_rag_answer(
        self,
        query: str,
        *,
        mode: str = "grounded_answer",
        retrieved_chunks: list[dict[str, object]] | None = None,
        safety_context: dict[str, object] | None = None,
    ) -> dict[str, object]:
        if retrieved_chunks is None:
            if is_operational_context_purpose(mode):
                return {
                    "ok": False,
                    "status": "operational_context_required",
                    "answer": "",
                    "error": (
                        "retrieved_chunks are required for operational RAG synthesis; "
                        "unscoped fallback retrieval is not allowed"
                    ),
                    "retrieved_ids": [],
                    "citation_map": [],
                    "validation": validate_rag_citations("", [], mode=mode, require_citations=True).as_payload(),
                }
            chunks = self.rag_search(query, limit=5)["results"]
        else:
            chunks = retrieved_chunks
        clean_chunks = [item for item in chunks if isinstance(item, dict) and not item.get("error")]
        citation_map = self.rag_context_broker.citation_map_for_chunks(clean_chunks)
        if is_operational_context_purpose(mode):
            rag_context_validation = self._validate_operational_rag_synthesis_context(clean_chunks, mode=mode)
            if not rag_context_validation.valid:
                return {
                    "ok": False,
                    "status": "invalid_rag_context",
                    "answer": "",
                    "error": "; ".join(rag_context_validation.errors),
                    "retrieved_ids": [self._rag_payload_citation_id(item) for item in clean_chunks],
                    "citation_map": citation_map,
                    "validation": validate_rag_citations("", clean_chunks, mode=mode, require_citations=True).as_payload(),
                }
        if not clean_chunks:
            return {
                "ok": False,
                "status": "insufficient_context",
                "answer": "",
                "retrieved_ids": [],
                "citation_map": [],
                "validation": validate_rag_citations("", [], mode=mode, require_citations=True).as_payload(),
            }
        disallowed = disallowed_rag_synthesis_model(
            self.config.rag.synthesis.model,
            self.config.rag.synthesis.disallowed_models,
        )
        if disallowed:
            return {
                "ok": False,
                "status": "disallowed_model",
                "answer": "",
                "error": f"RAG synthesis model {self.config.rag.synthesis.model!r} is disallowed by pattern {disallowed!r}",
                "retrieved_ids": [self._rag_payload_citation_id(item) for item in clean_chunks],
                "citation_map": citation_map,
                "validation": validate_rag_citations("", clean_chunks, mode=mode, require_citations=True).as_payload(),
            }
        system = build_wrapper_system_prompt(
            "rag_synthesis",
            (
                "Answer only from retrieved RAG context. Cite every factual sentence with rag:<chunk_id>. "
                "If context is insufficient, say exactly what is missing. Do not use MITRE taxonomy chunks "
                "to choose actions or expand scope."
            ),
        )
        prompt = self._rag_synthesis_prompt(query, clean_chunks, mode=mode, safety_context=safety_context or {})
        try:
            if self.config.rag.synthesis.provider == "ollama":
                response = self.ollama.generate(
                    model=self.config.rag.synthesis.model,
                    system=system,
                    prompt=prompt,
                    temperature=self.config.rag.synthesis.temperature,
                    timeout_seconds=300,
                )
                answer = response.text
                model = response.model
                provider = "ollama"
            else:
                client = LMStudioClient(
                    base_url=self._lmstudio_base_without_v1(self.config.rag.synthesis.base_url),
                    timeout_seconds=300,
                )
                response = client.chat(
                    model=self.config.rag.synthesis.model,
                    system=system,
                    prompt=prompt,
                    temperature=self.config.rag.synthesis.temperature,
                    max_tokens=self.config.rag.synthesis.max_tokens,
                    timeout_seconds=300,
                )
                answer = response.text
                model = response.model
                provider = "lmstudio_openai_compatible"
        except Exception as exc:  # noqa: BLE001 - surface model/provider failures as structured runtime output
            return {
                "ok": False,
                "status": "provider_error",
                "answer": "",
                "error": str(exc),
                "retrieved_ids": [self._rag_payload_citation_id(item) for item in clean_chunks],
                "citation_map": citation_map,
            }
        validation = validate_rag_citations(answer, clean_chunks, mode=mode, require_citations=True)
        return {
            "ok": validation.valid,
            "status": "ok" if validation.valid else "validation_failed",
            "answer": answer,
            "provider": provider,
            "model": model,
            "retrieved_ids": validation.retrieved_ids,
            "citation_map": citation_map,
            "validation": validation.as_payload(),
        }

    def _rag_synthesis_prompt(
        self,
        query: str,
        chunks: list[dict[str, object]],
        *,
        mode: str,
        safety_context: dict[str, object],
    ) -> str:
        lines = [
            f"Mode: {mode}",
            f"Question: {query.strip()}",
            f"Safety context: {json.dumps(json_ready(safety_context), sort_keys=True)}",
            "",
            "Retrieved context:",
        ]
        for item in chunks:
            citation_id = self._rag_payload_citation_id(item)
            metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
            source_display = str(item.get("source_display") or metadata.get("source_display") or "")
            text = str(item.get("text") or item.get("retrieval_text") or "").strip()
            if len(text) > 1800:
                text = text[:1800].rstrip() + "\n...TRUNCATED_RAG_CHUNK..."
            lines.extend(
                [
                    f"[{citation_id}]",
                    f"source={source_display}",
                    f"source_file={metadata.get('source_file') or item.get('source_file') or ''}",
                    f"domain={metadata.get('domain') or metadata.get('corpus_type') or ''}",
                    f"planner_visibility={metadata.get('planner_visibility') or ''}",
                    text,
                    "",
                ]
            )
        lines.append("Answer with citations using only rag:<chunk_id> IDs shown above.")
        return "\n".join(lines)

    def _validate_operational_rag_synthesis_context(
        self,
        chunks: list[dict[str, object]],
        *,
        mode: str,
    ):
        envelopes: list[ContextEnvelope] = []
        errors: list[str] = []
        for item in chunks:
            try:
                envelopes.append(ContextEnvelope.from_rag_chunk(item, purpose=mode, sink="prompt"))
            except ValueError as exc:
                errors.append(str(exc))
        result = ContextSinkValidator().validate("prompt", envelopes)
        if errors:
            result.valid = False
            result.errors.extend(errors)
            result.rejected_refs.extend(f"rag_context:{index}" for index in range(len(errors)))
        return result

    def _lmstudio_base_without_v1(self, base_url: str) -> str:
        clean = base_url.rstrip("/")
        return clean[:-3] if clean.endswith("/v1") else clean

    def rag_cve_search(self, query: str, *, target: str, limit: int = 5) -> dict[str, object]:
        target_record = self._resolve_target_reference(target)
        if target_record is None:
            raise ValueError(f"target not found: {target}")
        results = self.rag.retrieve(
            query,
            target_id=target_record.id,
            limit=limit,
            corpus_types=["vuln_intel", "cve_advisory", "exploit_note"],
        )
        evidence = self.workflow._current_generation_evidence(target_record, limit=200)
        payload_results: list[dict[str, object]] = []
        for item in results:
            payload = item.as_payload()
            payload["applicability_classification"] = self.workflow._rag_applicability_classification(item.chunk, evidence)
            payload["cve_ids"] = metadata_list_value(item.chunk.metadata, "cve_ids")
            payload["source_trust"] = metadata_value(item.chunk.metadata, "source_trust")
            payload_results.append(payload)
        return {
            "target": target_record.as_payload(),
            "query": query,
            "corpus_types": ["vuln_intel", "cve_advisory", "exploit_note"],
            "results": payload_results,
        }

    def rag_vuln_search(
        self,
        query: str,
        *,
        limit: int = 8,
        filters: dict[str, object] | None = None,
    ) -> dict[str, object]:
        clean_filters = {"domain": ["vuln_intel"], **(filters or {})}
        return self.rag_search(
            query or "vulnerability remediation detection affected package",
            limit=limit,
            corpus_types=["vuln_intel"],
            filters=clean_filters,
        )

    def rag_vuln_hints(
        self,
        query: str,
        *,
        limit: int = 8,
        filters: dict[str, object] | None = None,
    ) -> dict[str, object]:
        search = self.rag_vuln_search(query, limit=limit, filters=filters)
        hints = vulnerability_hints_from_results(
            [item for item in search.get("results", []) if isinstance(item, dict)]
        )
        return {
            "query": query,
            "search": search,
            **hints,
        }

    def rag_hints(self, query: str, *, target: str, limit: int = 8) -> dict[str, object]:
        target_record = self._resolve_target_reference(target)
        if target_record is None:
            raise ValueError(f"target not found: {target}")
        hints = self.workflow.build_rag_task_hints(target_record, query=query, limit=limit)
        return {
            "target": target_record.as_payload(),
            "query": query,
            "hints": {
                "accepted": hints.get("accepted", []),
                "rejected": hints.get("rejected", []),
            },
            "candidate_actions": [
                {
                    "kind": action.kind.value,
                    "title": action.title,
                    "summary": action.summary,
                    "confidence": action.confidence,
                    "phase": action.phase_label,
                    "subphase": action.subphase,
                    "transition_reason": action.transition_reason,
                    "prerequisite": action.prerequisite,
                    "metadata": dict(action.metadata),
                }
                for action in hints.get("actions", [])
            ],
        }

    def ask_operator_ai(self, message: str, *, target: str | None = None) -> dict[str, object]:
        self.repair_execution_state()
        question = message.strip()
        if not question:
            raise ValueError("message is required")
        target_record = self._resolve_operator_chat_target(target, question)
        route_model = self._wrapper_model_label() if self._use_only_wrapper_mode() else self.config.topology.local_deep
        route_num_gpu = self._role_num_gpu("local_deep")
        model = route_model
        operator_message = OperatorMessage(
            role="operator",
            body=question,
            target_id=target_record.id if target_record else None,
            metadata={"target_reference": target},
        )
        self.store.insert_operator_message(operator_message)
        self._write_operator_chat_log(operator_message)
        self.store.insert_event(
            EventRecord(
                type=EventType.OPERATOR_MESSAGE,
                summary="Operator message recorded",
                target_id=operator_message.target_id,
                metadata={"message_id": operator_message.id},
            )
        )

        system = (
            "You are Primordial's operator-facing runtime assistant. Answer only from the supplied "
            "runtime snapshot and recent operator messages. Be concise, cite record IDs when useful, "
            "do not invent findings, credentials, flags, or tool results, and distinguish facts from "
            "next-step recommendations. If a requested action would require a task, approval, or a "
            "new primitive, say so explicitly instead of pretending it has happened. Do not include "
            "generic security disclaimers or generic pentest playbooks; this console is for an "
            "authorized local runtime and needs concrete state-aware answers."
        )
        rag_context_for_answer = self._rag_context_payload(question, target_record.id if target_record else None)
        prompt = self._build_operator_prompt(question, target_record.id if target_record else None)
        direct_state_answer = self._operator_state_update_or_direct_answer(question, target_record)
        if direct_state_answer is not None:
            assistant_body = direct_state_answer
            model = "deterministic-state"
            metadata = {"ok": True, "mode": "operator_state_reducer", "route_model": route_model}
            ok = True
            error = None
        elif self._should_answer_from_state(question):
            deterministic_body = self._deterministic_operator_answer(question, target_record.id if target_record else None)
            assistant_body = deterministic_body
            model = "deterministic-state"
            deterministic_only = self._operator_question_requires_deterministic_only(question)
            metadata = {
                "ok": True,
                "mode": "deterministic_state_answer",
                "route_model": route_model,
                "ai_review_attempted": not deterministic_only,
            }
            ai_review = None
            if not deterministic_only:
                ai_review = self._operator_state_ai_review(
                    question=question,
                    deterministic_body=deterministic_body,
                    target_id=target_record.id if target_record else None,
                    route_model=route_model,
                    route_num_gpu=route_num_gpu,
                )
            if ai_review:
                assistant_body = f"{deterministic_body}\n\n**AI Review**\n{ai_review['text']}"
                model = str(ai_review["model"])
                metadata.update(
                    {
                        "mode": "deterministic_state_with_local_review",
                        "ai_review_model": ai_review["model"],
                        "elapsed_seconds": ai_review["elapsed_seconds"],
                        "route_num_gpu": route_num_gpu,
                    }
                )
            ok = True
            error = None
        else:
            try:
                if self._use_only_wrapper_mode():
                    response_payload = self._wrapper_ai_generate(
                        role="operator_chat",
                        system=system,
                        prompt=prompt,
                        persist=False,
                    )
                    assistant_body = str(response_payload["text"])
                    model = str(response_payload["model"])
                    elapsed_seconds = response_payload.get("elapsed_seconds")
                else:
                    response = self.ollama.generate(
                        model=route_model,
                        system=system,
                        prompt=prompt,
                        num_gpu=route_num_gpu,
                    )
                    assistant_body = response.text
                    model = route_model
                    elapsed_seconds = response.elapsed_seconds
                metadata = {
                    "elapsed_seconds": elapsed_seconds,
                    "ok": True,
                    "mode": "wrapper_only" if self._use_only_wrapper_mode() else "local_model",
                    "route_num_gpu": route_num_gpu,
                    "rag_context_ids": self._rag_context_ids(rag_context_for_answer),
                }
                if rag_context_for_answer and not self._operator_answer_cites_rag_context(
                    assistant_body,
                    rag_context_for_answer,
                ):
                    assistant_body = self._deterministic_operator_answer(
                        question,
                        target_record.id if target_record else None,
                    )
                    model = "deterministic-state"
                    metadata["guardrail_discarded_uncited_rag_output"] = True
                    metadata["mode"] = "deterministic_state_answer"
                    metadata["route_model"] = route_model
                elif self._operator_answer_violates_contract(assistant_body):
                    assistant_body = self._deterministic_operator_answer(
                        question,
                        target_record.id if target_record else None,
                    )
                    model = "deterministic-state"
                    metadata["guardrail_replaced_model_output"] = True
                    metadata["mode"] = "deterministic_state_answer"
                    metadata["route_model"] = route_model
                ok = True
                error = None
            except Exception as exc:  # noqa: BLE001 - convert provider failures into durable operator-visible state
                assistant_body = f"AI response failed: {exc}"
                metadata = {"ok": False, "error": str(exc)}
                ok = False
                error = str(exc)

        escalation_reason = self._operator_uncertainty_escalation_reason(question, assistant_body, metadata, target_record)
        if escalation_reason and target_record is not None:
            escalation_task = self.workflow.create_planner_uncertainty_escalation(
                target_record,
                reason_code=escalation_reason,
                question=question,
                blockers=[],
                session_id=self.store.get_active_session().id if self.store.get_active_session() else None,
            )
            if escalation_task is not None:
                metadata["planner_uncertainty_escalation_task_id"] = escalation_task.id
                metadata["planner_uncertainty_escalation_reason"] = escalation_reason
            assistant_body = self._append_operator_escalation_status(
                assistant_body,
                target_record,
                escalation_task=escalation_task,
                reason=escalation_reason,
            )

        assistant_message = OperatorMessage(
            role="assistant",
            body=assistant_body,
            target_id=target_record.id if target_record else None,
            model=model,
            metadata=metadata,
        )
        self.store.insert_operator_message(assistant_message)
        self._write_operator_chat_log(assistant_message)
        self.store.insert_event(
            EventRecord(
                type=EventType.OPERATOR_AI_RESPONSE,
                summary="Operator AI response recorded" if ok else "Operator AI response failed",
                target_id=assistant_message.target_id,
                metadata={"message_id": assistant_message.id, "model": model, "ok": ok},
            )
        )
        return {
            "ok": ok,
            "error": error,
            "model": model,
            "route_model": route_model,
            "route_num_gpu": route_num_gpu,
            "question": operator_message.as_payload(),
            "answer": assistant_message.as_payload(),
            "chat": self.operator_chat_payload(target=target),
        }

    def ask_approval_inquiry(self, task_id: str, message: str) -> dict[str, object]:
        question = message.strip()
        if not question:
            raise ValueError("message is required")
        task = self.store.get_task(task_id)
        if task is None:
            raise ValueError(f"task not found: {task_id}")
        target = self.store.get_target(task.target_id) if task.target_id else None
        operator_message = OperatorMessage(
            role="operator",
            body=question,
            target_id=target.id if target else None,
            metadata={
                "approval_task_id": task.id,
                "approval_inquiry": True,
            },
        )
        self.store.insert_operator_message(operator_message)
        self._write_operator_chat_log(operator_message)
        self.store.insert_event(
            EventRecord(
                type=EventType.OPERATOR_MESSAGE,
                summary="Approval inquiry recorded",
                target_id=operator_message.target_id,
                task_id=task.id,
                metadata={"message_id": operator_message.id, "approval_task_id": task.id},
            )
        )

        evidence_refs = self._approval_evidence_refs(task)
        evidence_records = [record for ref in evidence_refs if (record := self.store.get_evidence(ref)) is not None]
        answer = self._deterministic_approval_inquiry_answer(
            question,
            task=task,
            target=target,
            evidence_refs=evidence_refs,
            evidence_records=evidence_records,
        )
        assistant_message = OperatorMessage(
            role="assistant",
            body=answer,
            target_id=target.id if target else None,
            model="deterministic-approval",
            metadata={
                "approval_task_id": task.id,
                "approval_inquiry": True,
                "evidence_refs": evidence_refs,
            },
        )
        self.store.insert_operator_message(assistant_message)
        self._write_operator_chat_log(assistant_message)
        self.store.insert_event(
            EventRecord(
                type=EventType.OPERATOR_AI_RESPONSE,
                summary="Approval inquiry answered",
                target_id=assistant_message.target_id,
                task_id=task.id,
                metadata={
                    "message_id": assistant_message.id,
                    "model": "deterministic-approval",
                    "approval_task_id": task.id,
                    "evidence_refs": evidence_refs,
                },
            )
        )
        return {
            "ok": True,
            "model": "deterministic-approval",
            "question": operator_message.as_payload(),
            "answer": assistant_message.as_payload(),
            "task": task.as_payload(),
            "target": target.as_payload() if target else None,
            "evidence_refs": evidence_refs,
            "evidence": [record.as_payload() for record in evidence_records],
        }

    def _approval_evidence_refs(self, task: Task) -> list[str]:
        refs: list[str] = []

        def add(value: object) -> None:
            if isinstance(value, str):
                if value.startswith("evidence_") and value not in refs:
                    refs.append(value)
                return
            if isinstance(value, list | tuple | set):
                for item in value:
                    add(item)
                return
            if isinstance(value, dict):
                for key, item in value.items():
                    if "evidence" in str(key).lower():
                        add(item)
                    elif isinstance(item, dict | list | tuple | set):
                        add(item)

        add(task.evidence_refs)
        add(task.metadata)
        return refs

    def _deterministic_approval_inquiry_answer(
        self,
        question: str,
        *,
        task: Task,
        target: Target | None,
        evidence_refs: list[str],
        evidence_records: list[EvidenceRecord],
    ) -> str:
        lowered = question.lower()
        target_label = target.handle if target else "global"
        primitive = task.metadata.get("primitive_hint") or task.metadata.get("primitive") or task.kind.value
        intent = self.active_operator_intent().id
        active_generation = self._target_active_generation(target)
        current_records = [
            item for item in evidence_records if self._record_matches_active_generation(item, active_generation)
        ]
        stale_records = [item for item in evidence_records if item not in current_records]

        lines: list[str] = []
        if any(term in lowered for term in ("exact request", "show me", "request", "what is this")):
            lines.extend(
                [
                    "**Approval Request**",
                    f"- Task: `{task.id}`",
                    f"- Title: {task.title}",
                    f"- Kind: `{task.kind.value}`",
                    f"- Target: `{target_label}`",
                    f"- Primitive/request hint: `{primitive}`",
                    f"- Status: `{task.status.value}`; approval required: `{task.requires_approval}`",
                    f"- Risk: `{task.risk_tier.value}`; priority: `{task.priority}`",
                    f"- Active Operator Intent: `{intent}`",
                    f"- Summary: {task.summary}",
                    f"- Required capabilities: {', '.join(task.required_capabilities) if task.required_capabilities else 'none declared'}",
                    f"- Attached evidence refs: {', '.join(f'`{ref}`' for ref in evidence_refs) if evidence_refs else 'none'}",
                    f"- Inspect raw task: `/api/inspect/task/{task.id}`",
                ]
            )
            if task.metadata:
                lines.append(f"- Metadata keys: {', '.join(sorted(str(key) for key in task.metadata.keys()))}")
        elif any(term in lowered for term in ("evidence", "backs", "proof", "why", "support")):
            lines.extend(
                [
                    "**Evidence Check**",
                    f"- Task: `{task.id}`",
                    f"- Attached evidence refs: {', '.join(f'`{ref}`' for ref in evidence_refs) if evidence_refs else 'none'}",
                    f"- Current-generation attached evidence: {len(current_records)}",
                    f"- Stale-generation attached evidence: {len(stale_records)}",
                ]
            )
            if not evidence_refs:
                lines.append("- No evidence refs are attached to this approval request. Treat it as unsupported until the planner supplies current evidence.")
            missing = [ref for ref in evidence_refs if self.store.get_evidence(ref) is None]
            if missing:
                lines.append("- Missing evidence records: " + ", ".join(f"`{ref}`" for ref in missing))
            for item in current_records[:8]:
                lines.append(
                    f"- CURRENT `{item.id}` {item.title}: {item.summary} "
                    f"(confidence={item.confidence:.2f}, freshness={item.freshness:.2f})"
                )
            for item in stale_records[:5]:
                generation = item.metadata.get("active_ip_generation", "unknown")
                lines.append(f"- STALE `{item.id}` generation={generation} {item.title}: {item.summary}")
        else:
            lines.extend(
                [
                    "**Approval Inquiry**",
                    f"- Task `{task.id}` is waiting on `{task.kind.value}` for `{target_label}`.",
                    f"- Ask `show me the exact request` for the request packet.",
                    f"- Ask `what evidence backs this?` for attached evidence and current/stale generation status.",
                    "- Inquiry messages do not approve, deny, or modify the task.",
                ]
            )
        return "\n".join(lines)

    def export_operator_chat_logs(self) -> int:
        exported = 0
        for message in self.store.list_operator_messages(limit=10000):
            if self._write_operator_chat_log(message):
                exported += 1
        return exported

    def _write_operator_chat_log(self, message: OperatorMessage) -> bool:
        target = self.store.get_target(message.target_id) if message.target_id else None
        target_fragment = self._safe_log_fragment(target.handle if target else "global")
        day_dir = self.config.chat_logs_dir / message.created_at.strftime("%Y-%m-%d")
        day_dir.mkdir(parents=True, exist_ok=True)
        timestamp = message.created_at.strftime("%Y%m%dT%H%M%S%fZ")
        path = day_dir / f"{timestamp}_{message.id}_{message.role}_{target_fragment}.json"
        if path.exists():
            return False
        payload = {
            "id": message.id,
            "created_at": message.created_at.isoformat(),
            "role": message.role,
            "model": message.model,
            "target": target.as_payload() if target else None,
            "body": message.body,
            "metadata": json_ready(message.metadata),
        }
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return True

    def _safe_log_fragment(self, value: str) -> str:
        fragment = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
        return fragment.strip("._-")[:80] or "global"

    def task_audit_payload(self, task_id: str, limit: int = 25) -> dict[str, object] | None:
        task = self.store.get_task(task_id)
        if task is None:
            return None
        target = self.store.get_target(task.target_id)
        runs = self.store.list_task_runs(task_id=task_id, limit=limit)
        run_ids = {run.id for run in runs}
        checkpoints = [
            item.as_payload()
            for item in self.store.list_checkpoints(limit=limit * 5)
            if item.task_id == task_id or item.run_id in run_ids
        ][:limit]
        events = [
            item.as_payload()
            for item in self.store.list_events(limit=limit * 5)
            if item.task_id == task_id
        ][:limit]
        return {
            "task": task.as_payload(),
            "target": target.as_payload() if target else None,
            "runs": [item.as_payload() for item in runs],
            "traces": [item.as_payload() for item in self.store.list_traces(task_id=task_id, limit=limit)],
            "handoffs": [item.as_payload() for item in self.store.list_handoffs(task_id=task_id, limit=limit)],
            "checkpoints": checkpoints,
            "events": events,
        }

    def inspect_object(self, kind: str, object_id: str, *, limit: int = 25) -> dict[str, object]:
        normalized = self._normalize_inspect_kind(kind)
        record = self._lookup_inspect_record(normalized, object_id)
        if record is None:
            raise ValueError(f"{normalized} not found: {object_id}")
        payload = self._inspect_payload(record)
        related = self._inspect_related(normalized, payload, limit=limit)
        artifact_preview = self._inspect_artifact_preview(payload) if normalized in {"artifact", "checkpoint"} else None
        error_detail = self._inspect_error_detail(payload, related)
        return {
            "ok": True,
            "kind": normalized,
            "id": str(payload.get("id") or object_id),
            "title": self._inspect_title(normalized, payload),
            "summary": str(payload.get("summary") or payload.get("trace_summary") or payload.get("title") or ""),
            "record": payload,
            "related": related,
            "artifact_preview": artifact_preview,
            "error_detail": error_detail,
        }

    def inspect_many(self, kind: str, object_ids: list[str], *, limit: int = 25) -> dict[str, object]:
        normalized = self._normalize_inspect_kind(kind)
        members: list[dict[str, object]] = []
        failures: list[dict[str, str]] = []
        for object_id in object_ids:
            try:
                members.append(self.inspect_object(normalized, object_id, limit=limit))
            except ValueError as exc:
                failures.append({"id": object_id, "error": str(exc)})
        return {
            "ok": not failures,
            "kind": "group",
            "group_kind": normalized,
            "count": len(members),
            "members": members,
            "failures": failures,
        }

    def _normalize_inspect_kind(self, kind: str) -> str:
        value = str(kind or "").strip().lower().replace("-", "_")
        aliases = {
            "tasks": "task",
            "task_run": "run",
            "task_runs": "run",
            "taskrun": "run",
            "runs": "run",
            "agent_trace": "trace",
            "agent_traces": "trace",
            "traces": "trace",
            "events": "event",
            "evidences": "evidence",
            "artifacts": "artifact",
            "findings": "finding",
            "interests": "interest",
            "checkpoints": "checkpoint",
            "notifications": "notification",
            "external_sync": "sync_job",
            "external_sync_job": "sync_job",
            "external_sync_jobs": "sync_job",
            "sync": "sync_job",
            "sync_jobs": "sync_job",
            "handoffs": "handoff",
            "notes": "note",
            "memory_entry": "memory",
            "memory_entries": "memory",
            "document_chunk": "chunk",
            "document_chunks": "chunk",
            "rag_chunk": "chunk",
        }
        normalized = aliases.get(value, value)
        allowed = {
            "task",
            "run",
            "trace",
            "event",
            "evidence",
            "artifact",
            "finding",
            "interest",
            "checkpoint",
            "notification",
            "sync_job",
            "handoff",
            "note",
            "memory",
            "chunk",
            "target",
        }
        if normalized not in allowed:
            raise ValueError(f"unsupported inspect kind: {kind}")
        return normalized

    def _lookup_inspect_record(self, kind: str, object_id: str) -> object | None:
        if kind == "task":
            return self.store.get_task(object_id)
        if kind == "run":
            return self.store.get_task_run(object_id)
        if kind == "trace":
            return self.store.get_trace(object_id)
        if kind == "event":
            return self.store.get_event(object_id)
        if kind == "evidence":
            return self.store.get_evidence(object_id)
        if kind == "artifact":
            return self.store.get_artifact(object_id)
        if kind == "finding":
            return self.store.get_finding(object_id)
        if kind == "interest":
            return self.store.get_interest(object_id)
        if kind == "checkpoint":
            return self.store.get_checkpoint(object_id)
        if kind == "notification":
            return self.store.get_notification(object_id)
        if kind == "sync_job":
            return self.store.get_external_sync_job(object_id)
        if kind == "handoff":
            return self.store.get_handoff(object_id)
        if kind == "note":
            return self.store.get_note(object_id)
        if kind == "memory":
            return self.store.get_memory_entry(object_id)
        if kind == "chunk":
            return self.store.get_document_chunk(object_id)
        if kind == "target":
            return self.store.get_target(object_id)
        return None

    def _inspect_payload(self, record: object) -> dict[str, object]:
        if hasattr(record, "as_payload"):
            payload = record.as_payload()
            return payload if isinstance(payload, dict) else {"value": payload}
        if isinstance(record, dict):
            return json_ready(record)
        return {"value": str(record)}

    def _inspect_title(self, kind: str, payload: dict[str, object]) -> str:
        title = payload.get("title") or payload.get("summary") or payload.get("trace_summary") or payload.get("path")
        if title:
            return f"{kind}: {title}"
        return f"{kind}: {payload.get('id') or 'record'}"

    def _inspect_related(self, kind: str, payload: dict[str, object], *, limit: int) -> dict[str, object]:
        related: dict[str, object] = {}
        task_id = str(payload.get("task_id") or "")
        target_id = str(payload.get("target_id") or "")
        run_id = str(payload.get("run_id") or "")
        if kind == "task":
            task_id = str(payload.get("id") or "")
        elif kind == "run":
            task_id = str(payload.get("task_id") or "")
            run_id = str(payload.get("id") or run_id)
        if kind == "target":
            target_id = str(payload.get("id") or "")

        task = self.store.get_task(task_id) if task_id else None
        if task is not None:
            related["task"] = task.as_payload()
            target_id = target_id or str(task.target_id or "")
        target = self.store.get_target(target_id) if target_id else None
        if target is not None:
            related["target"] = target.as_payload()

        if task_id:
            runs = self.store.list_task_runs(task_id=task_id, limit=limit)
            run_ids = {run.id for run in runs}
            if run_id:
                run_ids.add(run_id)
            related["runs"] = [item.as_payload() for item in runs]
            related["traces"] = [item.as_payload() for item in self.store.list_traces(task_id=task_id, limit=limit)]
            related["handoffs"] = [item.as_payload() for item in self.store.list_handoffs(task_id=task_id, limit=limit)]
            related["artifacts"] = [item.as_payload() for item in self.store.list_artifacts(task_id=task_id, limit=limit)]
            related["checkpoints"] = [
                item.as_payload()
                for item in self.store.list_checkpoints(limit=limit * 5)
                if item.task_id == task_id or item.run_id in run_ids
            ][:limit]
            related["events"] = [
                item.as_payload()
                for item in self.store.list_events(limit=limit * 5)
                if item.task_id == task_id
            ][:limit]
            if target_id:
                related["evidence"] = [
                    item.as_payload()
                    for item in self.store.list_evidence(target_id=target_id, limit=limit * 5)
                    if item.task_id == task_id
                ][:limit]
        return related

    def _inspect_artifact_preview(self, payload: dict[str, object], *, max_bytes: int = 65536) -> dict[str, object] | None:
        raw_path = str(payload.get("path") or "")
        if not raw_path:
            return None
        path = Path(raw_path)
        try:
            resolved = path.resolve()
        except OSError as exc:
            return {"available": False, "path": raw_path, "error": str(exc)}
        allowed_roots = (self.config.artifacts_dir.resolve(), self.config.checkpoints_dir.resolve())
        if not any(root == resolved or root in resolved.parents for root in allowed_roots):
            return {"available": False, "path": raw_path, "error": "preview blocked outside runtime artifact roots"}
        if not resolved.exists() or not resolved.is_file():
            return {"available": False, "path": str(resolved), "error": "file is not present on disk"}
        data = resolved.read_bytes()[: max_bytes + 1]
        truncated = len(data) > max_bytes
        if truncated:
            data = data[:max_bytes]
        text = data.decode("utf-8", errors="replace")
        return {
            "available": True,
            "path": str(resolved),
            "size_bytes": resolved.stat().st_size,
            "truncated": truncated,
            "text": self._redact_inspector_text(text),
        }

    def _redact_inspector_text(self, text: str) -> str:
        redacted = re.sub(
            r"(?i)(api[_-]?key|token|secret|password|passwd|webhook)([\"']?\s*[:=]\s*[\"']?)([^\"'\s,}]{4,})",
            lambda match: f"{match.group(1)}{match.group(2)}[redacted]",
            text,
        )
        return re.sub(
            r"(?i)(authorization\s*:\s*bearer\s+)([A-Za-z0-9._~+/=-]{8,})",
            lambda match: f"{match.group(1)}[redacted]",
            redacted,
        )

    def _inspect_error_detail(self, payload: dict[str, object], related: dict[str, object]) -> dict[str, object]:
        messages: list[dict[str, str]] = []
        tracebacks: list[dict[str, str]] = []

        def scan(item: object, source: str) -> None:
            if not isinstance(item, dict):
                return
            metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
            for key in ("error", "last_error", "failure_reason"):
                value = item.get(key) or metadata.get(key)
                if value:
                    messages.append({"source": source, "key": key, "message": str(value)})
            for key in ("traceback", "stack", "stack_trace"):
                value = metadata.get(key) or item.get(key)
                if value:
                    tracebacks.append({"source": source, "key": key, "traceback": str(value)})
            exception_type = metadata.get("exception_type") or item.get("exception_type")
            if exception_type:
                messages.append({"source": source, "key": "exception_type", "message": str(exception_type)})

        scan(payload, "record")
        for key, value in related.items():
            if isinstance(value, dict):
                scan(value, key)
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    scan(item, f"{key}[{index}]")

        seen_messages: set[tuple[str, str, str]] = set()
        deduped_messages = []
        for item in messages:
            marker = (item["source"], item["key"], item["message"])
            if marker in seen_messages:
                continue
            seen_messages.add(marker)
            deduped_messages.append(item)
        seen_tracebacks: set[str] = set()
        deduped_tracebacks = []
        for item in tracebacks:
            text = item["traceback"]
            if text in seen_tracebacks:
                continue
            seen_tracebacks.add(text)
            deduped_tracebacks.append(item)
        return {
            "available": bool(deduped_messages or deduped_tracebacks),
            "messages": deduped_messages,
            "tracebacks": deduped_tracebacks,
            "stack_available": bool(deduped_tracebacks),
            "stack_note": "" if deduped_tracebacks else "No traceback was recorded for this object.",
        }

    def health_payload(self) -> dict[str, object]:
        storage = self.storage_status_payload()
        try:
            operator_intent = self.active_operator_intent().id
        except Exception:  # noqa: BLE001 - health should surface degraded storage instead of failing
            operator_intent = "unknown"
        return {
            "status": "ok" if storage.get("ok") else "degraded",
            "runtime_dir": str(self.config.runtime_dir),
            "database": storage["database"],
            "storage": storage,
            "recovery": dict(self._last_recovery_status),
            "autonomy_mode": self.config.autonomy.mode.value,
            "operator_intent": operator_intent,
            "active_modules": self.modules.active_modules(),
            "targets": int(storage.get("counts", {}).get("targets", 0)) if isinstance(storage.get("counts"), dict) else 0,
            "skills": len(self.skills.list()),
            "findings_dir": str(self.config.findings_dir),
            "notion_exports_dir": str(self.config.notion_exports_dir),
        }

    def storage_status_payload(self) -> dict[str, object]:
        database = {
            "driver": "postgres",
            "url": self.config.redacted_database_url,
            "schema": self.config.database_schema or "default",
            "pgvector_required": True,
        }
        try:
            with self.store.connect() as connection:
                version_row = connection.execute("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1").fetchone()
                vector_row = connection.execute("SELECT extname FROM pg_extension WHERE extname = 'vector'").fetchone()
                counts: dict[str, int] = {}
                for table in ("targets", "scope_assets", "tasks", "task_runs", "evidence", "notes", "app_settings"):
                    row = connection.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()
                    counts[table] = int(row["count"]) if row else 0
            schema_version = int(version_row["version"]) if version_row else None
            return {
                "ok": schema_version == _SCHEMA_VERSION and bool(vector_row),
                "database": database,
                "schema_version": schema_version,
                "expected_schema_version": _SCHEMA_VERSION,
                "pgvector_installed": bool(vector_row),
                "counts": counts,
                "recovery": dict(self._last_recovery_status),
            }
        except Exception as exc:  # noqa: BLE001 - surfaced as operator diagnostics
            return {
                "ok": False,
                "database": database,
                "schema_version": None,
                "expected_schema_version": _SCHEMA_VERSION,
                "pgvector_installed": False,
                "counts": {},
                "error": str(exc),
                "recovery": dict(self._last_recovery_status),
            }

    def credentials_payload(self) -> dict[str, object]:
        return self.credentials.status()

    def skills_payload(self, *, include_body: bool = False) -> dict[str, object]:
        return self.skills.payload(include_body=include_body)

    def scope_profiles_payload(self) -> dict[str, object]:
        htb_environment = self._classify_environment(profile=ScopeProfile.HACK_THE_BOX.value)
        hackerone_environment = self._classify_environment(profile=ScopeProfile.HACKERONE.value)
        builtins = [
            {
                "id": ScopeProfile.HACK_THE_BOX.value,
                "label": "Hack The Box",
                "base_profile": ScopeProfile.HACK_THE_BOX.value,
                "description": "Lab/CTF profile. Requires verified environment proof before stronger lab defaults apply.",
                "default_intent": htb_environment.default_intent,
                "environment_classification": htb_environment.as_payload(),
                "builtin": True,
            },
            {
                "id": ScopeProfile.HACKERONE.value,
                "label": "HackerOne",
                "base_profile": ScopeProfile.HACKERONE.value,
                "description": "Bug bounty profile. Requires stricter scope and program-rule awareness.",
                "default_intent": hackerone_environment.default_intent,
                "environment_classification": hackerone_environment.as_payload(),
                "builtin": True,
            },
        ]
        custom = self.store.get_setting(self.SCOPE_PROFILE_PRESETS_SETTING, {})
        if not isinstance(custom, dict):
            custom = {}
        custom_profiles = []
        for profile_id, payload in sorted(custom.items()):
            if not isinstance(payload, dict):
                continue
            custom_profiles.append(
                {
                    "id": str(profile_id),
                    "label": str(payload.get("label", profile_id)),
                    "base_profile": str(payload.get("base_profile", ScopeProfile.HACKERONE.value)),
                    "description": str(payload.get("description", "")),
                    "builtin": False,
                }
            )
        return {"profiles": builtins + custom_profiles}

    def upsert_scope_profile(
        self,
        *,
        profile_id: str,
        label: str,
        base_profile: str,
        description: str = "",
    ) -> dict[str, object]:
        normalized_id = self._normalize_scope_profile_id(profile_id or label)
        if normalized_id in {ScopeProfile.HACK_THE_BOX.value, ScopeProfile.HACKERONE.value}:
            raise ValueError("built-in scope profiles cannot be overwritten")
        parsed_base = ScopeProfile(str(base_profile).strip())
        custom = self.store.get_setting(self.SCOPE_PROFILE_PRESETS_SETTING, {})
        if not isinstance(custom, dict):
            custom = {}
        custom[normalized_id] = {
            "label": label.strip() or normalized_id,
            "base_profile": parsed_base.value,
            "description": description.strip(),
        }
        self.store.set_setting(self.SCOPE_PROFILE_PRESETS_SETTING, custom)
        self.store.insert_event(
            EventRecord(
                type=EventType.SCOPE_UPDATED,
                summary=f"Scope profile preset saved: {normalized_id}",
                metadata={"profile_id": normalized_id, "base_profile": parsed_base.value},
            )
        )
        payload = self.scope_profiles_payload()
        payload["saved"] = normalized_id
        return payload

    def delete_scope_profile(self, profile_id: str) -> dict[str, object]:
        normalized_id = self._normalize_scope_profile_id(profile_id)
        if normalized_id in {ScopeProfile.HACK_THE_BOX.value, ScopeProfile.HACKERONE.value}:
            raise ValueError("built-in scope profiles cannot be deleted")
        custom = self.store.get_setting(self.SCOPE_PROFILE_PRESETS_SETTING, {})
        if not isinstance(custom, dict):
            custom = {}
        removed = normalized_id in custom
        custom.pop(normalized_id, None)
        self.store.set_setting(self.SCOPE_PROFILE_PRESETS_SETTING, custom)
        self.store.insert_event(
            EventRecord(
                type=EventType.SCOPE_UPDATED,
                summary=f"Scope profile preset deleted: {normalized_id}",
                metadata={"profile_id": normalized_id, "removed": removed},
            )
        )
        payload = self.scope_profiles_payload()
        payload["deleted"] = normalized_id
        payload["removed"] = removed
        return payload

    def resolve_scope_profile(self, profile_id: str) -> ScopeProfile:
        raw = str(profile_id).strip()
        try:
            return ScopeProfile(raw)
        except ValueError:
            pass
        custom = self.store.get_setting(self.SCOPE_PROFILE_PRESETS_SETTING, {})
        if isinstance(custom, dict):
            payload = custom.get(self._normalize_scope_profile_id(raw))
            if isinstance(payload, dict):
                return ScopeProfile(str(payload.get("base_profile", ScopeProfile.HACKERONE.value)))
        raise ValueError(f"unknown scope profile: {profile_id}")

    def findings_context_payload(self, *, target: str | None = None, include_guidance: bool = True) -> dict[str, object]:
        target_record = self._resolve_target_reference(target) if target else None
        if target_record is None and target:
            raise ValueError("target not found")
        if target_record is not None:
            return {
                "target": target_record.as_payload(),
                "workspace": self.findings_context.payload_for_target(
                    target_record,
                    include_guidance=include_guidance,
                ),
            }
        return {
            "findings_dir": str(self.config.findings_dir),
            "notion_exports_dir": str(self.config.notion_exports_dir),
            "targets": [
                {
                    "target": item.as_payload(),
                    "workspace": self.findings_context.payload_for_target(item, include_guidance=False),
                }
                for item in self.store.list_targets()
            ],
        }

    def update_target_guidance(self, target: str, body: str) -> dict[str, object]:
        target_record = self._resolve_target_reference(target)
        if target_record is None:
            raise ValueError("target not found")
        workspace = self.findings_context.write_guidance(target_record, body)
        self.store.insert_event(
            EventRecord(
                type=EventType.SCOPE_UPDATED,
                summary=f"Updated agent guidance for {target_record.handle}",
                target_id=target_record.id,
                metadata={"guidance_path": str(workspace.guidance_path)},
            )
        )
        self.sync_findings_context_exports()
        return self.findings_context_payload(target=target_record.id, include_guidance=True)

    def sync_findings_context_exports(self) -> dict[str, object]:
        synced = []
        for target in self.store.list_targets():
            workspace = self.findings_context.sync_target_export(
                target,
                evidence=self.store.list_evidence(target_id=target.id, limit=100),
                notes=self.store.list_notes(target_id=target.id, limit=100),
                interests=self.store.list_interests(target_id=target.id, limit=100),
                findings=self.store.list_findings(target_id=target.id, limit=100),
            )
            synced.append({"target": target.handle, "workspace": workspace.as_payload()})
        return {"synced": synced}

    def audit_findings_context_exports(self) -> dict[str, object]:
        return self.findings_context.audit_generated_exports()

    def caido_status_payload(self, *, check_health: bool = False) -> dict[str, object]:
        if not self.credentials.get("caido", "graphql_url") or not self.credentials.get("caido", "api_token"):
            return CaidoIntegrationService(self.credentials, self.event_bus).status(check_health=False)
        return self.caido.status(check_health=check_health)

    def caido_httpql_presets(self, target: str | None = None) -> dict[str, object]:
        target_record = self._resolve_target_reference(target) if target else None
        targets = [target_record] if target_record else self.store.list_targets()
        target_rows = []
        presets = []
        for item in targets:
            if item is None:
                continue
            terms = self._caido_scope_terms(item)
            httpql = self.caido.build_target_httpql(terms)
            target_rows.append(
                {
                    "id": item.id,
                    "handle": item.handle,
                    "display_name": item.display_name,
                    "in_scope": item.in_scope,
                    "httpql": httpql,
                    "terms": terms,
                }
            )
        presets.extend(
            [
                {"id": "errors", "label": "Error responses", "httpql": "resp.code.gte:400"},
                {"id": "auth", "label": "Auth paths", "httpql": 'req.path.cont:"login" OR req.path.cont:"admin"'},
                {
                    "id": "tokens",
                    "label": "Token hints",
                    "httpql": 'resp.raw.cont:"api_key" OR resp.raw.cont:"secret" OR resp.raw.cont:"token"',
                },
            ]
        )
        return {"targets": target_rows, "presets": presets}

    def caido_search_requests(
        self,
        *,
        target: str | None = None,
        httpql: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, object]:
        target_record = self._resolve_target_reference(target) if target else self._resolve_target_reference(None)
        if target and target_record is None:
            raise ValueError("target not found")
        effective_httpql = (httpql or "").strip()
        if not effective_httpql:
            if target_record is not None:
                effective_httpql = self.caido.build_target_httpql(self._caido_scope_terms(target_record))
            else:
                terms: list[str] = []
                for item in self.store.list_targets():
                    terms.extend(self._caido_scope_terms(item))
                effective_httpql = self.caido.build_target_httpql(terms)
        result = self.caido.search_requests(effective_httpql, limit=limit, offset=offset)
        result["target"] = target_record.as_payload() if target_record else None
        result["presets"] = self.caido_httpql_presets()
        return result

    def caido_request_detail(self, request_id: str) -> dict[str, object]:
        return self.caido.request_detail(request_id)

    def caido_import_requests(
        self,
        *,
        target: str,
        request_ids: list[str],
        httpql: str = "",
    ) -> dict[str, object]:
        target_record = self._resolve_target_reference(target)
        if target_record is None:
            raise ValueError("target not found")
        if not target_record.in_scope:
            raise ValueError("target is not in scope")
        selected_ids = [str(item).strip() for item in request_ids if str(item).strip()]
        if not selected_ids:
            raise ValueError("request_ids is required")
        imported = []
        errors = []
        for request_id in selected_ids[:50]:
            detail = self.caido.request_detail(request_id)
            if not detail.get("ok"):
                errors.append({"id": request_id, "error": str(detail.get("error") or "detail fetch failed")})
                continue
            request_payload = detail.get("request") if isinstance(detail.get("request"), dict) else {}
            host = str(request_payload.get("host") or "")
            if not self._caido_host_in_scope(target_record, host):
                errors.append({"id": request_id, "error": f"host is not in target scope: {host}"})
                continue
            artifact = self._write_caido_capture_artifact(target_record, request_payload, httpql=httpql)
            self.store.insert_artifact(artifact)
            method = str(request_payload.get("method") or "HTTP").upper()
            path = str(request_payload.get("path") or "/")
            status = int(request_payload.get("status") or 0)
            evidence_metadata = {
                "kind": ArtifactKind.CAIDO_CAPTURE.value,
                "caido_request_id": request_id,
                "httpql": httpql,
                "method": method,
                "host": host,
                "path": path,
                "status_code": status,
                "request_sha256": request_payload.get("request_sha256") or "",
                "response_sha256": request_payload.get("response_sha256") or "",
                "request_snippet": request_payload.get("request_snippet") or "",
                "response_snippet": request_payload.get("response_snippet") or "",
                "request_truncated": bool(request_payload.get("request_truncated")),
                "response_truncated": bool(request_payload.get("response_truncated")),
                "raw_bodies_stored": False,
                "artifact_id": artifact.id,
            }
            if target_record.metadata.get("active_ip_generation") is not None:
                evidence_metadata["active_ip_generation"] = target_record.metadata["active_ip_generation"]
            if target_record.metadata.get("active_ip"):
                evidence_metadata["active_ip"] = target_record.metadata["active_ip"]
            evidence = EvidenceRecord(
                target_id=target_record.id,
                type=EvidenceType.HTTP_REPLAY,
                title=f"Caido capture: {method} {path}",
                summary=f"Imported Caido request {request_id}: {method} {host}{path} returned HTTP {status or 'unknown'}.",
                source_ref=f"caido://request/{request_id}",
                verification_status=VerificationStatus.PARTIAL,
                confidence=0.75,
                freshness=0.85,
                artifact_path=artifact.path,
                metadata=evidence_metadata,
            )
            self.store.insert_evidence(evidence)
            imported.append({"request_id": request_id, "evidence": evidence.as_payload(), "artifact": artifact.as_payload()})
        if imported:
            self.store.insert_event(
                EventRecord(
                    type=EventType.CAIDO_IMPORT,
                    summary=f"Imported {len(imported)} Caido capture(s)",
                    target_id=target_record.id,
                    metadata={
                        "request_ids": [item["request_id"] for item in imported],
                        "httpql": httpql,
                        "artifact_ids": [item["artifact"]["id"] for item in imported],
                        "evidence_ids": [item["evidence"]["id"] for item in imported],
                        "raw_bodies_stored": False,
                    },
                )
            )
        return {
            "target": target_record.as_payload(),
            "imported": imported,
            "errors": errors,
            "records": self.records_payload(limit=50, target_id=target_record.id),
        }

    def caido_replay_draft(self, *, target: str, raw_request: str) -> dict[str, object]:
        target_record = self._resolve_target_reference(target)
        if target_record is None:
            raise ValueError("target not found")
        if not target_record.in_scope:
            raise ValueError("target is not in scope")
        parsed = self.caido.parse_raw_request(raw_request)
        if not self._caido_host_in_scope(target_record, parsed.host):
            raise ValueError(f"raw request host is not in target scope: {parsed.host}")
        draft = self.caido.create_replay_draft(raw_request)
        draft["target"] = target_record.as_payload()
        return draft

    def caido_replay_send(
        self,
        *,
        target: str,
        raw_request: str,
        confirmation: str | None = None,
        session_id: str | None = None,
    ) -> dict[str, object]:
        target_record = self._resolve_target_reference(target)
        if target_record is None:
            raise ValueError("target not found")
        if not target_record.in_scope:
            raise ValueError("target is not in scope")
        parsed = self.caido.parse_raw_request(raw_request)
        if not self._caido_host_in_scope(target_record, parsed.host):
            raise ValueError(f"raw request host is not in target scope: {parsed.host}")
        if str(confirmation or "").strip() != parsed.raw_sha256:
            raise ValueError("same-session replay confirmation is required")
        selected_session_id = str(session_id or "").strip()
        draft: dict[str, object] | None = None
        if not selected_session_id:
            draft = self.caido.create_replay_draft(raw_request)
            if not draft.get("ok"):
                return {"ok": False, "target": target_record.as_payload(), "parsed": parsed.as_payload(), "error": draft.get("error")}
            session = draft.get("session") if isinstance(draft.get("session"), dict) else {}
            selected_session_id = str(session.get("id") or "")
        if not selected_session_id:
            raise ValueError("caido replay session_id is required")
        result = self.caido.send_replay(raw_request, session_id=selected_session_id)
        result["target"] = target_record.as_payload()
        result["session_id"] = selected_session_id
        if draft is not None:
            result["draft"] = draft.get("session")
        if result.get("ok"):
            task = result.get("task") if isinstance(result.get("task"), dict) else {}
            self.store.insert_event(
                EventRecord(
                    type=EventType.CAIDO_REPLAY_SENT,
                    summary=f"Caido Replay sent one request to {parsed.host}",
                    target_id=target_record.id,
                    metadata={
                        "raw_sha256": parsed.raw_sha256,
                        "method": parsed.method,
                        "host": parsed.host,
                        "port": parsed.port,
                        "path": parsed.path,
                        "is_tls": parsed.is_tls,
                        "caido_session_id": selected_session_id,
                        "caido_task_id": task.get("id") or "",
                        "caido_replay_entry_id": task.get("replay_entry_id") or "",
                        "raw_persisted": False,
                        "same_session_confirmation": True,
                    },
                )
            )
        return result

    def models_payload(self) -> dict[str, object]:
        wrapper_mode = self.model_wrapper_mode_payload()
        if wrapper_mode["use_only_wrapper"]:
            installed = OllamaModelListResult(
                ok=False,
                models=[],
                error="Ollama model listing skipped because use-only-wrapper mode is active.",
            )
        else:
            installed = self.ollama.list_models()
        selected = self._current_model_roles()
        processors = self._current_model_role_processors()
        role_metrics = self.store.latest_model_eval_role_metrics()
        available_models = list(installed.models)
        for model in selected.values():
            if model and model not in available_models:
                available_models.append(model)
        available_models = sorted(set(available_models))
        roles = []
        for role, config in self.MODEL_ROLE_CONFIG.items():
            roles.append(
                {
                    "role": role,
                    "label": config["label"],
                    "description": config["description"],
                    "processor": processors[role],
                    "default_model": config["default_model"],
                    "selected_model": selected[role],
                    "num_gpu": self._processor_num_gpu(processors[role]),
                    "default_processor": config["processor"],
                    "processor_options": ["gpu", "cpu"],
                    "metrics": role_metrics.get(role),
                    "wrapper_personality": WRAPPER_ROLE_PERSONALITY_PROMPTS.get(role, ""),
                }
            )
        return {
            "ollama": {
                "ok": installed.ok,
                "base_url": self.ollama.base_url,
                "error": installed.error,
                "disabled_by_wrapper_mode": bool(wrapper_mode["use_only_wrapper"]),
            },
            "wrapper_mode": wrapper_mode,
            "available_models": available_models,
            "roles": roles,
            "role_metrics": role_metrics,
            "eval_history": self.store.list_model_eval_history(limit=10),
        }

    def update_model_roles(
        self,
        selections: dict[str, str],
        processors: dict[str, str] | None = None,
        wrapper_mode: dict[str, object] | None = None,
    ) -> dict[str, object]:
        current = self._current_model_roles()
        current_processors = self._current_model_role_processors()
        current_wrapper_mode = self._current_model_wrapper_mode()
        if wrapper_mode is not None:
            current_wrapper_mode = self._normalize_model_wrapper_mode(wrapper_mode, current=current_wrapper_mode)
        installed = (
            OllamaModelListResult(ok=False, models=[], error="validation skipped in use-only-wrapper mode")
            if current_wrapper_mode.get("use_only_wrapper")
            else self.ollama.list_models()
        )
        installed_models = set(installed.models)
        changed: dict[str, str] = {}
        for role, model in selections.items():
            if role not in self.MODEL_ROLE_CONFIG:
                raise ValueError(f"unsupported model role: {role}")
            selected = str(model).strip()
            if not selected:
                continue
            if not current_wrapper_mode.get("use_only_wrapper") and installed.ok and selected not in installed_models:
                raise ValueError(f"model is not installed in Ollama: {selected}")
            current[role] = selected
            changed[role] = selected
        processor_changes: dict[str, str] = {}
        for role, processor in (processors or {}).items():
            if role not in self.MODEL_ROLE_CONFIG:
                raise ValueError(f"unsupported model role: {role}")
            selected_processor = str(processor).strip().lower()
            if selected_processor not in {"gpu", "cpu"}:
                raise ValueError(f"unsupported processor for {role}: {processor}")
            current_processors[role] = selected_processor
            processor_changes[role] = selected_processor
        self.store.set_setting("model_roles", current)
        self.store.set_setting("model_role_processors", current_processors)
        self.store.set_setting(self.MODEL_WRAPPER_MODE_SETTING, current_wrapper_mode)
        self._apply_model_roles(current)
        if current_wrapper_mode.get("use_only_wrapper"):
            self._ensure_agent_chat_api_available()
        self.store.insert_event(
            EventRecord(
                type=EventType.BOOTSTRAP,
                summary="Model role mapping updated",
                metadata={
                    "changed": changed,
                    "processor_changes": processor_changes,
                    "wrapper_mode": current_wrapper_mode,
                },
            )
        )
        return self.models_payload()

    def evaluate_models(
        self,
        *,
        models: list[str] | None = None,
        limit: int | None = None,
        include_outputs: bool = False,
        processor: str = "cpu",
        providers: list[str] | None = None,
        exhaustive: bool = False,
        max_context: int = 32768,
        context_sizes: list[int] | None = None,
        temperatures: list[float] | None = None,
        judge_model: str | None = None,
        csv_path: str | Path | None = None,
        json_out: str | Path | None = None,
        lmstudio_profile_path: str | Path | None = None,
        use_lmstudio_profile: bool = True,
        max_model_runtime_seconds: int = 1800,
    ) -> dict[str, object]:
        selected_processor = str(processor).strip().lower()
        if selected_processor not in {"cpu", "gpu"}:
            raise ValueError("processor must be cpu or gpu")
        provider_names = providers or ["ollama"]
        normalized_providers = []
        for item in provider_names:
            for provider in str(item).split(","):
                clean = provider.strip().lower()
                if clean in {"ollama", "lmstudio"} and clean not in normalized_providers:
                    normalized_providers.append(clean)
        normalized_providers = normalized_providers or ["ollama"]
        lmstudio = LMStudioClient() if "lmstudio" in normalized_providers else None
        lmstudio_profile = (
            self._load_lmstudio_profile(lmstudio_profile_path)
            if lmstudio is not None and use_lmstudio_profile
            else {}
        )
        evaluator = ModelEvaluationService(
            self.ollama,
            lmstudio=lmstudio,
            host_metrics_sampler=lambda: self.system_metrics_payload(force_refresh=True),
            lmstudio_profile=lmstudio_profile,
        )
        summary = evaluator.evaluate(
            models=models,
            limit=limit,
            include_outputs=include_outputs,
            num_gpu=self._processor_num_gpu(selected_processor),
            providers=normalized_providers,
            exhaustive=exhaustive,
            max_context=max_context,
            context_sizes=context_sizes,
            temperatures=temperatures,
            judge_model=judge_model,
            max_model_runtime_seconds=max_model_runtime_seconds,
        )
        artifacts = evaluator.write_artifacts(
            summary,
            output_dir=self.config.artifacts_dir / "model_eval",
            csv_path=Path(csv_path) if csv_path else None,
            json_path=Path(json_out) if json_out else None,
        )
        payload = summary.as_payload()
        run_id = self.store.insert_model_eval_ledger(
            summary=payload,
            artifacts=artifacts,
            metadata={
                "processor": selected_processor,
                "providers": normalized_providers,
                "max_context": max_context,
                "context_sizes": context_sizes or [],
                "exhaustive": exhaustive,
                "temperatures": temperatures or [0.0, 0.1],
                "judge_model": judge_model or "",
                "max_model_runtime_seconds": max_model_runtime_seconds,
                "lmstudio_profile_path": str(lmstudio_profile_path or self._lmstudio_profile_path())
                if lmstudio_profile
                else "",
                "lmstudio_profile_applied": bool(lmstudio_profile),
            },
        )
        payload["ledger_run_id"] = run_id
        self.store.insert_event(
            EventRecord(
                type=EventType.BOOTSTRAP,
                summary="Model evaluation completed",
                metadata={
                    "models": payload["models"],
                    "recommendations": payload["recommendations"],
                    "role_suggestions": payload.get("role_suggestions", []),
                    "model_identification": payload.get("model_identification", {}),
                    "processor": selected_processor,
                    "providers": normalized_providers,
                    "artifacts": artifacts,
                    "lmstudio_profile_applied": bool(lmstudio_profile),
                    "max_model_runtime_seconds": max_model_runtime_seconds,
                },
            )
        )
        return payload

    def tune_lmstudio_models(
        self,
        *,
        models: list[str] | None = None,
        context_length: int = 1024,
        max_tokens: int = 128,
        temperature: float = 0.0,
        cpu_reserve_mb: int = 4096,
        vram_soft_reserve_mb: int = 128,
        timeout_seconds: int = 120,
        profile_out: str | Path | None = None,
        json_out: str | Path | None = None,
    ) -> dict[str, object]:
        client = LMStudioClient()
        tuner = LMStudioPerformanceTuner(
            client,
            host_metrics_sampler=lambda: self.system_metrics_payload(force_refresh=True),
        )
        payload = tuner.tune(
            models=models,
            context_length=context_length,
            max_tokens=max_tokens,
            temperature=temperature,
            cpu_reserve_mb=cpu_reserve_mb,
            vram_soft_reserve_mb=vram_soft_reserve_mb,
            timeout_seconds=timeout_seconds,
        )
        stamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
        artifacts = tuner.write_artifacts(
            payload,
            output_dir=self.config.artifacts_dir / "model_eval" / f"lmstudio_tuning_{stamp}",
            profile_path=Path(profile_out) if profile_out else self._lmstudio_profile_path(),
            json_path=Path(json_out) if json_out else None,
        )
        payload["artifacts"] = artifacts
        self.store.insert_event(
            EventRecord(
                type=EventType.BOOTSTRAP,
                summary="LM Studio performance tuning completed",
                metadata={
                    "status": payload.get("status"),
                    "models": sorted(str(key) for key in payload.get("models", {}).keys())
                    if isinstance(payload.get("models"), dict)
                    else [],
                    "artifacts": artifacts,
                    "settings": payload.get("settings", {}),
                },
            )
        )
        return payload

    def _lmstudio_profile_path(self) -> Path:
        return self.config.runtime_dir / "model_eval" / "lmstudio_performance_profile.json"

    def _load_lmstudio_profile(self, profile_path: str | Path | None = None) -> dict[str, object]:
        target = Path(profile_path) if profile_path else self._lmstudio_profile_path()
        try:
            if not target.exists():
                return {}
            with target.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return {}
        return payload if isinstance(payload, dict) else {}

    def self_test_payload(self) -> dict[str, object]:
        checks = [
            self._self_test_database(),
            self._self_test_runtime_dirs(),
            self._self_test_scope(),
            self._self_test_metrics(),
            self._self_test_model_listing(),
            self._self_test_credentials_redacted(),
            self._self_test_core_payloads(),
            self._self_test_execution_repair(),
        ]
        failed = [item for item in checks if item["status"] == "fail"]
        warnings = [item for item in checks if item["status"] == "warn"]
        status = "fail" if failed else "warn" if warnings else "pass"
        return {
            "status": status,
            "generated_at": utc_now().isoformat(),
            "checks": checks,
            "summary": {
                "pass": sum(1 for item in checks if item["status"] == "pass"),
                "warn": len(warnings),
                "fail": len(failed),
            },
        }

    def warm_model_routes(self, *, keep_alive: str = "8h") -> dict[str, object]:
        if self._use_only_wrapper_mode():
            result = {
                "keep_alive": keep_alive,
                "results": [],
                "skipped": True,
                "reason": "use-only-wrapper mode is active; Ollama warmup is bypassed",
                "wrapper_mode": self.model_wrapper_mode_payload(),
            }
            self.store.insert_event(
                EventRecord(
                    type=EventType.BOOTSTRAP,
                    summary="Model warmup skipped for use-only-wrapper mode",
                    metadata=result,
                )
            )
            return result
        route_models = {
            "local_fast": ("local_fast", self.config.topology.local_fast),
            "local_compact": ("local_compact", self.config.topology.local_compact),
            "local_deep": ("local_deep", self.config.topology.local_deep),
            "local_code_cold": ("local_code", self.config.topology.local_code),
        }
        results = []
        for route, (role, model) in route_models.items():
            num_gpu = self._role_num_gpu(role)
            preload = self.ollama.preload(model=model, keep_alive=keep_alive, num_gpu=num_gpu)
            results.append(
                {
                    "route": route,
                    "model": preload.model,
                    "num_gpu": num_gpu,
                    "processor_hint": "cpu" if num_gpu == 0 else "default",
                    "ok": preload.ok,
                    "error": preload.error,
                    "elapsed_seconds": preload.elapsed_seconds,
                }
            )
        self.store.insert_event(
            EventRecord(
                type=EventType.BOOTSTRAP,
                summary="Model warmup completed",
                metadata={"keep_alive": keep_alive, "results": results},
            )
        )
        return {"keep_alive": keep_alive, "results": results}

    def clear_model_routes(self) -> dict[str, object]:
        if self._use_only_wrapper_mode():
            result = {
                "results": [],
                "skipped": True,
                "reason": "use-only-wrapper mode is active; Ollama unload is bypassed",
                "wrapper_mode": self.model_wrapper_mode_payload(),
            }
            self.store.insert_event(
                EventRecord(
                    type=EventType.BOOTSTRAP,
                    summary="Model clear/unload skipped for use-only-wrapper mode",
                    metadata=result,
                )
            )
            return result
        route_models = {
            "local_fast": ("local_fast", self.config.topology.local_fast),
            "local_compact": ("local_compact", self.config.topology.local_compact),
            "local_deep": ("local_deep", self.config.topology.local_deep),
            "local_code_cold": ("local_code", self.config.topology.local_code),
        }
        seen: set[tuple[str, int | None]] = set()
        results = []
        for route, (role, model) in route_models.items():
            num_gpu = self._role_num_gpu(role)
            key = (model, num_gpu)
            if key in seen:
                continue
            seen.add(key)
            unload = self.ollama.unload(model=model, num_gpu=num_gpu)
            results.append(
                {
                    "route": route,
                    "model": unload.model,
                    "num_gpu": num_gpu,
                    "processor_hint": "cpu" if num_gpu == 0 else "default",
                    "ok": unload.ok,
                    "error": unload.error,
                    "elapsed_seconds": unload.elapsed_seconds,
                }
            )
        self.store.insert_event(
            EventRecord(
                type=EventType.BOOTSTRAP,
                summary="Model clear/unload requested",
                metadata={"results": results},
            )
        )
        return {"results": results}

    def stop_active_work(self) -> dict[str, object]:
        self.store.set_setting(self.EXECUTION_MODE_SETTING, "tick")
        paused = self.store.pause_active_sessions()
        self.store.insert_event(
            EventRecord(
                type=EventType.BOOTSTRAP,
                summary="Operator requested stop for active GUI work",
                metadata={"paused_sessions": paused, "execution_mode": "tick"},
            )
        )
        return {"paused_sessions": paused, "execution_mode": self.execution_mode_payload()}

    def model_wrapper_mode_payload(self) -> dict[str, object]:
        mode = self._current_model_wrapper_mode()
        provider = str(mode.get("provider") or self.config.agent_chat_provider or "claude")
        model = mode.get("model")
        effort = mode.get("effort")
        preset = str(mode.get("preset") or self.DEFAULT_WRAPPER_PRESET)
        return {
            "use_only_wrapper": bool(mode.get("use_only_wrapper")),
            "local_chat_wrapper": "agent_chat_api",
            "preset": preset,
            "preset_label": self._wrapper_preset_label(preset),
            "provider": provider,
            "model": str(model) if model else None,
            "effort": str(effort) if effort else None,
            "model_label": self._wrapper_model_label(),
            "display_label": self._wrapper_display_label(mode),
            "presets": self._wrapper_preset_options(),
            "api": self.agent_chat_status_payload(timeout_seconds=0.5),
            "safe_guard": self.config.agent_chat_safe_guard,
            "personality_prompts": dict(WRAPPER_ROLE_PERSONALITY_PROMPTS),
            "detail": (
                "All runtime AI generation uses agent_chat_api role wrappers; direct Ollama generate, "
                "warmup, unload, and startup topology validation are bypassed."
                if mode.get("use_only_wrapper")
                else "Runtime AI generation uses local model routes unless an explicit premium wrapper task is created."
            ),
        }

    def _current_model_wrapper_mode(self) -> dict[str, object]:
        stored = self.store.get_setting(self.MODEL_WRAPPER_MODE_SETTING, {})
        default = self._default_model_wrapper_mode()
        if isinstance(stored, dict):
            mode = self._normalize_model_wrapper_mode(stored, current=default)
            if self.config.use_only_wrapper_mode:
                mode["use_only_wrapper"] = True
            return mode
        return default

    def _default_model_wrapper_mode(self) -> dict[str, object]:
        preset = dict(self.WRAPPER_PRESETS[self.DEFAULT_WRAPPER_PRESET])
        mode: dict[str, object] = {
            "use_only_wrapper": bool(self.config.use_only_wrapper_mode),
            "preset": self.DEFAULT_WRAPPER_PRESET,
            "provider": preset["provider"],
            "model": preset["model"],
            "effort": preset["effort"],
        }
        configured_provider = str(self.config.agent_chat_provider or "").strip().lower()
        if configured_provider in {"claude", "codex"}:
            mode["provider"] = configured_provider
            if configured_provider == "codex" and not self.config.agent_chat_model:
                mode["model"] = self.WRAPPER_PRESETS["codex_gpt55_high"]["model"]
                mode["effort"] = self.WRAPPER_PRESETS["codex_gpt55_high"]["effort"]
        if self.config.agent_chat_model:
            mode["model"] = self.config.agent_chat_model
        mode["preset"] = self._wrapper_preset_for(
            str(mode["provider"]),
            str(mode["model"]),
            str(mode["effort"]) if mode.get("effort") else None,
        )
        return mode

    def _normalize_model_wrapper_mode(
        self,
        payload: dict[str, object],
        *,
        current: dict[str, object] | None = None,
    ) -> dict[str, object]:
        normalized = dict(
            current
            or self._default_model_wrapper_mode()
        )
        if "use_only_wrapper" in payload:
            normalized["use_only_wrapper"] = self._coerce_bool(payload.get("use_only_wrapper"))
        preset_id = str(payload.get("preset") or "").strip().lower()
        if preset_id:
            if preset_id not in self.WRAPPER_PRESETS:
                raise ValueError(f"unsupported wrapper preset: {preset_id}")
            preset = self.WRAPPER_PRESETS[preset_id]
            normalized["preset"] = preset_id
            normalized["provider"] = preset["provider"]
            normalized["model"] = preset["model"]
            normalized["effort"] = preset["effort"]
        if "provider" in payload:
            provider = str(payload.get("provider") or "").strip().lower()
            if provider:
                if provider not in {"claude", "codex"}:
                    raise ValueError(f"unsupported wrapper provider: {provider}")
                normalized["provider"] = provider
                if "model" not in payload and not preset_id:
                    provider_preset = "codex_gpt55_high" if provider == "codex" else "claude_sonnet"
                    preset = self.WRAPPER_PRESETS[provider_preset]
                    normalized["preset"] = provider_preset
                    normalized["model"] = preset["model"]
                    normalized["effort"] = preset["effort"]
        if "model" in payload:
            raw_model = payload.get("model")
            model = str(raw_model).strip() if raw_model is not None else ""
            normalized["model"] = model or None
        if "effort" in payload:
            raw_effort = payload.get("effort")
            effort = str(raw_effort).strip().lower() if raw_effort is not None else ""
            if effort and effort not in self.WRAPPER_EFFORTS:
                raise ValueError(f"unsupported wrapper effort: {effort}")
            normalized["effort"] = effort or None
        provider = str(normalized.get("provider") or "").strip().lower()
        model = str(normalized.get("model") or "").strip()
        effort = str(normalized.get("effort") or "").strip().lower() or None
        if not model:
            provider_preset = "codex_gpt55_high" if provider == "codex" else "claude_sonnet"
            preset = self.WRAPPER_PRESETS[provider_preset]
            model = str(preset["model"])
            effort = str(preset["effort"]) if preset.get("effort") else None
        elif provider == "codex" and model == self.WRAPPER_PRESETS["codex_gpt55_high"]["model"] and not effort:
            effort = str(self.WRAPPER_PRESETS["codex_gpt55_high"]["effort"])
        inferred_preset = self._wrapper_preset_for(provider, model, effort)
        if not inferred_preset:
            raise ValueError(f"unsupported wrapper model for provider {provider}: {model or 'provider-default'}")
        normalized["preset"] = inferred_preset
        normalized["provider"] = provider
        normalized["model"] = model
        normalized["effort"] = effort
        return normalized

    def _wrapper_preset_for(self, provider: str, model: str, effort: str | None) -> str | None:
        for preset_id, preset in self.WRAPPER_PRESETS.items():
            if (
                provider == preset["provider"]
                and model == preset["model"]
                and (effort or None) == preset["effort"]
            ):
                return preset_id
        return None

    def _wrapper_preset_label(self, preset_id: str) -> str:
        preset = self.WRAPPER_PRESETS.get(preset_id)
        return str(preset.get("label")) if preset else preset_id

    def _wrapper_preset_options(self) -> list[dict[str, object]]:
        return [
            {
                "id": preset_id,
                "label": str(preset["label"]),
                "provider": str(preset["provider"]),
                "model": str(preset["model"]),
                "effort": str(preset["effort"]) if preset.get("effort") else None,
            }
            for preset_id, preset in self.WRAPPER_PRESETS.items()
        ]

    def _wrapper_display_label(self, mode: dict[str, object] | None = None) -> str:
        selected = mode or self._current_model_wrapper_mode()
        preset_id = str(selected.get("preset") or "")
        return self._wrapper_preset_label(preset_id) if preset_id else self._wrapper_model_label(selected)

    def _coerce_bool(self, value: object) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, int | float):
            return bool(value)
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on", "enabled"}
        return bool(value)

    def _use_only_wrapper_mode(self) -> bool:
        return bool(self._current_model_wrapper_mode().get("use_only_wrapper"))

    def _wrapper_model_label(self, mode: dict[str, object] | None = None) -> str:
        mode = mode or self._current_model_wrapper_mode()
        provider = str(mode.get("provider") or self.config.agent_chat_provider or "claude")
        model = mode.get("model") or self.config.agent_chat_model or "provider-default"
        effort = mode.get("effort")
        suffix = f":{effort}" if effort else ""
        return f"agent_chat_api:{provider}:{model}{suffix}"

    def agent_chat_status_payload(self, *, timeout_seconds: int | float = 1) -> dict[str, object]:
        base = {
            "ok": False,
            "base_url": self.config.agent_chat_base_url,
            "provider": self.config.agent_chat_provider,
            "model": self.config.agent_chat_model,
            "auto_start": self.config.agent_chat_auto_start,
        }
        try:
            health = self.agent_chat.health(timeout_seconds=timeout_seconds)
        except Exception as exc:  # noqa: BLE001 - surfaced as health/status, not a traceback
            return {**base, "error": str(exc)}
        return {
            **base,
            "ok": bool(health.get("ok", True)),
            "health": health,
            "workspace_root": str(health.get("workspace_root") or ""),
            "default_provider": str(health.get("default_provider") or ""),
        }

    def _ensure_agent_chat_api_available(self) -> dict[str, object]:
        if not isinstance(self.agent_chat, AgentChatClient):
            return {"ok": True, "injected_client": type(self.agent_chat).__name__}
        status = self.agent_chat_status_payload(timeout_seconds=0.5)
        if status.get("ok"):
            return status
        if not self.config.agent_chat_auto_start:
            return status
        started = self._start_local_agent_chat_api()
        status = self.agent_chat_status_payload(timeout_seconds=2)
        return {**status, "auto_start_attempt": started}

    def _start_local_agent_chat_api(self) -> dict[str, object]:
        parsed = urlparse.urlsplit(self.config.agent_chat_base_url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if parsed.scheme not in {"http", ""}:
            return {"started": False, "reason": "only local http agent_chat_api can be auto-started"}
        if host not in {"127.0.0.1", "localhost", "::1"}:
            return {"started": False, "reason": "agent_chat_api base_url is not local"}
        script = self.config.project_root / "agent_chat_api" / "app.py"
        if not script.exists():
            return {"started": False, "reason": f"agent_chat_api launcher not found: {script}"}
        process_dir = self.config.runtime_dir / "agent_chat_api"
        process_dir.mkdir(parents=True, exist_ok=True)
        log_path = process_dir / "agent_chat_api.log"
        env = os.environ.copy()
        env.setdefault("CHAT_API_HOST", host)
        env.setdefault("CHAT_API_PORT", str(port))
        env.setdefault("CHAT_API_WORKSPACE_ROOT", str(script.parent))
        env.setdefault("CHAT_API_SESSION_STORE", str(process_dir / "sessions.json"))
        env.setdefault("CHAT_API_AUDIT_LOG", str(process_dir / "provider-audit.jsonl"))
        if self.config.agent_chat_api_key:
            env.setdefault("CHAT_API_KEY", self.config.agent_chat_api_key)
        if self.config.agent_chat_provider:
            env.setdefault("CHAT_API_DEFAULT_PROVIDER", self.config.agent_chat_provider)
        command = [
            sys.executable or shutil.which("python3") or "python3",
            str(script),
            "--host",
            host,
            "--port",
            str(port),
            "--workspace-root",
            str(script.parent),
        ]
        try:
            with log_path.open("ab") as handle:
                process = subprocess.Popen(
                    command,
                    cwd=str(script.parent),
                    env=env,
                    stdout=handle,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
        except OSError as exc:
            return {"started": False, "reason": str(exc), "command": command}
        self.store.set_setting(
            self.AGENT_CHAT_PROCESS_SETTING,
            {
                "pid": process.pid,
                "base_url": self.config.agent_chat_base_url,
                "log_path": str(log_path),
                "started_at": utc_now().isoformat(),
            },
        )
        self.store.insert_event(
            EventRecord(
                type=EventType.BOOTSTRAP,
                summary="agent_chat_api auto-start requested",
                metadata={"pid": process.pid, "base_url": self.config.agent_chat_base_url, "log_path": str(log_path)},
            )
        )
        return {"started": True, "pid": process.pid, "log_path": str(log_path), "command": command}

    def _current_model_roles(self) -> dict[str, str]:
        stored = self.store.get_setting("model_roles", {})
        roles = {
            role: str(getattr(self.config.topology, str(config["topology_field"])))
            for role, config in self.MODEL_ROLE_CONFIG.items()
        }
        if isinstance(stored, dict):
            for role, model in stored.items():
                if role in roles and isinstance(model, str) and model.strip():
                    roles[role] = model.strip()
        return roles

    def _current_model_role_processors(self) -> dict[str, str]:
        stored = self.store.get_setting("model_role_processors", {})
        processors = {
            role: str(config["processor"])
            for role, config in self.MODEL_ROLE_CONFIG.items()
        }
        if isinstance(stored, dict):
            for role, processor in stored.items():
                if role in processors and isinstance(processor, str):
                    normalized = processor.strip().lower()
                    if normalized in {"gpu", "cpu"}:
                        processors[role] = normalized
        return processors

    def _role_num_gpu(self, role: str) -> int | None:
        return self._processor_num_gpu(self._current_model_role_processors().get(role, "gpu"))

    def _processor_num_gpu(self, processor: str) -> int | None:
        return 0 if processor == "cpu" else None

    def _ollama_timeout_seconds_for_processor(self, processor: str) -> int:
        tuning = self.runtime_tuning_payload()
        if processor == "cpu":
            return int(tuning["cpu_ai_timeout_seconds"])
        return int(tuning["gpu_ai_timeout_seconds"])

    def _worker_ai_generate(
        self,
        task: Task,
        system: str,
        prompt: str,
        temperature: float = 0.0,
    ) -> dict[str, object] | None:
        selection = self.router.select_route(task)
        route = task.provider_route or selection.route
        role = self._model_role_for_route(route) or "local_fast"
        prompt = self._with_worker_rag_context(task, prompt, role=role)
        if self._use_only_wrapper_mode():
            try:
                return self._wrapper_ai_generate(
                    role=role,
                    system=system,
                    prompt=prompt,
                    task=task,
                    temperature=temperature,
                    persist=False,
                )
            except Exception as exc:  # noqa: BLE001 - wrapper AI is opportunistic and must not stall autonomy
                self.store.insert_event(
                    EventRecord(
                        type=EventType.TASK_FAILED,
                        summary="Worker wrapper AI generation unavailable",
                        target_id=task.target_id,
                        task_id=task.id,
                        metadata={"error": str(exc), "model": self._wrapper_model_label(), "wrapper_mode": True},
                    )
                )
                return None
        if not self.ollama.is_reachable(timeout_seconds=1.5):
            return None
        model = task.provider_model or selection.model_name
        processor = self._current_model_role_processors().get(role or "", "gpu") if role else "gpu"
        num_gpu = self._role_num_gpu(role) if role else None
        try:
            response = self.ollama.generate(
                model=model,
                system=system,
                prompt=prompt,
                temperature=temperature,
                num_gpu=num_gpu,
                keep_alive="2h",
                timeout_seconds=self._ollama_timeout_seconds_for_processor(processor),
            )
        except Exception as exc:  # noqa: BLE001 - worker AI is opportunistic and must not stall autonomy
            self.store.insert_event(
                EventRecord(
                    type=EventType.TASK_FAILED,
                    summary="Worker AI generation unavailable",
                    target_id=task.target_id,
                    task_id=task.id,
                    metadata={"error": str(exc), "model": model},
                )
            )
            return None
        return {
            "model": response.model,
            "text": response.text,
            "elapsed_seconds": response.elapsed_seconds,
            "num_gpu": num_gpu,
            "processor": processor,
            "prompt_tokens": response.prompt_tokens,
            "completion_tokens": response.completion_tokens,
        }

    def _with_worker_rag_context(self, task: Task, prompt: str, *, role: str) -> str:
        query = " ".join(part for part in [task.title, task.summary, task.kind.value] if part)
        try:
            pack = self.build_rag_context_pack(
                query,
                purpose="worker_ai_review",
                role=role,
                task=task,
                limit=4,
            )
        except Exception:  # noqa: BLE001 - advisory RAG must not break AI review
            return prompt
        context = str(pack.get("prompt_context") or "").strip()
        if not context:
            return prompt
        return (
            f"{prompt}\n\n"
            "Role-aware RAG advisory pack:\n"
            f"{context}\n\n"
            "Use RAG only as cited source material. Do not treat it as target evidence, approval, or scope."
        )

    def _wrapper_ai_generate(
        self,
        *,
        role: str,
        system: str,
        prompt: str,
        task: Task | None = None,
        temperature: float = 0.0,
        persist: bool = False,
    ) -> dict[str, object]:
        mode = self._current_model_wrapper_mode()
        provider = str(mode.get("provider") or self.config.agent_chat_provider or "claude")
        selected_model = mode.get("model") or self.config.agent_chat_model
        selected_effort = mode.get("effort")
        status = self._ensure_agent_chat_api_available()
        if not status.get("ok"):
            raise RuntimeError(
                "wrapper-only mode is active but agent_chat_api is not reachable. "
                f"base_url={self.config.agent_chat_base_url}; error={status.get('error') or status.get('reason') or status}"
            )
        system_prompt = build_wrapper_system_prompt(role, system)
        response = self.agent_chat.chat(
            system_prompt=system_prompt,
            prompt=prompt,
            provider=provider,
            model=str(selected_model) if selected_model else None,
            effort=str(selected_effort) if selected_effort else None,
            conversation_id=f"primordial:{task.id}:wrapper:{role}" if task else None,
            persist=persist,
        )
        return {
            "model": self._wrapper_model_label(mode),
            "text": response.text,
            "elapsed_seconds": response.elapsed_seconds,
            "provider": response.provider,
            "wrapper_display_label": self._wrapper_display_label(mode),
            "request_id": response.request_id,
            "conversation_id": response.conversation_id,
            "session_resumed": response.session_resumed,
            "processor": "wrapper",
            "adapter": "agent_chat_api",
            "wrapper_mode": "use_only_wrapper",
            "wrapper_role": role,
            "temperature": temperature,
            "prompt_tokens": response.prompt_tokens,
            "completion_tokens": response.completion_tokens,
        }

    def _operator_state_ai_review(
        self,
        *,
        question: str,
        deterministic_body: str,
        target_id: str | None,
        route_model: str,
        route_num_gpu: int | None,
        max_wall_seconds: int = 90,
    ) -> dict[str, object] | None:
        _wall_start = time.monotonic()
        system = (
            "You are Primordial's local deep-review assistant. The deterministic state block is the source "
            "of truth. Do not contradict it, invent findings, invent flags, or claim actions ran. Add only "
            "a concise operational review: what changed, what is probably blocking progress, and the next "
            "safe primitive-backed move. If evidence or interests are marked historical, you must not treat "
            "them as current target facts or current exploit paths. If nothing changed, say that directly and "
            "explain why."
        )
        prompt = (
            f"Operator question:\n{question}\n\n"
            f"Deterministic runtime state:\n{deterministic_body}\n\n"
            f"Additional bounded snapshot:\n{self._build_operator_state_digest(target_id)}\n\n"
            "Return 3-6 concise bullets under no extra heading. No generic disclaimers. No exploit code. "
            "Use current-generation records only for target claims."
        )
        if time.monotonic() - _wall_start >= max_wall_seconds:
            return None
        try:
            if self._use_only_wrapper_mode():
                response_payload = self._wrapper_ai_generate(
                    role="local_deep",
                    system=system,
                    prompt=prompt,
                    persist=False,
                )
                text = str(response_payload.get("text") or "").strip()
                elapsed = response_payload.get("elapsed_seconds")
                model = str(response_payload.get("model") or self._wrapper_model_label())
            else:
                processor = "cpu" if route_num_gpu == 0 else "gpu"
                response = self.ollama.generate(
                    model=route_model,
                    system=system,
                    prompt=prompt,
                    temperature=0.0,
                    num_gpu=route_num_gpu,
                    keep_alive="2h",
                    timeout_seconds=self._ollama_timeout_seconds_for_processor(processor),
                )
                if not isinstance(response.text, str):
                    return None
                text = response.text.strip()
                elapsed = response.elapsed_seconds if isinstance(response.elapsed_seconds, int | float) else None
                model = str(response.model)
        except Exception as exc:  # noqa: BLE001 - deterministic state remains available when local review fails
            self.store.insert_event(
                EventRecord(
                    type=EventType.OPERATOR_AI_RESPONSE,
                    summary="Operator state AI review unavailable",
                    target_id=target_id,
                    metadata={"error": str(exc), "model": route_model},
                )
            )
            return None
        if not text or self._operator_answer_violates_contract(text):
            return None
        return {"model": model, "text": text, "elapsed_seconds": elapsed}

    def _model_role_for_route(self, route: ProviderRoute | None) -> str | None:
        if route == ProviderRoute.LOCAL_FAST:
            return "local_fast"
        if route == ProviderRoute.LOCAL_DEEP:
            return "local_deep"
        if route == ProviderRoute.LOCAL_COMPACT:
            return "local_compact"
        if route in {ProviderRoute.LOCAL_CODE, ProviderRoute.COLD_REVIEW}:
            return "local_code"
        return None

    def _apply_persisted_model_roles(self) -> None:
        self._apply_model_roles(self._current_model_roles())

    def _apply_model_roles(self, roles: dict[str, str]) -> None:
        for role, model in roles.items():
            config = self.MODEL_ROLE_CONFIG.get(role)
            if not config:
                continue
            setattr(self.config.topology, str(config["topology_field"]), model)

    def set_notion_credentials(
        self,
        *,
        api_key: str | None = None,
        parent_page_id: str | None = None,
        version: str | None = None,
    ) -> dict[str, object]:
        values = {
            "api_key": api_key or "",
            "parent_page_id": parent_page_id or "",
            "version": version or "",
        }
        self.credentials.clear_service_status("notion")
        outcome = self.credentials.update_service("notion", values)
        self.store.insert_event(
            EventRecord(
                type=EventType.CREDENTIAL_UPDATED,
                summary="Notion credentials updated",
                metadata={"service": "notion", "changed": outcome["changed"]},
            )
        )
        return self.credentials_payload()

    def set_discord_credentials(self, *, webhook_url: str | None = None) -> dict[str, object]:
        validated_webhook_url = validate_discord_webhook_url(webhook_url or "")
        outcome = self.credentials.update_service("discord", {"webhook_url": validated_webhook_url})
        self.store.insert_event(
            EventRecord(
                type=EventType.CREDENTIAL_UPDATED,
                summary="Discord credentials updated",
                metadata={"service": "discord", "changed": outcome["changed"]},
            )
        )
        return self.credentials_payload()

    def set_known_credentials(
        self,
        *,
        username: str | None = None,
        password: str | None = None,
        domain: str | None = None,
    ) -> dict[str, object]:
        values = {
            "username": username or "",
            "password": password or "",
            "domain": domain or "",
        }
        outcome = self.credentials.update_service("known", values)
        self.store.insert_event(
            EventRecord(
                type=EventType.CREDENTIAL_UPDATED,
                summary="Known credentials updated",
                metadata={"service": "known", "changed": outcome["changed"]},
            )
        )
        return self.credentials_payload()

    def set_lab_credentials(
        self,
        *,
        username: str | None = None,
        password: str | None = None,
        domain: str | None = None,
    ) -> dict[str, object]:
        return self.set_known_credentials(username=username, password=password, domain=domain)

    def set_caido_credentials(
        self,
        *,
        graphql_url: str | None = None,
        api_token: str | None = None,
    ) -> dict[str, object]:
        existing_graphql_url = self.credentials.get("caido", "graphql_url")
        selected_graphql_url = CaidoIntegrationService.normalize_graphql_url(graphql_url or "")
        default_graphql_url = ""
        if api_token and not selected_graphql_url:
            if not existing_graphql_url or existing_graphql_url != CaidoIntegrationService.normalize_graphql_url(existing_graphql_url):
                default_graphql_url = CaidoIntegrationService.DEFAULT_GRAPHQL_URL
        values = {
            "graphql_url": selected_graphql_url or default_graphql_url,
            "api_token": api_token or "",
        }
        outcome = self.credentials.update_service("caido", values)
        self.store.insert_event(
            EventRecord(
                type=EventType.CREDENTIAL_UPDATED,
                summary="Caido credentials updated",
                metadata={"service": "caido", "changed": outcome["changed"]},
            )
        )
        return self.credentials_payload()

    def clear_credentials(self, service: str) -> dict[str, object]:
        if service not in {"notion", "discord", "known", "lab", "caido"}:
            raise ValueError("service must be one of: notion, discord, known, lab, caido")
        removed = self.credentials.clear_service(service)
        if service == "lab":
            removed = self.credentials.clear_service("known") or removed
        elif service == "known":
            removed = self.credentials.clear_service("lab") or removed
        self.store.insert_event(
            EventRecord(
                type=EventType.CREDENTIAL_CLEARED,
                summary=f"{('known' if service == 'lab' else service).title()} credentials cleared",
                metadata={"service": service, "removed": removed},
            )
        )
        return self.credentials_payload()

    def _resolve_operator_chat_target(self, target: str | None, question: str) -> Target | None:
        target_record = self._resolve_target_reference(target)
        if target_record is not None:
            return target_record
        lowered = question.lower()
        for candidate in self.store.list_targets():
            identifiers = [candidate.handle, candidate.display_name, str(candidate.metadata.get("active_ip") or "")]
            identifiers.extend(asset.asset for asset in self.store.list_scope_assets(candidate.id))
            for identifier in identifiers:
                normalized = str(identifier or "").strip().lower()
                if not normalized:
                    continue
                if re.search(rf"(?<![a-z0-9_.:-]){re.escape(normalized)}(?![a-z0-9_.:-])", lowered):
                    return candidate
        return None

    def _operator_state_update_or_direct_answer(self, question: str, target: Target | None) -> str | None:
        lowered = question.lower()
        ips = self._extract_ip_addresses(question)
        is_ip_question = "ip" in lowered and any(term in lowered for term in ("using", "target", "what", "which", "current"))
        is_ip_update = bool(ips) and any(
            term in lowered
            for term in (
                "should be using",
                "use ",
                "using ",
                "target is",
                "ip is",
                "set ip",
                "change ip",
                "update ip",
            )
        )
        if is_ip_update:
            if not target:
                return (
                    "**Target IP Update Blocked**\n"
                    "- I found an IP correction, but no target was selected. Re-send it with `--target <handle>` "
                    "or select a target in the GUI/web app."
                )
            return self._apply_operator_active_ip(target, ips[-1])
        if is_ip_question:
            return self._target_ip_answer(target)
        return None

    def _extract_ip_addresses(self, value: str) -> list[str]:
        ips: list[str] = []
        for match in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", value):
            try:
                parsed = ipaddress.ip_address(match)
            except ValueError:
                continue
            if parsed.version == 4 and match not in ips:
                ips.append(match)
        return ips

    def _validated_optional_ip(self, value: str | None) -> str:
        candidate = str(value or "").strip()
        if not candidate:
            return ""
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError as exc:
            raise ValueError(f"invalid IP address: {candidate}") from exc

    def _apply_operator_active_ip(self, target: Target, ip: str) -> str:
        previous_ip = str(target.metadata.get("active_ip") or "").strip()
        refreshed_target = self.set_target_active_ip(target, ip, source="operator_chat")
        assets = self.store.list_scope_assets(refreshed_target.id)
        ip_assets = [asset.asset for asset in assets if asset.asset_type == "ip"]
        old_line = f"\n- Previous active IP: `{previous_ip}`" if previous_ip and previous_ip != ip else ""
        return (
            "**Target IP Updated**\n"
            f"- Target: `{target.handle}`\n"
            f"- Active operator-confirmed IP: `{ip}`\n"
            f"- Configured IP scope assets: {', '.join(f'`{item}`' for item in ip_assets) or 'none'}"
            f"{old_line}\n"
            "- Prior evidence that references older IPs is historical until recon/service discovery reruns for this active IP."
        )

    def _target_ip_answer(self, target: Target | None) -> str:
        if not target:
            return (
                "**Target IP**\n"
                "- No target is selected. Ask with a registered target handle, for example `--target <handle>`, "
                "or select a target in the GUI/web app."
            )
        assets = self.store.list_scope_assets(target.id)
        active_ip = str(target.metadata.get("active_ip") or "").strip()
        ip_assets = [asset.asset for asset in assets if asset.asset_type == "ip"]
        host_assets = [asset.asset for asset in assets if asset.asset_type in {"hostname", "webapp"}]
        historical_ips = self._historical_evidence_ips(target.id)
        lines = [
            "**Target IP**",
            f"- Target: `{target.handle}`",
            f"- Active operator-confirmed IP: `{active_ip}`" if active_ip else "- Active operator-confirmed IP: not set",
            f"- Configured IP scope assets: {', '.join(f'`{item}`' for item in ip_assets) or 'none'}",
            f"- Host/web assets: {', '.join(f'`{item}`' for item in host_assets) or 'none'}",
        ]
        if historical_ips:
            lines.append(
                f"- Historical evidence references: {', '.join(f'`{item}`' for item in historical_ips[:8])}"
            )
        if active_ip and historical_ips and any(item != active_ip for item in historical_ips):
            lines.append("- Any non-active historical IPs should be treated as stale until refreshed recon completes.")
        return "\n".join(lines)

    def _historical_evidence_ips(self, target_id: str) -> list[str]:
        seen: list[str] = []
        for item in self.store.list_evidence(target_id=target_id, limit=100):
            for ip in self._extract_ip_addresses(json.dumps(item.as_payload())):
                if ip not in seen:
                    seen.append(ip)
        return seen

    def _build_operator_prompt(self, question: str, target_id: str | None) -> str:
        target = self.store.get_target(target_id) if target_id else None
        rag_context_pack = self._rag_context_pack_payload(question, target_id)
        rag_context = rag_context_pack.get("chunks", []) if isinstance(rag_context_pack.get("chunks"), list) else []
        snapshot = {
            "operator_question": question,
            "active_session": (
                self.store.get_active_session().as_payload()
                if self.store.get_active_session()
                else None
            ),
            "current_target": target.as_payload() if target else None,
            "dashboard_counts": self.store.count_all(),
            "scope": self.scope_payload(),
            "recent_tasks": [item.as_payload() for item in self.store.list_tasks(target_id=target_id, limit=10)],
            "recent_evidence": [
                item.as_payload() for item in self.store.list_evidence(target_id=target_id, limit=10)
            ],
            "recent_notes": [item.as_payload() for item in self.store.list_notes(target_id=target_id, limit=8)],
            "recent_interests": [
                item.as_payload() for item in self.store.list_interests(target_id=target_id, limit=8)
            ],
            "recent_findings": [
                item.as_payload() for item in self.store.list_findings(target_id=target_id, limit=6)
            ],
            "recent_events": [item.as_payload() for item in self.store.list_events(limit=12)],
            "recent_operator_messages": [
                item.as_payload()
                for item in reversed(self.store.list_operator_messages(target_id=target_id, limit=8))
                if item.role != "assistant" or not self._operator_answer_violates_contract(item.body)
            ],
            "credentials_status": self.credentials_payload(),
            "available_skills": self.skills_payload(include_body=False),
            "permanent_findings_context": (
                self.findings_context.payload_for_target(target, include_guidance=True)
                if target
                else None
            ),
            "rag_context": rag_context,
            "rag_context_pack": rag_context_pack,
        }
        rendered = json.dumps(json_ready(snapshot), indent=2, sort_keys=True)
        if len(rendered) > 24000:
            rendered = rendered[:24000] + "\n...TRUNCATED_TO_KEEP_OPERATOR_CHAT_BOUNDED..."
        digest = self._build_operator_state_digest(target_id)
        return (
            "Answer the operator question using this bounded Primordial runtime snapshot.\n"
            "Do not assume hidden state outside this snapshot.\n\n"
            "Required answer contract:\n"
            "- Use concise markdown with these headings when relevant: Facts, Blockers, Next Actions.\n"
            "- Every factual claim must be supported by a record in the snapshot.\n"
            "- RAG context is advisory source material, not target evidence, approval, scope, or execution authority.\n"
            "- If you use RAG, cite rag:<chunk_id>; never present rag:<chunk_id> as evidence:<id>.\n"
            "- If user/root flags are not present in evidence, say they have not been obtained.\n"
            "- If current production primitives are insufficient, say exactly which primitive or operator input is missing.\n"
            "- Do not say evidence is implied; use the exact evidence, task, note, or primitive names supplied.\n\n"
            "Deterministic state digest:\n"
            f"{digest}\n\n"
            "Loaded runtime skills:\n"
            f"{self.skills.context_digest() or 'none'}\n\n"
            "Permanent findings context digest:\n"
            f"{self.findings_context.context_digest(target) or 'none'}\n\n"
            "Full structured snapshot:\n"
            f"{rendered}"
        )

    def _rag_context_payload(self, question: str, target_id: str | None) -> list[dict[str, object]]:
        pack = self._rag_context_pack_payload(question, target_id)
        chunks = pack.get("chunks", [])
        return [item for item in chunks if isinstance(item, dict)]

    def _rag_context_pack_payload(self, question: str, target_id: str | None) -> dict[str, object]:
        purpose = self._operator_rag_context_purpose(question)
        if not target_id:
            return {
                "query": question,
                "purpose": purpose,
                "role": "operator_chat",
                "target_id": None,
                "chunks": [],
                "citation_map": [],
                "omitted_sources": [],
                "warnings": [],
                "prompt_context": "",
            }
        try:
            target = self.store.get_target(target_id)
            return self.build_rag_context_pack(
                question,
                purpose=purpose,
                role="operator_chat",
                target=target,
                limit=5,
            )
        except Exception as exc:  # noqa: BLE001 - retrieval must not break operator Q&A
            return {
                "query": question,
                "purpose": purpose,
                "role": "operator_chat",
                "target_id": target_id,
                "chunks": [
                    {
                        "error": str(exc),
                        "retrieval_source": "rag_error",
                        "chunk_id": "",
                        "evidence_refs": [],
                    }
                ],
                "citation_map": [],
                "omitted_sources": [],
                "warnings": [str(exc)],
                "prompt_context": "",
            }

    def _operator_rag_context_purpose(self, question: str) -> str:
        lowered = question.lower()
        reporting_terms = (
            "mitre",
            "att&ck",
            "attack mapping",
            "map to",
            "mapping",
            "report",
            "detection",
            "mitigation",
            "classify",
            "classification",
            "cwe",
            "owasp",
        )
        return "report_mapping" if any(term in lowered for term in reporting_terms) else "operator_answer"

    def _rag_context_ids(self, rag_context: list[dict[str, object]]) -> list[str]:
        ids: list[str] = []
        for item in rag_context:
            for key in ("citation_id", "chunk_id"):
                ref = str(item.get(key) or "").strip()
                if not ref:
                    continue
                ids.append(ref if ref.startswith("rag:") else f"rag:{ref}")
        return sorted(set(ids))

    def _operator_answer_cites_rag_context(self, body: str, rag_context: list[dict[str, object]]) -> bool:
        clean_context = [item for item in rag_context if not item.get("error")]
        if not self._rag_context_ids(clean_context):
            return True
        return validate_rag_citations(body, clean_context, mode="operator_answer", require_citations=True).valid

    def _deterministic_rag_citation_answer(
        self,
        question: str,
        target_id: str | None,
        rag_context: list[dict[str, object]],
    ) -> str:
        base = self._deterministic_operator_answer(question, target_id)
        lines = []
        for item in rag_context[:5]:
            if item.get("error"):
                continue
            chunk_id = str(item.get("chunk_id") or "")
            citation_id = str(item.get("citation_id") or chunk_id).strip()
            if citation_id and not citation_id.startswith("rag:"):
                citation_id = f"rag:{citation_id}"
            refs = item.get("evidence_refs", [])
            evidence = ", ".join(f"`{ref}`" for ref in refs) if isinstance(refs, list) else ""
            title = str(item.get("source_display") or item.get("title") or "Imported document")
            text = str(item.get("text") or "").replace("\n", " ").strip()
            if len(text) > 220:
                text = text[:220].rstrip() + "..."
            lines.append(f"- `{citation_id}` linked_evidence={evidence or 'none'} advisory_only=true {title}: {text}")
        if not lines:
            return base
        return base + "\n\n**RAG Hints (not evidence)**\n" + "\n".join(lines)

    def _build_operator_state_digest(self, target_id: str | None) -> str:
        target = self.store.get_target(target_id) if target_id else None
        lines = []
        if target:
            lines.append(f"Target: {target.display_name} handle={target.handle} profile={target.profile.value}")
            if target.metadata.get("active_ip"):
                lines.append(
                    f"Active IP: {target.metadata.get('active_ip')} generation={target.metadata.get('active_ip_generation')}"
                )
            methodology_state = self._live_methodology_state_payload(target)
            if isinstance(methodology_state, dict) and methodology_state:
                lines.append(
                    "Methodology state: "
                    f"phase={methodology_state.get('phase')} "
                    f"subphase={methodology_state.get('subphase')} "
                    f"completion={methodology_state.get('completion')}"
                )
                if methodology_state.get("no_progress_reason"):
                    lines.append(f"No-progress reason: {methodology_state.get('no_progress_reason')}")
                if methodology_state.get("next_unblock_action"):
                    lines.append(f"Next unblock action: {methodology_state.get('next_unblock_action')}")
        active_generation = self._target_active_generation(target)
        tasks = self.store.list_tasks(target_id=target_id, limit=12)
        raw_evidence = self.store.list_evidence(target_id=target_id, limit=30)
        raw_notes = self.store.list_notes(target_id=target_id, limit=20)
        raw_interests = self.store.list_interests(target_id=target_id, limit=20)
        raw_findings = self.store.list_findings(target_id=target_id, limit=12)
        evidence = [item for item in raw_evidence if self._record_matches_active_generation(item, active_generation)][:12]
        notes = [item for item in raw_notes if self._record_matches_active_generation(item, active_generation)][:8]
        interests = [item for item in raw_interests if self._record_matches_active_generation(item, active_generation)][:8]
        findings = [item for item in raw_findings if self._record_matches_active_generation(item, active_generation)][:8]
        primitives = self.store.list_primitives()
        lines.append("Recent tasks:")
        lines.extend(f"- {task.kind.value} status={task.status.value} model={task.provider_model}" for task in tasks)
        if active_generation is not None:
            stale_evidence_count = len(raw_evidence) - len([item for item in raw_evidence if self._record_matches_active_generation(item, active_generation)])
            stale_interest_count = len(raw_interests) - len(
                [item for item in raw_interests if self._record_matches_active_generation(item, active_generation)]
            )
            lines.append(
                f"Historical records excluded from current reasoning: evidence={stale_evidence_count}, interests={stale_interest_count}"
            )
        lines.append("Current-generation evidence:")
        lines.extend(f"- {item.id}: {item.title} :: {item.summary}" for item in evidence)
        lines.append("Current-generation notes:")
        lines.extend(f"- {item.title}: {item.body[:500]}" for item in notes)
        lines.append("Current-generation interests:")
        lines.extend(f"- {item.title}: {item.summary}" for item in interests)
        if findings:
            lines.append("Current-generation findings:")
            lines.extend(f"- {finding.title}: {finding.summary}" for finding in findings)
        else:
            lines.append("Current-generation findings: none")
        flag_hits = [
            item.id
            for item in evidence
            if any(token in json.dumps(item.as_payload()).lower() for token in ("user.txt", "root.txt", "flag{", "htb{"))
        ]
        lines.append(f"Flag evidence IDs: {', '.join(flag_hits) if flag_hits else 'none'}")
        primitive_names = ", ".join(sorted(primitive.name for primitive in primitives))
        lines.append(f"Registered primitives: {primitive_names}")
        return "\n".join(lines)

    def _live_methodology_state_payload(self, target: Target | None) -> dict[str, object]:
        if target is None:
            return {}
        try:
            state = self.workflow.preview_target_state(target)
        except Exception:  # noqa: BLE001 - status surfaces must degrade safely
            cached = target.metadata.get("methodology_state", {})
            return cached if isinstance(cached, dict) else {}
        payload = state.as_payload()
        payload["planner_version"] = 2
        return payload

    def _target_active_generation(self, target: Target | None) -> str | None:
        if target is None or target.metadata.get("active_ip_generation") is None:
            return None
        return str(target.metadata["active_ip_generation"])

    def _record_matches_active_generation(self, record: object, active_generation: str | None) -> bool:
        if active_generation is None:
            return True
        metadata = getattr(record, "metadata", {})
        if not isinstance(metadata, dict):
            return False
        return str(metadata.get("active_ip_generation", "")) == active_generation

    def _should_answer_from_state(self, question: str) -> bool:
        lowered = question.lower()
        forced_terms = (
            "deterministic",
            "exact state",
            "raw state",
            "current status",
            "status and next step",
            "summarize",
            "summary",
            "next 3",
            "next three",
            "scoped recon",
            "recon steps",
            "latest task fail",
            "last task fail",
            "why did the latest task",
            "failed task",
            "blocked task",
            "open port",
            "open ports",
            "only 2 open",
            "only two open",
            "login portal",
            "login portals",
            "port 80",
            "escalate",
            "premium review",
            "remote review",
            "gpt",
            "anything new",
            "what is it doing",
            "what are you doing",
            "enough production primitives",
            "user.txt",
            "root.txt",
        )
        if any(term in lowered for term in forced_terms):
            return True
        if "flag" in lowered and any(term in lowered for term in ("status", "have", "found", "got", "obtained")):
            return True
        if "evidence" in lowered and any(term in lowered for term in ("list", "exact", "current", "stored", "status")):
            return True
        return False

    def _operator_question_requires_deterministic_only(self, question: str) -> bool:
        lowered = question.lower()
        deterministic_terms = (
            "summarize",
            "summary",
            "next 3",
            "next three",
            "scoped recon",
            "recon steps",
            "latest task fail",
            "last task fail",
            "why did the latest task",
            "failed task",
            "blocked task",
            "open port",
            "open ports",
            "only 2 open",
            "only two open",
            "login portal",
            "login portals",
            "port 80",
            "escalate",
            "premium review",
            "remote review",
            "gpt",
        )
        return any(term in lowered for term in deterministic_terms)

    def _operator_answer_violates_contract(self, body: str) -> bool:
        lowered = body.lower()
        unsupported_patterns = (
            "thought process",
            "ddos",
            "denial of service",
            "ethical considerations",
            "as an ai",
            "always ensure you have",
            "hello! i'm here to help",
            "how can i assist you today",
            "to help you best",
            "could you please tell me",
            "what you'd like to know or do",
        )
        return any(pattern in lowered for pattern in unsupported_patterns)

    def _operator_uncertainty_escalation_reason(
        self,
        question: str,
        body: str,
        metadata: dict[str, object],
        target: Target | None,
    ) -> str:
        if target is None:
            return ""
        current_evidence = [
            item
            for item in self.store.list_evidence(target_id=target.id, limit=100)
            if self._record_matches_active_generation(item, self._target_active_generation(target))
        ]
        if not current_evidence:
            return ""
        if self._operator_requests_premium_escalation(question):
            return "operator_requested_premium_review"
        if metadata.get("guardrail_replaced_model_output"):
            return "local_model_contract_violation"
        lowered_question = question.lower()
        asks_needed = "what is needed" in lowered_question or "what's needed" in lowered_question or "whats needed" in lowered_question
        if asks_needed and "No runnable next action is derivable from current evidence." in body:
            return "operator_needed_question_unresolved"
        return ""

    def _operator_requests_premium_escalation(self, question: str) -> bool:
        lowered = question.lower()
        mentions_premium = any(term in lowered for term in ("gpt", "premium", "remote review", "claude"))
        asks_escalation = any(term in lowered for term in ("escalate", "send", "ask", "review"))
        return mentions_premium and asks_escalation

    def _append_operator_escalation_status(
        self,
        body: str,
        target: Target,
        *,
        escalation_task: Task | None,
        reason: str,
    ) -> str:
        task = escalation_task
        if task is None:
            active = [
                item
                for item in self.store.list_tasks(target_id=target.id, limit=50)
                if item.kind == TaskKind.REVIEW_PREMIUM_ESCALATION
                and item.status
                in {TaskStatus.PENDING, TaskStatus.RUNNING, TaskStatus.WAITING, TaskStatus.NEEDS_APPROVAL}
            ]
            task = active[0] if active else None
        if task is None:
            status = (
                "**Premium Review**\n"
                f"- Request detected for `{target.handle}`, but no new premium review task was created. "
                "A duplicate review may already be recorded, or current evidence is insufficient for a structured packet."
            )
            return f"{body}\n\n{status}"
        approval = "auto-approved" if task.metadata.get("auto_approved") else task.status.value
        status = (
            "**Premium Review**\n"
            f"- Created or found `{task.kind.value}` task `{task.id}` for `{target.handle}`.\n"
            f"- Status: `{approval}`. Reason: `{reason}`.\n"
            "- The review packet is evidence-linked and cannot approve credential use, scope expansion, PoC execution, or Operator Intent changes."
        )
        return f"{body}\n\n{status}"

    def _deterministic_operator_answer(self, question: str, target_id: str | None) -> str:
        target = self.store.get_target(target_id) if target_id else None
        tasks = self.store.list_tasks(target_id=target_id, limit=12)
        evidence = self.store.list_evidence(target_id=target_id, limit=12)
        active_generation = self._target_active_generation(target)
        current_evidence = [
            item
            for item in evidence
            if self._record_matches_active_generation(item, active_generation)
        ]
        stale_evidence = [item for item in evidence if item not in current_evidence]
        raw_interests = self.store.list_interests(target_id=target_id, limit=12)
        raw_findings = self.store.list_findings(target_id=target_id, limit=8)
        interests = [item for item in raw_interests if self._record_matches_active_generation(item, active_generation)]
        findings = [item for item in raw_findings if self._record_matches_active_generation(item, active_generation)]
        primitives = self.store.list_primitives()
        primitive_names = {primitive.name for primitive in primitives}
        capabilities = {
            tag
            for primitive in primitives
            for tag in [primitive.name, *primitive.capability_tags]
        }
        evidence_kinds = {
            str(item.metadata.get("kind"))
            for item in current_evidence
            if item.metadata.get("kind")
        }
        flag_hits = [
            item
            for item in current_evidence
            if any(token in json.dumps(item.as_payload()).lower() for token in ("user.txt", "root.txt", "flag{", "htb{"))
        ]
        potential_paths = self._deterministic_potential_paths(current_evidence, interests, findings)
        lab_credentials_configured = self._lab_credentials_configured()
        credential_surface = classify_credentialed_access_surface(current_evidence)
        blockers = self._deterministic_blockers(
            flag_hits,
            findings,
            potential_paths,
            capabilities,
            lab_credentials_configured,
            credential_surface,
        )
        next_actions = self._deterministic_next_actions(current_evidence, interests, findings, capabilities, credential_surface)
        capability_gaps = self._deterministic_capability_gaps(current_evidence, evidence_kinds, capabilities, credential_surface)
        methodology_state = self._live_methodology_state_payload(target) if target else {}
        direct_answers = self._deterministic_direct_answers(
            question,
            target=target,
            tasks=tasks,
            evidence=current_evidence,
            interests=interests,
            findings=findings,
            next_actions=next_actions,
        )
        derived_next_actions = list(next_actions)
        if isinstance(methodology_state, dict):
            planned_actions = methodology_state.get("candidate_actions", [])
            if isinstance(planned_actions, list) and planned_actions:
                merged_actions: list[str] = []
                seen_actions: set[str] = set()
                for item in planned_actions[:5]:
                    if not isinstance(item, dict):
                        continue
                    title = str(item.get("title") or "Untitled action")
                    confidence = item.get("confidence")
                    prerequisite = str(item.get("prerequisite") or "").strip()
                    reason = str(item.get("transition_reason") or "").strip()
                    line = title
                    if prerequisite:
                        line += f" Prerequisite: {prerequisite}."
                    if confidence not in {None, ""}:
                        line += f" Confidence: {float(confidence):.2f}."
                    if reason:
                        line += f" Reason: {reason}"
                    normalized = line.strip()
                    lowered = normalized.lower()
                    if lowered not in seen_actions:
                        merged_actions.append(normalized)
                        seen_actions.add(lowered)
                for action in derived_next_actions:
                    lowered = action.lower()
                    if lowered in seen_actions:
                        continue
                    merged_actions.append(action)
                    seen_actions.add(lowered)
                next_actions = merged_actions[:6]

        facts = []
        if target:
            facts.append(f"Target `{target.handle}` is `{target.profile.value}` and in_scope={target.in_scope}.")
            active_ip = str(target.metadata.get("active_ip") or "").strip()
            if active_ip:
                facts.append(f"Active operator-confirmed IP is `{active_ip}`.")
            if isinstance(methodology_state, dict) and methodology_state:
                facts.append(
                    f"Methodology phase is `{methodology_state.get('phase')}` / `{methodology_state.get('subphase')}` "
                    f"with completion state `{methodology_state.get('completion')}`."
                )
            if stale_evidence:
                facts.append(
                    f"{len(stale_evidence)} recent evidence record(s) are historical for an older active-IP generation."
                )
        freshness_line = self._operator_recent_change_line(question, target_id)
        if freshness_line:
            facts.append(freshness_line)
        for item in current_evidence[:6]:
            facts.append(f"`{item.title}`: {item.summary}")
        if not facts:
            facts.append("No target-specific evidence is currently stored.")

        task_summary = ", ".join(f"{task.kind.value}:{task.status.value}" for task in tasks[:8]) or "none"
        sections = []
        if direct_answers:
            sections.append("**Direct Answer**\n" + "\n".join(f"- {line}" for line in direct_answers))
        sections.append(
            "**Facts**\n"
            + "\n".join(f"- {fact}" for fact in facts)
            + f"\n- Recent task states: {task_summary}"
            + f"\n- Registered primitives: {', '.join(sorted(primitive_names)) or 'none'}"
        )
        if potential_paths:
            sections.append("**Potential Paths**\n" + "\n".join(f"- {path}" for path in potential_paths))
        sections.append(
            "**Blockers**\n"
            + "\n".join(f"- {blocker}" for blocker in (blockers or ["No current blockers derived from stored state."]))
        )
        if isinstance(methodology_state, dict) and methodology_state.get("no_progress_reason"):
            sections.append(
                "**Planner State**\n"
                + "\n".join(
                    [
                        f"- No progress reason: {methodology_state.get('no_progress_reason')}",
                        f"- Next unblock action: {methodology_state.get('next_unblock_action') or 'none'}",
                    ]
                )
            )
        sections.append(
            "**Next Actions**\n"
            + "\n".join(f"- {action}" for action in (next_actions or ["No runnable next action is derivable from current evidence."]))
        )
        if capability_gaps:
            sections.append("**Capability Gaps**\n" + "\n".join(f"- {gap}" for gap in capability_gaps))
        return "\n\n".join(sections)

    def _deterministic_direct_answers(
        self,
        question: str,
        *,
        target: Target | None,
        tasks: list[Task],
        evidence: list[EvidenceRecord],
        interests: list[Interest],
        findings: list[Finding],
        next_actions: list[str],
    ) -> list[str]:
        lowered = question.lower()
        lines: list[str] = []
        asks_target_state = any(
            term in lowered
            for term in (
                "summarize",
                "summary",
                "next 3",
                "next three",
                "scoped recon",
                "recon steps",
                "latest task fail",
                "last task fail",
                "open port",
                "login portal",
                "port 80",
                "escalate",
                "gpt",
            )
        )
        if asks_target_state and target is None:
            return ["No target is selected or named in the question, so I cannot give target-specific runtime state."]

        if any(term in lowered for term in ("open port", "open ports", "only 2 open", "only two open")):
            services = self._current_open_port_summary(evidence)
            if services:
                line = (
                    f"Stored current evidence observes {len(services)} unique open TCP port(s): "
                    + ", ".join(f"`{item}`" for item in services)
                    + "."
                )
                lines.append(line)
                if not self._has_full_port_scan_evidence(evidence):
                    lines.append(
                        "That is an observed-port answer, not proof that no other ports exist; no full-range port sweep evidence is stored."
                    )
            else:
                lines.append("No current TCP service-discovery evidence is stored, so open ports cannot be answered from state.")

        if any(term in lowered for term in ("login portal", "login portals", "port 80", "auth surface", "auth surfaces")):
            auth_paths = self._current_auth_surface_summary(evidence, interests, findings)
            if auth_paths:
                lines.append(
                    "Stored current evidence identifies auth/session candidate(s): "
                    + ", ".join(f"`{item}`" for item in auth_paths[:10])
                    + "."
                )
            elif any(self._evidence_has_http_surface(item) for item in evidence):
                lines.append("No stored current evidence identifies a login portal on port 80.")
            else:
                lines.append("No current HTTP evidence is stored, so login portals cannot be answered from state.")

        if any(term in lowered for term in ("latest task fail", "last task fail", "why did the latest task", "failed task", "blocked task")):
            task = self._latest_problem_task(tasks)
            if task is None:
                lines.append("No failed, blocked, cancelled, or approval-waiting task is present in the recent target task set.")
            else:
                reason = self._task_problem_reason(task)
                lines.append(
                    f"Latest problem task is `{task.kind.value}` `{task.id}` with status `{task.status.value}`: {reason}"
                )

        if any(term in lowered for term in ("next 3", "next three", "scoped recon", "recon steps")):
            scoped = next_actions[:3]
            if scoped:
                for index, action in enumerate(scoped, start=1):
                    lines.append(f"Scoped recon step {index}: {action}")
            else:
                lines.append("No runnable scoped recon step is derivable from current evidence.")

        if self._operator_requests_premium_escalation(question):
            if target is None:
                lines.append("Premium review was not created because no target is selected.")
            elif not evidence:
                lines.append(f"Premium review was not created for `{target.handle}` because no current evidence is stored.")
            else:
                lines.append(
                    f"Premium review requested for `{target.handle}`; a structured evidence-linked review task will be created if no active duplicate exists."
                )

        return lines

    def _current_open_port_summary(self, evidence: list[EvidenceRecord]) -> list[str]:
        ports: dict[int, set[str]] = {}
        for item in evidence:
            services = item.metadata.get("open_services", [])
            if not isinstance(services, list):
                continue
            for service in services:
                if not isinstance(service, dict):
                    continue
                try:
                    port = int(service.get("port", 0) or 0)
                except (TypeError, ValueError):
                    continue
                if port <= 0:
                    continue
                name = str(service.get("service") or service.get("name") or "").strip().lower()
                ports.setdefault(port, set())
                if name:
                    ports[port].add(name)
        summary = []
        for port in sorted(ports):
            names = sorted(ports[port])
            summary.append(f"{port}/{names[0]}" if names else str(port))
        return summary

    def _has_full_port_scan_evidence(self, evidence: list[EvidenceRecord]) -> bool:
        for item in evidence:
            payload = json.dumps(item.as_payload()).lower()
            if any(term in payload for term in ("full-range", "full range", "all 65535", "65535 ports", "1-65535")):
                return True
        return False

    def _current_auth_surface_summary(
        self,
        evidence: list[EvidenceRecord],
        interests: list[Interest],
        findings: list[Finding],
    ) -> list[str]:
        candidates: list[str] = []

        def add(value: object) -> None:
            text = str(value or "").strip()
            if not text:
                return
            lowered = text.lower()
            if any(term in lowered for term in ("login", "signin", "sign-in", "auth", "session", "admin", "account")):
                if text not in candidates:
                    candidates.append(text)

        for item in evidence:
            for key in ("auth_surfaces", "forms", "paths", "page_links", "interesting_paths"):
                values = item.metadata.get(key, [])
                if isinstance(values, list):
                    for value in values:
                        add(value)
        for item in interests:
            if item.metadata.get("class") == "auth":
                values = item.metadata.get("paths", [])
                if isinstance(values, list):
                    for value in values:
                        add(value)
                add(item.title)
                add(item.summary)
        for item in findings:
            values = item.metadata.get("auth_surfaces", [])
            if isinstance(values, list):
                for value in values:
                    add(value)
            values = item.metadata.get("interesting_paths", [])
            if isinstance(values, list):
                for value in values:
                    add(value)
        return candidates

    def _latest_problem_task(self, tasks: list[Task]) -> Task | None:
        problem_statuses = {
            TaskStatus.FAILED,
            TaskStatus.BLOCKED,
            TaskStatus.CANCELLED,
            TaskStatus.NEEDS_APPROVAL,
            TaskStatus.WAITING,
        }
        candidates = [task for task in tasks if task.status in problem_statuses]
        if not candidates:
            return None
        return sorted(candidates, key=lambda task: task.updated_at, reverse=True)[0]

    def _task_problem_reason(self, task: Task) -> str:
        for key in ("block_reason", "reason", "error", "validation_reason", "next_unblock_action"):
            value = task.metadata.get(key)
            if value:
                return str(value)
        validation = task.metadata.get("validation_issues")
        if isinstance(validation, list) and validation:
            first = validation[0]
            if isinstance(first, dict):
                return str(first.get("message") or first.get("reason") or task.summary)
            return str(first)
        return task.summary or task.title

    def _operator_recent_change_line(self, question: str, target_id: str | None) -> str:
        lowered = question.lower()
        if not any(term in lowered for term in ("anything new", "what's new", "whats new", "any new")):
            return ""
        messages = self.store.list_operator_messages(target_id=target_id, limit=20)
        last_assistant_at = None
        for message in messages:
            if message.role == "assistant":
                last_assistant_at = message.created_at
                break
        if last_assistant_at is None:
            return "No previous assistant response exists for comparison."
        new_tasks = [item for item in self.store.list_tasks(target_id=target_id, limit=100) if item.created_at > last_assistant_at]
        new_evidence = [
            item for item in self.store.list_evidence(target_id=target_id, limit=100) if item.created_at > last_assistant_at
        ]
        new_findings = [
            item for item in self.store.list_findings(target_id=target_id, limit=100) if item.created_at > last_assistant_at
        ]
        if not new_tasks and not new_evidence and not new_findings:
            return "No new task, evidence, or finding records have been stored since the last assistant response."
        return (
            "New since last assistant response: "
            f"{len(new_tasks)} task(s), {len(new_evidence)} evidence record(s), {len(new_findings)} finding(s)."
        )

    def _deterministic_potential_paths(
        self,
        evidence: list[EvidenceRecord],
        interests: list[Interest],
        findings: list[Finding],
    ) -> list[str]:
        paths: list[str] = []
        seen: set[str] = set()

        for finding in findings:
            status = getattr(finding, "verification_status", None)
            if status == VerificationStatus.VERIFIED:
                continue
            line = (
                f"`{finding.title}` is a {finding.severity.value} candidate with "
                f"{finding.confidence:.2f} confidence and {finding.verification_status.value} verification."
            )
            self._append_unique(paths, seen, line)

        for interest in interests:
            if interest.status in {InterestStatus.REJECTED, InterestStatus.STALE, InterestStatus.SUPERSEDED}:
                continue
            interest_class = str(interest.metadata.get("class", ""))
            if interest_class == "exploit_research" or "poc" in interest.title.lower() or "exploit" in interest.title.lower():
                line = f"`{interest.title}`: {interest.summary} Confidence {interest.confidence:.2f}."
                if self._looks_like_lpe(interest.title, interest.summary):
                    line += " Prerequisite: requires user shell or credentialed access before LPE verification."
                self._append_unique(paths, seen, line)

        for item in evidence:
            if item.metadata.get("kind") != "exploit_research":
                continue
            match_count = int(item.metadata.get("match_count", 0) or 0)
            if match_count <= 0:
                continue
            line = (
                f"`{item.title}` retained {match_count} non-DoS public exploit reference(s). "
                "These are potential paths until target-specific version/applicability evidence verifies them."
            )
            if self._looks_like_lpe(item.title, item.summary):
                line += " Prerequisite: requires user shell or credentialed access before LPE verification."
            self._append_unique(paths, seen, line)

        return paths

    def _deterministic_blockers(
        self,
        flag_hits: list[EvidenceRecord],
        findings: list[Finding],
        potential_paths: list[str],
        capabilities: set[str],
        lab_credentials_configured: bool,
        credential_surface: CredentialedAccessSurface,
    ) -> list[str]:
        blockers: list[str] = []
        if not flag_hits:
            blockers.append("No stored evidence contains a user/root flag or flag-like token.")
        verified_findings = [
            finding for finding in findings if getattr(finding, "verification_status", None) == VerificationStatus.VERIFIED
        ]
        if not verified_findings and not potential_paths:
            blockers.append("No verified findings or potential exploit paths are stored for this target.")
        if not self._has_any_capability(capabilities, "finding-verification", "auth-analysis"):
            blockers.append("No registered finding-verification primitive is available for exploitation-phase validation.")
        if not self._has_any_capability(capabilities, "winrm", "smb-session", "flag-collection", "credential-use"):
            blockers.append("No credentialed WinRM/SMB flag-collection primitive is registered.")
        elif credential_surface.eligible and not lab_credentials_configured and not flag_hits:
            blockers.append("Known username/password are not configured, so credentialed Windows SMB/WinRM verification cannot run.")
        if potential_paths and not self._poc_adaptation_available(capabilities):
            blockers.append(
                "Retained public PoC candidates exist, but no gated PoC applicability/adaptation primitive is registered."
            )
        return blockers

    def _lab_credentials_configured(self) -> bool:
        username = self.credentials.get("known", "username")
        password = self.credentials.get("known", "password")
        return bool(username and password)

    def _deterministic_next_actions(
        self,
        evidence: list[EvidenceRecord],
        interests: list[Interest],
        findings: list[Finding],
        capabilities: set[str],
        credential_surface: CredentialedAccessSurface,
    ) -> list[str]:
        actions: list[tuple[float, str]] = []
        evidence_kinds = {
            str(item.metadata.get("kind"))
            for item in evidence
            if item.metadata.get("kind")
        }
        has_http = any(self._evidence_has_http_surface(item) for item in evidence)
        has_dns_port = self._evidence_has_port(evidence, 53)
        has_ad_ports = any(
            self._evidence_has_port(evidence, port)
            for port in (88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269)
        )
        has_shell = self._has_shell_or_credentialed_access(evidence, interests, findings)
        lab_credentials_configured = self._lab_credentials_configured()
        has_exploit_candidates = any(
            item.metadata.get("kind") == "exploit_research" and int(item.metadata.get("match_count", 0) or 0) > 0
            for item in evidence
        ) or any(interest.metadata.get("class") == "exploit_research" for interest in interests)
        has_versioned_service_terms = self._has_service_version_terms(evidence)
        has_lpe_candidate = any(
            self._looks_like_lpe(item.title, item.summary)
            for item in [*evidence, *interests]
        ) or any(self._looks_like_lpe(finding.title, finding.summary) for finding in findings)

        if "tcp_service_discovery" not in evidence_kinds and self._has_any_capability(capabilities, "tcp-service-discovery"):
            actions.append((0.92, "Run bounded TCP service discovery. Prerequisite: target is in scope."))
        if has_dns_port and "dns_enumeration" not in evidence_kinds and self._has_any_capability(capabilities, "dns-enumeration"):
            actions.append((0.88, "Run bounded DNS enumeration. Prerequisite: TCP evidence shows DNS/53."))
        if has_ad_ports and "ad_enumeration" not in evidence_kinds and self._has_any_capability(capabilities, "ad-enumeration", "ldap-enumeration"):
            actions.append((0.87, "Run anonymous AD enumeration. Prerequisite: TCP evidence shows LDAP/Kerberos/SMB services."))
        if has_http and "web_content_discovery" not in evidence_kinds and self._has_any_capability(capabilities, "content-discovery", "path-enumeration"):
            actions.append((0.82, "Run bounded web content discovery. Prerequisite: HTTP probe evidence shows a live web surface."))
        if (
            {"tcp_service_discovery", "dns_enumeration", "ad_enumeration"}.intersection(evidence_kinds)
            and "exploit_research" not in evidence_kinds
            and self._has_any_capability(capabilities, "exploit-research", "searchsploit")
            and has_versioned_service_terms
        ):
            actions.append((0.78, "Run evidence-backed Searchsploit research. Prerequisite: service/version terms from stored recon evidence."))
        elif (
            {"tcp_service_discovery", "dns_enumeration", "ad_enumeration"}.intersection(evidence_kinds)
            and "exploit_research" not in evidence_kinds
            and self._has_any_capability(capabilities, "exploit-research", "searchsploit")
        ):
            actions.append((0.77, "Collect current service/version evidence before Searchsploit research. Prerequisite: exact product/version terms are not yet stored."))
        if has_exploit_candidates:
            if self._poc_adaptation_available(capabilities):
                actions.append((0.76, "Run gated public PoC applicability validation against exact service/version evidence. Prerequisite: retained non-DoS Searchsploit candidates."))
            else:
                actions.append((0.76, "Add a gated PoC applicability/adaptation primitive before validating retained public exploit references. Prerequisite: retained non-DoS Searchsploit candidates."))
        if has_ad_ports and "ad_enumeration" in evidence_kinds and "kerberos_user_discovery" not in evidence_kinds:
            actions.append((0.74, "Add or run Kerberos/LDAP user discovery before AS-REP/Kerberoast checks. Prerequisite: AD enumeration evidence exists."))
        if has_lpe_candidate and has_shell:
            actions.append((0.80, "Verify local privilege-escalation candidate. Prerequisite: credentialed shell/access evidence exists."))
        elif has_lpe_candidate:
            actions.append((0.54, "Defer local privilege-escalation candidate until user shell or credentialed access exists. Prerequisite: foothold not yet evidenced."))
        if (
            credential_surface.eligible
            and self._has_any_capability(capabilities, "credentialed-access-check", "smb-session", "winrm")
            and not lab_credentials_configured
        ):
            actions.append((0.72, "Configure known credentials before credentialed Windows SMB/WinRM verification. Prerequisite: operator-provided username/password."))

        return [f"{text} Confidence: {score:.2f}." for score, text in sorted(actions, reverse=True)[:5]]

    def _has_service_version_terms(self, evidence: list[EvidenceRecord]) -> bool:
        version_pattern = re.compile(r"\b\d+(?:\.\d+){1,3}[A-Za-z0-9._+-]*\b")
        empty_values = {"", "unknown", "none", "n/a", "tcpwrapped"}

        def has_version(value: object) -> bool:
            text = str(value or "").strip()
            if text.lower() in empty_values:
                return False
            return bool(version_pattern.search(text))

        for item in evidence:
            metadata = item.metadata
            for key in ("service_version", "version", "product_version", "banner", "fingerprint"):
                if has_version(metadata.get(key)):
                    return True
            for service in metadata.get("open_services", []):
                if not isinstance(service, dict):
                    continue
                version = service.get("version") or service.get("product_version")
                product = service.get("product") or service.get("name") or service.get("service")
                if has_version(version):
                    return True
                combined = " ".join(str(service.get(key) or "") for key in ("product", "banner", "extrainfo", "fingerprint"))
                if product and has_version(combined):
                    return True
            headers = metadata.get("headers")
            if isinstance(headers, dict) and has_version(headers.get("server") or headers.get("Server")):
                return True
        return False

    def _deterministic_capability_gaps(
        self,
        evidence: list[EvidenceRecord],
        evidence_kinds: set[str],
        capabilities: set[str],
        credential_surface: CredentialedAccessSurface,
    ) -> list[str]:
        gaps: list[str] = []
        has_http = any(self._evidence_has_http_surface(item) for item in evidence)
        has_ad_ports = any(self._evidence_has_port(evidence, port) for port in (88, 389, 445, 636, 3268, 3269))
        has_exploit_candidates = any(
            item.metadata.get("kind") == "exploit_research" and int(item.metadata.get("match_count", 0) or 0) > 0
            for item in evidence
        )
        if has_http and "web_content_discovery" not in evidence_kinds and not self._has_any_capability(capabilities, "content-discovery", "path-enumeration"):
            gaps.append("Content discovery primitive is missing for live HTTP surfaces.")
        if has_ad_ports and not self._has_any_capability(capabilities, "kerberos-user-discovery", "ldap-user-discovery", "asrep-roast", "kerberoast"):
            gaps.append("Kerberos/LDAP user-discovery primitive is missing for AD attack-path validation.")
        if has_exploit_candidates and not self._poc_adaptation_available(capabilities):
            gaps.append("Gated exploit-synthesis/adaptation primitive is missing for retained public PoC candidates.")
        if credential_surface.eligible and not self._has_any_capability(capabilities, "winrm", "smb-session", "flag-collection", "credential-use"):
            gaps.append("Credentialed WinRM/SMB flag-collection primitive is missing.")
        return gaps

    def _append_unique(self, values: list[str], seen: set[str], value: str) -> None:
        key = value.lower()
        if key not in seen:
            values.append(value)
            seen.add(key)

    def _poc_adaptation_available(self, capabilities: set[str]) -> bool:
        if self._has_any_capability(capabilities, "poc-adaptation", "poc-applicability-validation"):
            return True
        return self.config.autonomy.allow_remote_premium and self._has_any_capability(capabilities, "exploit-synthesis")

    def _has_any_capability(self, capabilities: set[str], *needles: str) -> bool:
        lowered = {capability.lower() for capability in capabilities}
        return any(any(needle in capability for capability in lowered) for needle in needles)

    def _evidence_has_port(self, evidence: list[EvidenceRecord], port: int) -> bool:
        for item in evidence:
            for service in item.metadata.get("open_services", []):
                if isinstance(service, dict) and int(service.get("port", 0) or 0) == port:
                    return True
        return False

    def _evidence_has_http_surface(self, item: EvidenceRecord) -> bool:
        effective_url = item.metadata.get("effective_url")
        status_code = item.metadata.get("status_code")
        if isinstance(effective_url, str) and effective_url.startswith(("http://", "https://")):
            return not isinstance(status_code, int) or status_code < 500
        for service in item.metadata.get("open_services", []):
            if not isinstance(service, dict):
                continue
            name = str(service.get("service", "")).lower()
            port = int(service.get("port", 0) or 0)
            if name in {"http", "https", "http-rpc-epmap"} or port in {80, 443, 593, 5985}:
                return True
        return False

    def _has_shell_or_credentialed_access(
        self,
        evidence: list[EvidenceRecord],
        interests: list[Interest],
        findings: list[Finding],
    ) -> bool:
        del interests
        records = [item.as_payload() for item in evidence]
        records.extend(
            finding.as_payload()
            for finding in findings
            if getattr(finding, "verification_status", None) in {VerificationStatus.PARTIAL, VerificationStatus.VERIFIED}
        )
        joined = json.dumps(records).lower()
        if any(token in joined for token in ("requires credentialed access", "requires user shell", "before lpe verification")):
            joined = joined.replace("requires credentialed access", "")
            joined = joined.replace("requires user shell", "")
            joined = joined.replace("before lpe verification", "")
        return any(
            token in joined
            for token in (
                "user.txt",
                "root.txt",
                "shell",
                "credentialed",
                "valid credential",
                "winrm session",
                "smb session",
                "meterpreter",
                # Linux / generic shell indicators
                "interactive shell",
                "shell obtained",
                "reverse shell",
                "bind shell",
                "command execution",
                "rce confirmed",
                "arbitrary command",
                "shell_access",
                "initial_access",
                # HTB/CTF flag patterns
                "flag.txt",
                "proof.txt",
                "local.txt",
                "pwned",
                "pwn3d",
                "foothold",
            )
        )

    def _looks_like_lpe(self, *values: str) -> bool:
        joined = " ".join(values).lower()
        return any(
            token in joined
            for token in (
                "unquoted service path",
                "local privilege escalation",
                "privilege escalation",
                "lpe",
                "privesc",
                # Linux LPE signals
                "sudo exploit",
                "suid",
                "sgid",
                "kernel exploit",
                "dirtycow",
                "dirty cow",
                "dirty pipe",
                "pwnkit",
                "polkit",
                "cve-2021-4034",
                "cve-2022-0847",
                "writable /etc/passwd",
                "writable sudoers",
                "no passwd sudo",
                "capabilities exploit",
                "cap_setuid",
            )
        )

    def _caido_scope_terms(self, target: Target) -> list[str]:
        terms: list[str] = []
        if target.handle:
            terms.append(target.handle)
        active_ip = str(target.metadata.get("active_ip") or "").strip()
        if active_ip:
            terms.append(active_ip)
        for asset in self.store.list_scope_assets(target.id):
            value = str(asset.asset or "").strip()
            if value:
                terms.append(value)
        seen: set[str] = set()
        deduped = []
        for item in terms:
            normalized = item.lower()
            if normalized in seen:
                continue
            seen.add(normalized)
            deduped.append(item)
        return deduped

    def _caido_host_in_scope(self, target: Target, host: str) -> bool:
        if not target.in_scope:
            return False
        selected = self._normalize_scope_host(host)
        if not selected:
            return False
        allowed = {self._normalize_scope_host(target.handle)}
        active_ip = str(target.metadata.get("active_ip") or "").strip()
        if active_ip:
            allowed.add(self._normalize_scope_host(active_ip))
        for asset in self.store.list_scope_assets(target.id):
            value = str(asset.asset or "").strip()
            if value:
                allowed.add(self._normalize_scope_host(value))
        allowed.discard("")
        return selected in allowed

    def _normalize_scope_host(self, value: str) -> str:
        raw = str(value or "").strip()
        if not raw:
            return ""
        parsed = urlparse.urlsplit(raw if "://" in raw else f"//{raw}")
        if parsed.hostname:
            return parsed.hostname.strip("[]").rstrip(".").lower()
        return raw.split("/", 1)[0].split(":", 1)[0].strip("[]").rstrip(".").lower()

    def _write_caido_capture_artifact(
        self,
        target: Target,
        request_payload: dict[str, object],
        *,
        httpql: str,
    ) -> ArtifactRecord:
        request_id = str(request_payload.get("id") or "unknown")
        artifact_dir = self.config.artifacts_dir / "caido" / self._safe_log_fragment(target.handle)
        artifact_dir.mkdir(parents=True, exist_ok=True)
        path = artifact_dir / f"{self._safe_log_fragment(request_id)}.json"
        payload = {
            "version": 1,
            "kind": ArtifactKind.CAIDO_CAPTURE.value,
            "target": target.as_payload(),
            "caido_request_id": request_id,
            "httpql": httpql,
            "imported_at": utc_now().isoformat(),
            "raw_bodies_stored": False,
            "request": {
                "id": request_id,
                "method": request_payload.get("method") or "",
                "host": request_payload.get("host") or "",
                "port": request_payload.get("port"),
                "path": request_payload.get("path") or "",
                "status": request_payload.get("status") or 0,
                "source": request_payload.get("source") or "",
                "request_sha256": request_payload.get("request_sha256") or "",
                "response_sha256": request_payload.get("response_sha256") or "",
                "request_snippet": request_payload.get("request_snippet") or "",
                "response_snippet": request_payload.get("response_snippet") or "",
                "request_truncated": bool(request_payload.get("request_truncated")),
                "response_truncated": bool(request_payload.get("response_truncated")),
            },
        }
        path.write_text(json.dumps(json_ready(payload), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        content = path.read_bytes()
        return ArtifactRecord(
            task_id=None,
            target_id=target.id,
            kind=ArtifactKind.CAIDO_CAPTURE,
            path=str(path),
            sha256=hashlib.sha256(content).hexdigest(),
            size_bytes=len(content),
            metadata={
                "caido_request_id": request_id,
                "httpql": httpql,
                "raw_bodies_stored": False,
            },
        )

    def _resolve_target_reference(self, target: str | None) -> Target | None:
        if not target:
            targets = self.store.list_targets()
            return targets[0] if len(targets) == 1 else None
        direct = self.store.get_target(target)
        if direct is not None:
            return direct
        return self.store.get_target_by_handle(target)

    def _infer_asset_type(self, asset: str) -> str:
        if asset.startswith("http://") or asset.startswith("https://"):
            return "webapp"
        try:
            ipaddress.ip_address(asset)
            return "ip"
        except ValueError:
            return "hostname"

    def _recover_runtime_state(self) -> None:
        tasks = self.store.list_tasks(limit=500)
        seen_successes: set[tuple[str | None, str]] = set()
        for task in tasks:
            route = self.router.select_route(task)
            changed = False
            if task.provider_route is None:
                task.provider_route = route.route
                changed = True
            if not task.provider_model:
                task.provider_model = route.model_name
                changed = True
            if task.status.value == "running":
                task.status = TaskStatus.PENDING
                changed = True
            if task.status.value == "succeeded":
                seen_successes.add((task.target_id, task.kind.value))
            if changed:
                self.store.insert_task(task)

        for task in self.store.list_tasks(limit=500):
            key = (task.target_id, task.kind.value)
            if key in seen_successes and task.status in {TaskStatus.PENDING, TaskStatus.WAITING}:
                task.status = TaskStatus.CANCELLED
                task.metadata["recovered_duplicate"] = True
                self.store.insert_task(task)
        self.resume_tracker.resume_due_tasks(limit=500)

    def _apply_runtime_tuning(self) -> None:
        tuning = self.runtime_tuning_payload()
        self.WORKER_AI_TIMEOUT_SECONDS_GPU = int(tuning["gpu_ai_timeout_seconds"])
        self.WORKER_AI_TIMEOUT_SECONDS_CPU = int(tuning["cpu_ai_timeout_seconds"])
        self.workflow.stale_run_max_age_seconds = int(tuning["stale_run_timeout_seconds"])

    def _validate_topology_models(self) -> None:
        """Check that configured topology model names exist in Ollama; emit warnings for missing models."""
        if self._use_only_wrapper_mode():
            self.store.insert_event(
                EventRecord(
                    type=EventType.BOOTSTRAP,
                    summary="Topology model validation skipped for use-only-wrapper mode",
                    metadata={"wrapper_mode": self.model_wrapper_mode_payload()},
                )
            )
            return
        import logging
        result = self.ollama.list_models()
        if not result.ok:
            logging.getLogger(__name__).warning(
                "Ollama unreachable at startup — cannot validate topology models: %s", result.error
            )
            return
        installed = set(result.models)
        installed.update(model.removesuffix(":latest") for model in result.models if model.endswith(":latest"))
        topology = self.config.topology
        role_model_map = {
            "local_fast": topology.local_fast,
            "local_deep": topology.local_deep,
            "local_code": topology.local_code,
            "local_compact": topology.local_compact,
        }
        missing = [role for role, model in role_model_map.items() if model and model not in installed]
        if missing:
            logging.getLogger(__name__).warning(
                "Topology models not found in Ollama: %s — run 'ollama pull <model>' or update MODEL_ROLE_CONFIG.",
                {r: role_model_map[r] for r in missing},
            )
            self.store.insert_event(
                EventRecord(
                    type=EventType.SYNC_FAILED,
                    summary=f"Topology models missing from Ollama: {', '.join(missing)}",
                    metadata={"missing_roles": {r: role_model_map[r] for r in missing}},
                )
            )

    def _bounded_int(self, raw: object, *, default: int, minimum: int) -> int:
        try:
            value = int(raw) if raw is not None else default
        except (TypeError, ValueError):
            value = default
        return max(minimum, value)

    def _self_test_database(self) -> dict[str, object]:
        try:
            with self.store.connect() as connection:
                row = connection.execute("SELECT 1 AS ok").fetchone()
            ok = bool(row and int(row["ok"]) == 1)
            return {"id": "db", "label": "Database reachable", "status": "pass" if ok else "fail", "details": {}}
        except Exception as exc:  # noqa: BLE001 - self-test reports all failures as data
            return {"id": "db", "label": "Database reachable", "status": "fail", "details": {"error": str(exc)}}

    def _self_test_runtime_dirs(self) -> dict[str, object]:
        dirs = [
            self.config.runtime_dir,
            self.config.artifacts_dir,
            self.config.checkpoints_dir,
            self.config.chat_logs_dir,
            self.config.findings_dir,
        ]
        results = []
        for directory in dirs:
            try:
                directory.mkdir(parents=True, exist_ok=True)
                probe = directory / ".primordial_self_test"
                probe.write_text("ok\n", encoding="utf-8")
                probe.unlink(missing_ok=True)
                results.append({"path": str(directory), "writable": True})
            except OSError as exc:
                results.append({"path": str(directory), "writable": False, "error": str(exc)})
        status = "pass" if all(item["writable"] for item in results) else "fail"
        return {"id": "runtime_dirs", "label": "Runtime directories writable", "status": status, "details": {"dirs": results}}

    def _self_test_scope(self) -> dict[str, object]:
        scope = self.scope_payload()
        totals = scope.get("totals", {}) if isinstance(scope.get("totals"), dict) else {}
        target_count = int(totals.get("targets", 0) or 0)
        status = "pass" if target_count else "warn"
        return {"id": "scope", "label": "Target scope present", "status": status, "details": totals}

    def _self_test_metrics(self) -> dict[str, object]:
        metrics = self.system_metrics_payload(force_refresh=True)
        cpu = metrics.get("cpu", {}) if isinstance(metrics.get("cpu"), dict) else {}
        network = metrics.get("network", {}) if isinstance(metrics.get("network"), dict) else {}
        ok = bool(cpu.get("available")) and bool(network.get("available"))
        return {
            "id": "metrics",
            "label": "Host metrics available",
            "status": "pass" if ok else "warn",
            "details": {
                "cpu": bool(cpu.get("available")),
                "memory": cpu.get("memory"),
                "network": network,
                "gpu": metrics.get("gpu", {}),
            },
        }

    def _self_test_model_listing(self) -> dict[str, object]:
        details: dict[str, object] = {}
        if self.ollama.is_reachable(timeout_seconds=0.5):
            ollama = self.ollama.list_models()
            details["ollama"] = {
                "ok": ollama.ok,
                "count": len(ollama.models),
                "base_url": self.ollama.base_url,
                "error": ollama.error,
            }
        else:
            details["ollama"] = {
                "ok": False,
                "count": 0,
                "base_url": self.ollama.base_url,
                "error": "Ollama tags endpoint is not reachable",
            }
        lmstudio = LMStudioClient(timeout_seconds=1).list_models()
        details["lmstudio"] = {
            "ok": lmstudio.ok,
            "count": len(lmstudio.models),
            "error": lmstudio.error,
        }
        ollama_details = details.get("ollama", {}) if isinstance(details.get("ollama"), dict) else {}
        status = "pass" if bool(ollama_details.get("ok")) or lmstudio.ok else "warn"
        return {"id": "model_listing", "label": "Model provider listing reachable", "status": status, "details": details}

    def _self_test_credentials_redacted(self) -> dict[str, object]:
        payload = self.credentials_payload()
        serialized = json.dumps(payload, sort_keys=True)
        leaked = [token for token in ("api_key", "password", "token", "webhook") if f"secret_{token}" in serialized]
        return {
            "id": "credentials",
            "label": "Credentials redacted",
            "status": "fail" if leaked else "pass",
            "details": {"services": list((payload.get("services", {}) if isinstance(payload.get("services"), dict) else {}).keys())},
        }

    def _self_test_core_payloads(self) -> dict[str, object]:
        checks: dict[str, bool] = {}
        try:
            checks["health"] = self.health_payload().get("status") == "ok"
            checks["scope"] = "targets" in self.scope_payload()
            checks["work_status"] = "summary" in self.work_status_payload()
            checks["models"] = "roles" in self.models_payload()
        except Exception as exc:  # noqa: BLE001 - self-test reports payload failures
            return {"id": "core_payloads", "label": "Core web payloads healthy", "status": "fail", "details": {"error": str(exc), "checks": checks}}
        return {
            "id": "core_payloads",
            "label": "Core web payloads healthy",
            "status": "pass" if all(checks.values()) else "fail",
            "details": checks,
        }

    def _self_test_execution_repair(self) -> dict[str, object]:
        try:
            repaired = self.repair_execution_state()
            running = len(self.store.list_running_task_runs())
            status = "pass" if running == 0 else "warn"
            return {
                "id": "execution_repair",
                "label": "Stale/running task repair status",
                "status": status,
                "details": {"repair": repaired, "running_runs": running},
            }
        except Exception as exc:  # noqa: BLE001 - self-test reports repair failure
            return {"id": "execution_repair", "label": "Stale/running task repair status", "status": "fail", "details": {"error": str(exc)}}

    def _read_cpu_metrics(self) -> dict[str, object]:
        cpu_count = max(1, os.cpu_count() or 1)
        load_1 = load_5 = load_15 = 0.0
        if hasattr(os, "getloadavg"):
            try:
                load_1, load_5, load_15 = os.getloadavg()
            except OSError:
                pass
        percent = None
        try:
            with Path("/proc/stat").open("r", encoding="utf-8") as handle:
                first_line = handle.readline().strip()
            fields = [int(value) for value in first_line.split()[1:]]
            if len(fields) >= 4:
                idle = fields[3] + (fields[4] if len(fields) > 4 else 0)
                total = sum(fields)
                previous = self._cpu_sample
                self._cpu_sample = (idle, total)
                if previous is not None:
                    idle_delta = idle - previous[0]
                    total_delta = total - previous[1]
                    if total_delta > 0:
                        percent = max(0.0, min(100.0, 100.0 * (1.0 - (idle_delta / total_delta))))
        except OSError:
            percent = None
        if percent is None:
            percent = max(0.0, min(100.0, (load_1 / cpu_count) * 100.0))
        memory_total_mb = None
        memory_available_mb = None
        memory_free_mb = None
        try:
            meminfo: dict[str, float] = {}
            with Path("/proc/meminfo").open("r", encoding="utf-8") as handle:
                for line in handle:
                    key, _, remainder = line.partition(":")
                    parts = remainder.strip().split()
                    if not parts:
                        continue
                    try:
                        meminfo[key] = float(parts[0]) / 1024.0
                    except ValueError:
                        continue
            memory_total_mb = meminfo.get("MemTotal")
            memory_available_mb = meminfo.get("MemAvailable")
            memory_free_mb = meminfo.get("MemFree")
        except OSError:
            pass
        if memory_available_mb is None:
            memory_available_mb = memory_free_mb
        memory_percent = None
        if memory_total_mb and memory_available_mb is not None:
            memory_percent = max(0.0, min(100.0, 100.0 * (1.0 - (memory_available_mb / memory_total_mb))))
        memory = {
            "percent": round(memory_percent, 1) if memory_percent is not None else 0.0,
            "used_mb": round(memory_total_mb - memory_available_mb, 1) if memory_total_mb is not None and memory_available_mb is not None else None,
            "available_mb": round(memory_available_mb, 1) if memory_available_mb is not None else None,
            "free_mb": round(memory_free_mb, 1) if memory_free_mb is not None else None,
            "total_mb": round(memory_total_mb, 1) if memory_total_mb is not None else None,
        }
        return {
            "available": True,
            "percent": round(percent, 1),
            "load_1": round(load_1, 2),
            "load_5": round(load_5, 2),
            "load_15": round(load_15, 2),
            "cpu_count": cpu_count,
            "memory": memory,
            "memory_available_mb": round(memory_available_mb, 1) if memory_available_mb is not None else None,
            "memory_free_mb": round(memory_free_mb, 1) if memory_free_mb is not None else None,
            "memory_total_mb": round(memory_total_mb, 1) if memory_total_mb is not None else None,
            "memory_percent": round(memory_percent, 1) if memory_percent is not None else None,
        }

    def _read_network_metrics(self, now: float) -> dict[str, object]:
        try:
            rx_total = 0
            tx_total = 0
            with Path("/proc/net/dev").open("r", encoding="utf-8") as handle:
                for line in handle.readlines()[2:]:
                    name, _, counters = line.partition(":")
                    iface = name.strip()
                    if not iface or iface == "lo":
                        continue
                    fields = counters.split()
                    if len(fields) < 16:
                        continue
                    rx_total += int(fields[0])
                    tx_total += int(fields[8])
        except (OSError, ValueError):
            return {
                "available": False,
                "rx_bytes_per_sec": 0.0,
                "tx_bytes_per_sec": 0.0,
                "rx_label": "0 B/s",
                "tx_label": "0 B/s",
            }
        previous = self._network_sample
        self._network_sample = (rx_total, tx_total, now)
        rx_rate = tx_rate = 0.0
        if previous is not None:
            elapsed = max(0.001, now - previous[2])
            rx_rate = max(0.0, (rx_total - previous[0]) / elapsed)
            tx_rate = max(0.0, (tx_total - previous[1]) / elapsed)
        return {
            "available": True,
            "rx_bytes": rx_total,
            "tx_bytes": tx_total,
            "rx_bytes_per_sec": round(rx_rate, 2),
            "tx_bytes_per_sec": round(tx_rate, 2),
            "rx_label": self._bytes_per_second_label(rx_rate),
            "tx_label": self._bytes_per_second_label(tx_rate),
        }

    def _bytes_per_second_label(self, value: float) -> str:
        units = ("B/s", "KB/s", "MB/s", "GB/s")
        current = float(value)
        unit = units[0]
        for unit in units:
            if current < 1024.0 or unit == units[-1]:
                break
            current /= 1024.0
        if unit == "B/s":
            return f"{int(current)} {unit}"
        return f"{current:.1f} {unit}"

    def _read_gpu_metrics(self) -> dict[str, object]:
        nvidia_smi = shutil.which("nvidia-smi")
        if not nvidia_smi:
            return {
                "available": False,
                "percent": 0.0,
                "memory_percent": 0.0,
                "memory_used_mb": None,
                "memory_free_mb": None,
                "memory_total_mb": None,
                "temperature_c": None,
                "error": "nvidia-smi not found",
            }
        try:
            result = subprocess.run(
                [
                    nvidia_smi,
                    "--query-gpu=utilization.gpu,utilization.memory,memory.used,memory.total,temperature.gpu",
                    "--format=csv,noheader,nounits",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=2,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {
                "available": False,
                "percent": 0.0,
                "memory_percent": 0.0,
                "memory_used_mb": None,
                "memory_free_mb": None,
                "memory_total_mb": None,
                "temperature_c": None,
                "error": str(exc),
            }
        if result.returncode != 0:
            return {
                "available": False,
                "percent": 0.0,
                "memory_percent": 0.0,
                "memory_used_mb": None,
                "memory_free_mb": None,
                "memory_total_mb": None,
                "temperature_c": None,
                "error": result.stderr.strip() or result.stdout.strip() or "nvidia-smi failed",
            }
        line = next((item.strip() for item in result.stdout.splitlines() if item.strip()), "")
        if not line:
            return {
                "available": False,
                "percent": 0.0,
                "memory_percent": 0.0,
                "memory_used_mb": None,
                "memory_free_mb": None,
                "memory_total_mb": None,
                "temperature_c": None,
                "error": "nvidia-smi returned no GPU data",
            }
        parts = [segment.strip() for segment in line.split(",")]
        try:
            utilization = float(parts[0])
            memory_utilization = float(parts[1])
            memory_used = float(parts[2])
            memory_total = float(parts[3])
            temperature = float(parts[4])
        except (IndexError, ValueError):
            return {
                "available": False,
                "percent": 0.0,
                "memory_percent": 0.0,
                "memory_used_mb": None,
                "memory_free_mb": None,
                "memory_total_mb": None,
                "temperature_c": None,
                "error": f"unexpected nvidia-smi output: {line}",
            }
        memory_percent = max(0.0, min(100.0, memory_utilization))
        if memory_total > 0:
            memory_percent = max(0.0, min(100.0, (memory_used / memory_total) * 100.0))
        return {
            "available": True,
            "percent": round(max(0.0, min(100.0, utilization)), 1),
            "memory_percent": round(memory_percent, 1),
            "memory_used_mb": round(memory_used, 1),
            "memory_free_mb": round(max(0.0, memory_total - memory_used), 1),
            "memory_total_mb": round(memory_total, 1),
            "temperature_c": round(temperature, 1),
            "error": None,
        }

    def _cleanup_deleted_paths(self, raw_paths: list[str]) -> None:
        allowed_roots = (self.config.artifacts_dir.resolve(), self.config.checkpoints_dir.resolve())
        seen: set[Path] = set()
        for raw_path in raw_paths:
            path = Path(raw_path)
            try:
                resolved = path.resolve()
            except FileNotFoundError:
                continue
            if not any(root == resolved or root in resolved.parents for root in allowed_roots):
                continue
            if resolved.exists() and resolved.is_file():
                resolved.unlink()
            seen.add(resolved.parent)
        for directory in sorted(seen, key=lambda item: len(item.parts), reverse=True):
            for root in allowed_roots:
                current = directory
                while current != root and root in current.parents:
                    try:
                        current.rmdir()
                    except OSError:
                        break
                    current = current.parent

    def _load_scope_payload(self, path: Path) -> dict[str, object]:
        if path.suffix.lower() == ".json":
            return json.loads(path.read_text())
        lines = [
            line.strip()
            for line in path.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        return {
            "profile": ScopeProfile.HACKERONE.value,
            "targets": [
                {
                    "handle": line,
                    "display_name": line,
                    "in_scope": True,
                    "assets": [{"asset": line, "asset_type": "hostname"}],
                }
                for line in lines
            ],
        }

    def _load_environment_classifier(self, project_root: Path) -> EnvironmentClassifier:
        candidates = [
            project_root / "goal" / "fragments" / "environments.yaml",
            Path(__file__).resolve().parents[2] / "goal" / "fragments" / "environments.yaml",
        ]
        for environment_contract in candidates:
            if not environment_contract.exists():
                continue
            try:
                return EnvironmentClassifier.from_goal_file(environment_contract)
            except Exception:  # noqa: BLE001 - fall back to the next deterministic source.
                continue
        return EnvironmentClassifier.default()

    def _classify_environment(
        self,
        *,
        profile: str,
        resolved_profile: str | None = None,
        payload: dict[str, object] | None = None,
        target_metadata: dict[str, object] | None = None,
        asset_metadata: list[dict[str, object]] | None = None,
    ) -> EnvironmentClassification:
        return self.environment_classifier.classify(
            profile=profile,
            resolved_profile=resolved_profile,
            payload=payload,
            target_metadata=target_metadata,
            asset_metadata=asset_metadata,
        )

    def _default_operator_intent_for_environment(self, classification: EnvironmentClassification) -> str:
        if not classification.upgrade_applied:
            return OperatorIntentRegistry.DEFAULT_INTENT_ID
        if not self._operator_intent_exists(classification.default_intent):
            return OperatorIntentRegistry.DEFAULT_INTENT_ID
        return classification.default_intent

    def _operator_intent_exists(self, intent_id: str) -> bool:
        self._load_operator_intents()
        try:
            self.operator_intents.get(intent_id)
        except KeyError:
            return False
        return True

    def _ensure_profile_default_operator_intent(
        self,
        profile: ScopeProfile,
        *,
        classification: EnvironmentClassification | None = None,
    ) -> None:
        classification = classification or self._classify_environment(profile=profile.value)
        default_intent = self._default_operator_intent_for_environment(classification)
        if default_intent == OperatorIntentRegistry.DEFAULT_INTENT_ID:
            return
        intent = self.operator_intents.get(default_intent)
        session = self.store.get_active_session()
        if session is None:
            self.start_session(profile=profile, environment_classification=classification)
            return
        current_intent = str(session.metadata.get("operator_intent_id") or OperatorIntentRegistry.DEFAULT_INTENT_ID)
        if current_intent != OperatorIntentRegistry.DEFAULT_INTENT_ID:
            return
        session.metadata["operator_intent_id"] = intent.id
        session.metadata["environment_classification"] = classification.as_payload()
        session.updated_at = utc_now()
        self.store.insert_session(session)
        self.store.insert_event(
            EventRecord(
                type=EventType.BOOTSTRAP,
                summary=f"Operator intent defaulted for {profile.value} scope: {intent.id}",
                metadata={
                    "operator_intent": intent.as_payload(),
                    "profile": profile.value,
                    "session_id": session.id,
                    "environment_classification": classification.as_payload(),
                },
            )
        )

    def _asset_metadata_from_entries(self, entries: list[str | dict[str, object]]) -> list[dict[str, object]]:
        metadata: list[dict[str, object]] = []
        for entry in entries:
            if isinstance(entry, dict) and isinstance(entry.get("metadata"), dict):
                metadata.append(dict(entry["metadata"]))
        return metadata

    def _normalize_scope_profile_id(self, value: str) -> str:
        normalized = re.sub(r"[^a-z0-9_]+", "_", str(value).strip().lower())
        normalized = normalized.strip("_")
        if not normalized:
            raise ValueError("scope profile id is required")
        return normalized[:64]

    def _register_modules(self) -> None:
        self.modules.register(
            "security",
            lambda: build_security_mode_services(
                self.store,
                self.catalog,
                self.config,
                self.credentials,
                ai_generate=self._worker_ai_generate,
                active_intent_policy_loader=self.intent_policy,
                active_intent_id_loader=lambda: self.active_operator_intent().id,
            ),
            metadata={"kind": "mode", "default": True},
        )
        self.modules.register(
            "notion",
            lambda: NotionSyncService(self.store, self.credentials, self.event_bus, self.findings_context),
            metadata={"kind": "adapter", "default": True},
        )
        self.modules.register(
            "discord",
            lambda: DiscordNotificationService(self.store, self.credentials, self.event_bus),
            metadata={"kind": "adapter", "default": True},
        )
        self.modules.register(
            "caido",
            lambda: CaidoIntegrationService(self.credentials, self.event_bus),
            metadata={"kind": "adapter", "default": True},
        )

    def _register_worker_runners(self) -> None:
        self.worker_broker.register_runner(
            InProcessWorkerRunner(
                runner_id="security-analysis-runner",
                lane="hot-path",
                supported_routes={
                    ProviderRoute.LOCAL_FAST,
                },
                executor_loader=lambda: self.security.primitive_executor,
                max_concurrency=self.config.autonomy.hot_path_concurrency,
                contract=WorkerContract(
                    name="analysis_hot_contract",
                    supported_roles={AgentRole.ORCHESTRATOR, AgentRole.RECON_WORKER, AgentRole.ANALYSIS_WORKER},
                    preferred_kinds={
                        TaskKind.RECON_SCAN,
                        TaskKind.SERVICE_DISCOVERY,
                        TaskKind.DNS_ENUMERATION,
                        TaskKind.WEB_CONTENT_DISCOVERY,
                        TaskKind.AD_ENUMERATION,
                        TaskKind.KERBEROS_USER_DISCOVERY,
                        TaskKind.ANALYZE_EVIDENCE,
                    },
                    processor="gpu",
                    quality_tier=82,
                ),
            )
        )
        self.worker_broker.register_runner(
            InProcessWorkerRunner(
                runner_id="security-deep-runner",
                lane="hot-path",
                supported_routes={ProviderRoute.LOCAL_DEEP},
                executor_loader=lambda: self.security.primitive_executor,
                max_concurrency=self.config.autonomy.high_risk_concurrency,
                contract=WorkerContract(
                    name="deep_reasoning_contract",
                    supported_roles={AgentRole.EXPLOITATION_WORKER, AgentRole.CHAINING_WORKER},
                    preferred_kinds={
                        TaskKind.KERBEROS_ATTACK_CHECK,
                        TaskKind.CREDENTIALED_ACCESS_CHECK,
                        TaskKind.VERIFY_HYPOTHESIS,
                        TaskKind.CHAIN_CANDIDATES,
                    },
                    processor="gpu",
                    quality_tier=88,
                ),
            )
        )
        self.worker_broker.register_runner(
            InProcessWorkerRunner(
                runner_id="security-code-runner",
                lane="cold-path",
                supported_routes={ProviderRoute.LOCAL_CODE, ProviderRoute.COLD_REVIEW},
                executor_loader=lambda: self.security.primitive_executor,
                max_concurrency=self.config.autonomy.cold_path_concurrency,
                contract=WorkerContract(
                    name="code_cpu_contract",
                    supported_roles={AgentRole.CODE_WORKER},
                    preferred_kinds={TaskKind.EXPLOIT_RESEARCH, TaskKind.POC_APPLICABILITY_VALIDATION},
                    processor="cpu",
                    quality_tier=91,
                ),
            )
        )
        self.worker_broker.register_runner(
            InProcessWorkerRunner(
                runner_id="security-compact-runner",
                lane="compact-path",
                supported_routes={ProviderRoute.LOCAL_COMPACT},
                executor_loader=lambda: self.security.primitive_executor,
                max_concurrency=self.config.autonomy.compact_path_concurrency,
                contract=WorkerContract(
                    name="compact_verifier_contract",
                    supported_roles={AgentRole.MEMORY_WORKER, AgentRole.BEHAVIOR_VERIFIER},
                    preferred_kinds={TaskKind.VERIFY_AGENT_BEHAVIOR, TaskKind.COMPACT_MEMORY},
                    processor="cpu",
                    quality_tier=84,
                ),
            )
        )
        self.worker_broker.register_runner(
            AgentChatPremiumReviewRunner(
                self.agent_chat,
                target_loader=lambda target_id: self.store.get_target(target_id) if target_id else None,
                remote_cost_recorder=self.store.insert_remote_cost,
                max_concurrency=self.config.autonomy.remote_premium_concurrency,
            )
        )
