from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import re
from threading import RLock
import shutil
import subprocess
import time

from primordial.adapters.caido import CaidoIntegrationService
from primordial.adapters.discord import DiscordNotificationService
from primordial.adapters.notion import NotionSyncService
from primordial.core.config import AppConfig
from primordial.core.credentials import CredentialStore
from primordial.core.domain.enums import (
    AgentRole,
    EvidenceType,
    EventType,
    InterestStatus,
    MethodologyName,
    ProviderRoute,
    ScopeProfile,
    TaskKind,
    TaskRunStatus,
    TaskStatus,
    VerificationStatus,
)
from primordial.core.domain.models import (
    DashboardSnapshot,
    EventRecord,
    EvidenceRecord,
    Finding,
    Interest,
    Note,
    OperatorMessage,
    ScopeAsset,
    Session,
    Target,
    json_ready,
    utc_now,
)
from primordial.core.events.bus import EventBus, RuntimeSignal
from primordial.core.findings_context import FindingsContextService
from primordial.core.modules.registry import ModuleRegistry
from primordial.core.orchestration.policy import PolicyEngine
from primordial.core.orchestration.verifier import BehaviorVerifier
from primordial.core.orchestration.workflow import WorkflowOrchestrator
from primordial.core.primitives.catalog import PrimitiveCatalog
from primordial.core.providers.router import ProviderRouter
from primordial.core.providers.ollama import OllamaClient
from primordial.core.providers.model_eval import ModelEvaluationService
from primordial.core.recovery.crash_journal import CrashJournal
from primordial.core.recovery.resume_tracker import ResumeTracker
from primordial.core.providers.scheduler import ModelScheduler
from primordial.core.skills import RuntimeSkillRegistry
from primordial.core.storage.runtime import RuntimeStore
from primordial.core.validation import build_default_validation_registry
from primordial.core.workers import InProcessWorkerRunner, WorkerBroker, WorkerContract
from primordial.modes.security.module import SecurityModeServices, build_security_mode_services


class PrimordialRuntime:
    EXECUTION_MODE_SETTING = "execution_mode"
    EXECUTION_MODE_INTERVAL_SETTING = "execution_mode_interval_seconds"
    EXECUTION_MODES = {"tick", "continuous"}
    DEFAULT_EXECUTION_INTERVAL_SECONDS = 30
    RUNTIME_TUNING_SETTING = "runtime_tuning"
    DEFAULT_WORKER_AI_TIMEOUT_SECONDS_GPU = 120
    DEFAULT_WORKER_AI_TIMEOUT_SECONDS_CPU = 300
    DEFAULT_STALE_RUN_TIMEOUT_SECONDS = 3600
    MIN_GPU_AI_TIMEOUT_SECONDS = 15
    MIN_CPU_AI_TIMEOUT_SECONDS = 30
    MIN_STALE_RUN_TIMEOUT_SECONDS = 60
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
        self.store = RuntimeStore(config.database_path)
        self.credentials = CredentialStore(config.credentials_path)
        self.catalog = PrimitiveCatalog()
        self.event_bus = EventBus()
        self.modules = ModuleRegistry(self.event_bus)
        self.crash_journal = CrashJournal(config.crash_journal_path)
        self.policy = PolicyEngine(
            config.autonomy,
            credentials_status_loader=self.credentials_payload,
            daily_remote_cost_loader=self.store.get_daily_remote_cost_usd,
        )
        self.router = ProviderRouter(config.topology)
        self.ollama = OllamaClient()
        self.model_scheduler = ModelScheduler(config.autonomy)
        self.verifier = BehaviorVerifier()
        self.validation = build_default_validation_registry()
        self.skills = RuntimeSkillRegistry(config.skills_dir)
        self.findings_context = FindingsContextService(config.findings_dir, config.notion_exports_dir)
        self.resume_tracker = ResumeTracker(self.store, self.event_bus)
        self.worker_broker = WorkerBroker(self.event_bus)
        self._metrics_lock = RLock()
        self._cpu_sample: tuple[int, int] | None = None
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
        self.repair_execution_state()
        for target in self.store.list_targets():
            self.findings_context.ensure_target(target)
        self.store.insert_event(
            EventRecord(
                type=EventType.BOOTSTRAP,
                summary="Primordial runtime initialized",
                metadata={
                    "autonomy_mode": self.config.autonomy.mode.value,
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
    ) -> Session:
        self.store.pause_active_sessions()
        session = Session(
            methodology=methodology,
            profile=profile,
            autonomy_mode=self.config.autonomy.mode.value,
            title=title,
        )
        self.store.insert_session(session)
        self.store.insert_event(
            EventRecord(
                type=EventType.SESSION_STARTED,
                summary=f"Session started: {title}",
                metadata={"methodology": methodology.value, "profile": profile.value},
            )
        )
        return session

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
        payload_profile = self.resolve_scope_profile(str(profile or payload.get("profile", ScopeProfile.HACKERONE.value)))
        targets = payload.get("targets", [])
        if not isinstance(targets, list):
            raise ValueError("scope payload targets must be a list")
        session = self.store.get_active_session() or self.start_session(profile=payload_profile)
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
                },
            )
        )
        return {
            "source": source_name,
            "profile": payload_profile.value,
            "session_id": session.id,
            "targets_imported": imported_targets,
            "assets_imported": imported_assets,
        }

    def run_tick(self, max_executions: int = 3):
        report = self.workflow.tick(max_executions=max_executions)
        self.process_external_queues()
        return report

    def repair_execution_state(self) -> dict[str, int]:
        recovered_runs = self.workflow.recover_stale_execution_state(limit=500)
        resumed_tasks = self.resume_tracker.resume_due_tasks(limit=200)
        return {"recovered_runs": recovered_runs, "resumed_tasks": resumed_tasks}

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
        return {
            "gpu_ai_timeout_seconds": gpu_timeout,
            "cpu_ai_timeout_seconds": cpu_timeout,
            "stale_run_timeout_seconds": stale_timeout,
            "defaults": {
                "gpu_ai_timeout_seconds": self.DEFAULT_WORKER_AI_TIMEOUT_SECONDS_GPU,
                "cpu_ai_timeout_seconds": self.DEFAULT_WORKER_AI_TIMEOUT_SECONDS_CPU,
                "stale_run_timeout_seconds": self.DEFAULT_STALE_RUN_TIMEOUT_SECONDS,
            },
            "minimums": {
                "gpu_ai_timeout_seconds": self.MIN_GPU_AI_TIMEOUT_SECONDS,
                "cpu_ai_timeout_seconds": self.MIN_CPU_AI_TIMEOUT_SECONDS,
                "stale_run_timeout_seconds": self.MIN_STALE_RUN_TIMEOUT_SECONDS,
            },
        }

    def update_runtime_tuning(
        self,
        *,
        gpu_ai_timeout_seconds: int | None = None,
        cpu_ai_timeout_seconds: int | None = None,
        stale_run_timeout_seconds: int | None = None,
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
        if approved:
            self.run_tick(max_executions=1)
        return task

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
                display_name=display_name or handle,
                profile=profile,
                in_scope=in_scope,
                metadata=dict(metadata or {}),
            )
        self.store.insert_target(target)
        self.findings_context.ensure_target(target)

        normalized_assets = assets or [handle]
        for asset_entry in normalized_assets:
            if isinstance(asset_entry, dict):
                raw_asset = str(asset_entry["asset"])
                asset_type = str(asset_entry.get("asset_type", self._infer_asset_type(raw_asset)))
                asset_metadata = dict(asset_entry.get("metadata", {}))
            else:
                raw_asset = str(asset_entry)
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
        existing = self.store.get_target_by_handle(handle, profile)
        if existing is None:
            target = self.register_target(
                handle=handle,
                display_name=display_name or handle,
                profile=profile,
                in_scope=in_scope,
                assets=[],
                emit_event=False,
            )
        else:
            target = existing
            target.display_name = display_name or target.display_name
            target.in_scope = in_scope
            target.updated_at = utc_now()
            self.store.insert_target(target)

        self.store.delete_scope_assets_for_target(target.id)

        for row in asset_rows:
            raw_asset = str(row["asset"]).strip()
            if not raw_asset:
                continue
            asset_type = str(row.get("asset_type") or self._infer_asset_type(raw_asset))
            meta: dict[str, object] = {
                "ports": str(row.get("ports") or "*"),
                "scope_rule": str(row.get("scope_rule") or "allow"),
                "operator_managed": True,
            }
            self.store.insert_scope_asset(
                ScopeAsset(
                    target_id=target.id,
                    asset=raw_asset,
                    asset_type=asset_type,
                    metadata=meta,
                )
            )

        if active_ip:
            target = self.set_target_active_ip(target, active_ip, source="scope_editor")

        self.findings_context.ensure_target(target)
        self.store.insert_event(
            EventRecord(
                type=EventType.SCOPE_UPDATED,
                summary=f"Scope assets replaced for {target.handle}: {len(asset_rows)} asset(s)",
                target_id=target.id,
                metadata={"asset_count": len(asset_rows), "profile": profile.value},
            )
        )
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
        deletion = self.store.delete_target_cascade(target.id)
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
            if has_credentialed_capability and not lab_credentials_configured and self._target_has_remote_admin_surface(evidence):
                blockers.append(
                    {
                        "target": target.handle,
                        "kind": "missing_lab_credentials",
                        "summary": (
                            f"`{target.handle}` has SMB/WinRM-like services, but lab username/password are not configured."
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
        return any(self._evidence_has_port(evidence, port) for port in (445, 5985, 5986))

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

    def ask_operator_ai(self, message: str, *, target: str | None = None) -> dict[str, object]:
        self.repair_execution_state()
        question = message.strip()
        if not question:
            raise ValueError("message is required")
        target_record = self._resolve_target_reference(target)
        route_model = self.config.topology.local_deep
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
            metadata = {
                "ok": True,
                "mode": "deterministic_state_answer",
                "route_model": route_model,
                "ai_review_attempted": True,
            }
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
                response = self.ollama.generate(
                    model=route_model,
                    system=system,
                    prompt=prompt,
                    num_gpu=route_num_gpu,
                )
                assistant_body = response.text
                metadata = {
                    "elapsed_seconds": response.elapsed_seconds,
                    "ok": True,
                    "mode": "local_model",
                    "route_num_gpu": route_num_gpu,
                }
                if self._operator_answer_violates_contract(assistant_body):
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

    def health_payload(self) -> dict[str, object]:
        return {
            "status": "ok",
            "runtime_dir": str(self.config.runtime_dir),
            "database_path": str(self.config.database_path),
            "autonomy_mode": self.config.autonomy.mode.value,
            "active_modules": self.modules.active_modules(),
            "targets": len(self.store.list_targets()),
            "skills": len(self.skills.list()),
            "findings_dir": str(self.config.findings_dir),
            "notion_exports_dir": str(self.config.notion_exports_dir),
        }

    def credentials_payload(self) -> dict[str, object]:
        return self.credentials.status()

    def skills_payload(self, *, include_body: bool = False) -> dict[str, object]:
        return self.skills.payload(include_body=include_body)

    def scope_profiles_payload(self) -> dict[str, object]:
        builtins = [
            {
                "id": ScopeProfile.HACK_THE_BOX.value,
                "label": "Hack The Box",
                "base_profile": ScopeProfile.HACK_THE_BOX.value,
                "description": "Lab/CTF profile. Allows HTB-style workflows while still blocking DoS and unsafe primitives.",
                "builtin": True,
            },
            {
                "id": ScopeProfile.HACKERONE.value,
                "label": "HackerOne",
                "base_profile": ScopeProfile.HACKERONE.value,
                "description": "Bug bounty profile. Requires stricter scope and program-rule awareness.",
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

    def caido_status_payload(self, *, check_health: bool = False) -> dict[str, object]:
        if not self.credentials.get("caido", "graphql_url") or not self.credentials.get("caido", "api_token"):
            return CaidoIntegrationService(self.credentials, self.event_bus).status(check_health=False)
        return self.caido.status(check_health=check_health)

    def models_payload(self) -> dict[str, object]:
        installed = self.ollama.list_models()
        selected = self._current_model_roles()
        processors = self._current_model_role_processors()
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
                }
            )
        return {
            "ollama": {
                "ok": installed.ok,
                "base_url": self.ollama.base_url,
                "error": installed.error,
            },
            "available_models": available_models,
            "roles": roles,
        }

    def update_model_roles(
        self,
        selections: dict[str, str],
        processors: dict[str, str] | None = None,
    ) -> dict[str, object]:
        current = self._current_model_roles()
        current_processors = self._current_model_role_processors()
        installed = self.ollama.list_models()
        installed_models = set(installed.models)
        changed: dict[str, str] = {}
        for role, model in selections.items():
            if role not in self.MODEL_ROLE_CONFIG:
                raise ValueError(f"unsupported model role: {role}")
            selected = str(model).strip()
            if not selected:
                continue
            if installed.ok and selected not in installed_models:
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
        self._apply_model_roles(current)
        self.store.insert_event(
            EventRecord(
                type=EventType.BOOTSTRAP,
                summary="Model role mapping updated",
                metadata={"changed": changed, "processor_changes": processor_changes},
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
    ) -> dict[str, object]:
        selected_processor = str(processor).strip().lower()
        if selected_processor not in {"cpu", "gpu"}:
            raise ValueError("processor must be cpu or gpu")
        evaluator = ModelEvaluationService(self.ollama)
        summary = evaluator.evaluate(
            models=models,
            limit=limit,
            include_outputs=include_outputs,
            num_gpu=self._processor_num_gpu(selected_processor),
        )
        payload = summary.as_payload()
        self.store.insert_event(
            EventRecord(
                type=EventType.BOOTSTRAP,
                summary="Model evaluation completed",
                metadata={
                    "models": payload["models"],
                    "recommendations": payload["recommendations"],
                    "processor": selected_processor,
                },
            )
        )
        return payload

    def warm_model_routes(self, *, keep_alive: str = "8h") -> dict[str, object]:
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
        if not self.ollama.is_reachable(timeout_seconds=1.5):
            return None
        model = task.provider_model or self.router.select_route(task).model_name
        role = self._model_role_for_route(task.provider_route)
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
        if not isinstance(response.text, str):
            return None
        text = response.text.strip()
        if not text or self._operator_answer_violates_contract(text):
            return None
        elapsed = response.elapsed_seconds if isinstance(response.elapsed_seconds, int | float) else None
        return {"model": str(response.model), "text": text, "elapsed_seconds": elapsed}

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
        outcome = self.credentials.update_service("discord", {"webhook_url": webhook_url or ""})
        self.store.insert_event(
            EventRecord(
                type=EventType.CREDENTIAL_UPDATED,
                summary="Discord credentials updated",
                metadata={"service": "discord", "changed": outcome["changed"]},
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
        values = {
            "username": username or "",
            "password": password or "",
            "domain": domain or "",
        }
        outcome = self.credentials.update_service("lab", values)
        self.store.insert_event(
            EventRecord(
                type=EventType.CREDENTIAL_UPDATED,
                summary="Lab credentials updated",
                metadata={"service": "lab", "changed": outcome["changed"]},
            )
        )
        return self.credentials_payload()

    def set_caido_credentials(
        self,
        *,
        graphql_url: str | None = None,
        api_token: str | None = None,
    ) -> dict[str, object]:
        values = {
            "graphql_url": graphql_url or "",
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
        if service not in {"notion", "discord", "lab", "caido"}:
            raise ValueError("service must be one of: notion, discord, lab, caido")
        removed = self.credentials.clear_service(service)
        self.store.insert_event(
            EventRecord(
                type=EventType.CREDENTIAL_CLEARED,
                summary=f"{service.title()} credentials cleared",
                metadata={"service": service, "removed": removed},
            )
        )
        return self.credentials_payload()

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
                "- No target is selected. Ask with a target handle, for example `--target pirate.htb`, "
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

    def _operator_answer_violates_contract(self, body: str) -> bool:
        lowered = body.lower()
        unsupported_patterns = (
            "thought process",
            "DDoS",
            "denial of service",
            "ethical considerations",
            "as an ai",
            "always ensure you have",
        )
        return any(pattern in lowered for pattern in unsupported_patterns)

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
        blockers = self._deterministic_blockers(
            flag_hits,
            findings,
            potential_paths,
            capabilities,
            lab_credentials_configured,
        )
        next_actions = self._deterministic_next_actions(current_evidence, interests, findings, capabilities)
        capability_gaps = self._deterministic_capability_gaps(current_evidence, evidence_kinds, capabilities)
        methodology_state = self._live_methodology_state_payload(target) if target else {}
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
        sections = [
            "**Facts**\n"
            + "\n".join(f"- {fact}" for fact in facts)
            + f"\n- Recent task states: {task_summary}"
            + f"\n- Registered primitives: {', '.join(sorted(primitive_names)) or 'none'}"
        ]
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
        elif not lab_credentials_configured and not flag_hits:
            blockers.append("Lab username/password are not configured, so credentialed SMB/WinRM verification cannot run.")
        if potential_paths and not self._poc_adaptation_available(capabilities):
            blockers.append(
                "Retained public PoC candidates exist, but no gated PoC applicability/adaptation primitive is registered."
            )
        return blockers

    def _lab_credentials_configured(self) -> bool:
        username = self.credentials.get("lab", "username")
        password = self.credentials.get("lab", "password")
        return bool(username and password)

    def _deterministic_next_actions(
        self,
        evidence: list[EvidenceRecord],
        interests: list[Interest],
        findings: list[Finding],
        capabilities: set[str],
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
        ):
            actions.append((0.78, "Run evidence-backed Searchsploit research. Prerequisite: service/version terms from stored recon evidence."))
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
        if self._has_any_capability(capabilities, "credentialed-access-check", "smb-session", "winrm") and not lab_credentials_configured:
            actions.append((0.72, "Configure lab credentials before credentialed SMB/WinRM verification. Prerequisite: operator-provided username/password."))

        return [f"{text} Confidence: {score:.2f}." for score, text in sorted(actions, reverse=True)[:5]]

    def _deterministic_capability_gaps(
        self,
        evidence: list[EvidenceRecord],
        evidence_kinds: set[str],
        capabilities: set[str],
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
        if not self._has_any_capability(capabilities, "winrm", "smb-session", "flag-collection", "credential-use"):
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
        import logging
        result = self.ollama.list_models()
        if not result.ok:
            logging.getLogger(__name__).warning(
                "Ollama unreachable at startup — cannot validate topology models: %s", result.error
            )
            return
        installed = set(result.models)
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
        return {
            "available": True,
            "percent": round(percent, 1),
            "load_1": round(load_1, 2),
            "load_5": round(load_5, 2),
            "load_15": round(load_15, 2),
            "cpu_count": cpu_count,
        }

    def _read_gpu_metrics(self) -> dict[str, object]:
        nvidia_smi = shutil.which("nvidia-smi")
        if not nvidia_smi:
            return {
                "available": False,
                "percent": 0.0,
                "memory_percent": 0.0,
                "memory_used_mb": None,
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
            InProcessWorkerRunner(
                runner_id="security-premium-runner",
                lane="remote-premium",
                supported_routes={ProviderRoute.REMOTE_PREMIUM},
                executor_loader=lambda: self.security.primitive_executor,
                max_concurrency=self.config.autonomy.remote_premium_concurrency,
                contract=WorkerContract(
                    name="premium_review_contract",
                    supported_roles={AgentRole.CLAUDE_REVIEWER},
                    preferred_kinds={TaskKind.REVIEW_PREMIUM_ESCALATION},
                    processor="cpu",
                    quality_tier=95,
                ),
            )
        )
