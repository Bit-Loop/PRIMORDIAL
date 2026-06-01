from __future__ import annotations

from primordial.app.runtime_deps import (
    _SCHEMA_VERSION,
    CaidoIntegrationService,
    DiscordNotificationService,
    EnvironmentClassification,
    EventRecord,
    EventType,
    MethodologyName,
    NotionSyncService,
    OperatorIntentRegistry,
    RuntimeSignal,
    ScopeProfile,
    SecurityModeServices,
    Session,
)

class RuntimeLifecycleMixin:
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
