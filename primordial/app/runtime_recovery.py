from __future__ import annotations

from primordial.app.runtime_deps import (
    build_security_mode_services,
    CaidoIntegrationService,
    DiscordNotificationService,
    NotionSyncService,
    Path,
    register_default_worker_runners,
    TaskStatus,
)

class RuntimeRecoveryMixin:
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
        register_default_worker_runners(
            worker_broker=self.worker_broker,
            executor_loader=lambda: self.security.primitive_executor,
            agent_chat=self.agent_chat,
            target_loader=lambda target_id: self.store.get_target(target_id) if target_id else None,
            remote_cost_recorder=self.store.insert_remote_cost,
            hot_path_concurrency=self.config.autonomy.hot_path_concurrency,
            high_risk_concurrency=self.config.autonomy.high_risk_concurrency,
            cold_path_concurrency=self.config.autonomy.cold_path_concurrency,
            compact_path_concurrency=self.config.autonomy.compact_path_concurrency,
            remote_premium_concurrency=self.config.autonomy.remote_premium_concurrency,
        )
