from __future__ import annotations

from primordial.app.runtime_deps import (
    json,
    LMStudioClient,
    utc_now,
)

class RuntimeSelfTestMixin:
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
