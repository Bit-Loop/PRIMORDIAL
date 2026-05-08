from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from primordial.config import AppConfig
from primordial.core.doctor import dumps_doctor_json, run_doctor
from primordial.core.domain.enums import AgentRole, MethodologyPhase, ScopeProfile, TaskKind, TaskStatus
from primordial.core.domain.models import Target, Task
from primordial.core.storage.runtime import RuntimeStore


class PostgresStorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        config = AppConfig.from_env(project_root=Path(self.temp_dir.name))
        self.store = RuntimeStore(config.database_url, schema=config.database_schema)
        self.store.initialize()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_jsonb_settings_round_trip(self) -> None:
        self.store.set_setting("jsonb-check", {"nested": {"ok": True}, "items": [1, 2, 3]})

        self.assertEqual(
            self.store.get_setting("jsonb-check"),
            {"nested": {"ok": True}, "items": [1, 2, 3]},
        )

    def test_target_profile_handle_uniqueness_updates_existing_row(self) -> None:
        target = Target(handle="same.htb", display_name="Old", profile=ScopeProfile.HACK_THE_BOX)
        self.store.insert_target(target)
        target.display_name = "New"
        self.store.insert_target(target)

        rows = self.store.list_targets()
        loaded = self.store.get_target_by_handle("same.htb", ScopeProfile.HACK_THE_BOX)

        self.assertEqual(len(rows), 1)
        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded.display_name, "New")

    def test_task_claim_uses_postgres_pending_locking(self) -> None:
        task = Task(
            target_id=None,
            phase=MethodologyPhase.RECON,
            kind=TaskKind.RECON_SCAN,
            title="Claim me",
            summary="Pending task",
            role=AgentRole.ORCHESTRATOR,
            status=TaskStatus.PENDING,
        )
        self.store.insert_task(task)

        claimed = self.store.claim_next_pending_task()
        claimed_again = self.store.claim_next_pending_task()

        self.assertIsNotNone(claimed)
        assert claimed is not None
        self.assertEqual(claimed.id, task.id)
        self.assertEqual(claimed.status, TaskStatus.RUNNING)
        self.assertIsNone(claimed_again)

    def test_model_eval_ledger_round_trip(self) -> None:
        run_id = self.store.insert_model_eval_ledger(
            summary={
                "providers": ["ollama"],
                "models": ["ollama/model-a"],
                "recommendations": {"local_fast": "ollama/model-a"},
                "aggregate_rows": [
                    {
                        "provider": "ollama",
                        "model": "model-a",
                        "model_id": "ollama/model-a",
                        "aggregate_score": 0.75,
                    }
                ],
                "results": [{"role": "local_fast", "model_id": "ollama/model-a", "passed": True}],
            }
        )

        metrics = self.store.latest_model_eval_role_metrics()
        history = self.store.list_model_eval_history()

        self.assertIn("local_fast", metrics)
        self.assertEqual(metrics["local_fast"]["run_id"], run_id)
        self.assertEqual(metrics["local_fast"]["aggregate_score"], 0.75)
        self.assertEqual(history[0]["id"], run_id)

    def test_vector_extension_is_installed(self) -> None:
        with self.store.connect() as connection:
            row = connection.execute("SELECT extname FROM pg_extension WHERE extname = %s", ("vector",)).fetchone()

        self.assertIsNotNone(row)
        assert row is not None
        self.assertEqual(row["extname"], "vector")

    def test_doctor_reports_ready_postgres_runtime(self) -> None:
        payload = run_doctor(project_root=Path(self.temp_dir.name))
        checks = {check["id"]: check for check in payload["checks"]}

        self.assertEqual(checks["db_reachable"]["status"], "pass")
        self.assertEqual(checks["pgvector_installed"]["status"], "pass")
        self.assertEqual(checks["schema_version"]["status"], "pass")
        self.assertIn('"ok"', dumps_doctor_json(payload))

class RuntimeStorageStaticTests(unittest.TestCase):
    def test_doctor_reports_missing_database_url(self) -> None:
        with patch.dict("os.environ", {"PRIMORDIAL_DATABASE_URL": "", "PRIMORDIAL_TEST_DATABASE_URL": ""}):
            payload = run_doctor(project_root=Path(__file__).resolve().parents[1])
        checks = {check["id"]: check for check in payload["checks"]}

        self.assertFalse(payload["ok"])
        self.assertEqual(checks["db_reachable"]["status"], "fail")

    def test_runtime_store_has_no_sqlite_compatibility_layer(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "primordial/core/storage/runtime.py").read_text()
        banned_tokens = [
            "_translate_sql",
            "_translate_upsert",
            "INSERT OR REPLACE",
            "BEGIN IMMEDIATE",
            "date('now')",
            "target_id IS %s",
        ]

        for token in banned_tokens:
            self.assertNotIn(token, source)
