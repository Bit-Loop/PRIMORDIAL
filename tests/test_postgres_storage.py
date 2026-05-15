from __future__ import annotations

import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from primordial.config import AppConfig
from primordial.core.doctor import dumps_doctor_json, run_doctor
from primordial.core.domain.enums import (
    AgentRole,
    ExternalSyncKind,
    ExternalSyncStatus,
    HandoffStatus,
    MethodologyPhase,
    ScopeProfile,
    TaskKind,
    TaskStatus,
)
from primordial.core.domain.models import ExternalSyncJob, ScopeAsset, Target, Task, TaskHandoff, utc_now
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

    def test_target_scope_replacement_rolls_back_on_mid_save_error(self) -> None:
        target = Target(handle="rollback.htb", display_name="Rollback", profile=ScopeProfile.HACK_THE_BOX)
        self.store.insert_target(target)
        self.store.insert_scope_asset(ScopeAsset(target_id=target.id, asset="rollback.htb", asset_type="domain"))

        with self.assertRaises(KeyError):
            self.store.replace_target_scope_assets(
                handle="rollback.htb",
                display_name="Changed",
                profile=ScopeProfile.HACK_THE_BOX,
                in_scope=False,
                active_ip=None,
                asset_rows=[
                    {"asset": "new.rollback.htb", "asset_type": "domain"},
                    {"asset_type": "domain"},
                ],
            )

        loaded = self.store.get_target_by_handle("rollback.htb", ScopeProfile.HACK_THE_BOX)
        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded.display_name, "Rollback")
        self.assertTrue(loaded.in_scope)
        self.assertEqual({item.asset for item in self.store.list_scope_assets(target.id)}, {"rollback.htb"})

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

    def test_guarded_task_status_update_rejects_stale_precondition(self) -> None:
        task = Task(
            target_id=None,
            phase=MethodologyPhase.RECON,
            kind=TaskKind.RECON_SCAN,
            title="Guard me",
            summary="Guarded transition fixture",
            role=AgentRole.ORCHESTRATOR,
            status=TaskStatus.PENDING,
        )
        self.store.insert_task(task)

        blocked = self.store.update_task_status(
            task.id,
            from_statuses=[TaskStatus.RUNNING],
            to_status=TaskStatus.SUCCEEDED,
            metadata_patch={"should_not_write": True},
        )
        updated = self.store.update_task_status(
            task.id,
            from_statuses=[TaskStatus.PENDING],
            to_status=TaskStatus.BLOCKED,
            metadata_patch={"guarded": True},
        )

        self.assertIsNone(blocked)
        self.assertIsNotNone(updated)
        assert updated is not None
        self.assertEqual(updated.status, TaskStatus.BLOCKED)
        self.assertTrue(updated.metadata["guarded"])

    def test_external_sync_jobs_are_claimed_before_processing(self) -> None:
        target = Target(handle="notion.htb", display_name="Notion", profile=ScopeProfile.HACK_THE_BOX)
        self.store.insert_target(target)
        job = ExternalSyncJob(
            kind=ExternalSyncKind.NOTION,
            target_id=target.id,
            summary="Sync target",
            payload={"target_id": target.id},
            status=ExternalSyncStatus.PENDING,
        )
        self.store.insert_external_sync_job(job)

        claimed = self.store.claim_next_external_sync_job(kind=ExternalSyncKind.NOTION)
        claimed_again = self.store.claim_next_external_sync_job(kind=ExternalSyncKind.NOTION)

        self.assertIsNotNone(claimed)
        assert claimed is not None
        self.assertEqual(claimed.id, job.id)
        self.assertEqual(claimed.status, ExternalSyncStatus.RUNNING)
        self.assertIsNone(claimed_again)

    def test_pending_external_sync_jobs_can_be_failed_in_bulk(self) -> None:
        target = Target(handle="notion.htb", display_name="Notion", profile=ScopeProfile.HACK_THE_BOX)
        self.store.insert_target(target)
        jobs = [
            ExternalSyncJob(
                kind=ExternalSyncKind.NOTION,
                target_id=target.id,
                summary="Sync target",
                payload={"target_id": target.id},
                status=ExternalSyncStatus.PENDING,
            )
            for _ in range(2)
        ]
        for job in jobs:
            self.store.insert_external_sync_job(job)

        failed = self.store.fail_pending_external_sync_jobs(
            kind=ExternalSyncKind.NOTION,
            reason="auth blocked",
            metadata_patch={"auth_blocked": True},
        )
        refreshed = {job.id: job for job in self.store.list_external_sync_jobs(limit=20)}

        self.assertEqual(failed, 2)
        self.assertTrue(all(refreshed[job.id].status == ExternalSyncStatus.FAILED for job in jobs))
        self.assertTrue(all(refreshed[job.id].metadata["auth_blocked"] for job in jobs))

    def test_handoff_consume_and_expire_lifecycle(self) -> None:
        target = Target(handle="handoff.htb", display_name="Handoff", profile=ScopeProfile.HACK_THE_BOX)
        self.store.insert_target(target)
        source_task = Task(
            target_id=target.id,
            phase=MethodologyPhase.RECON,
            kind=TaskKind.RECON_SCAN,
            title="Recon source",
            summary="Produces handoff",
            role=AgentRole.RECON_WORKER,
            status=TaskStatus.SUCCEEDED,
        )
        analysis_task = Task(
            target_id=target.id,
            phase=MethodologyPhase.ANALYSIS,
            kind=TaskKind.ANALYZE_EVIDENCE,
            title="Analysis consumer",
            summary="Consumes handoff",
            role=AgentRole.ANALYSIS_WORKER,
            status=TaskStatus.PENDING,
        )
        self.store.insert_task(source_task)
        self.store.insert_task(analysis_task)
        handoff = TaskHandoff(
            task_id=source_task.id,
            source_agent=AgentRole.RECON_WORKER,
            destination_agent=AgentRole.ANALYSIS_WORKER,
            reason="Analyze recon",
            expected_output_type="analysis",
        )
        expired = TaskHandoff(
            task_id=source_task.id,
            source_agent=AgentRole.RECON_WORKER,
            destination_agent=AgentRole.CHAINING_WORKER,
            reason="Expired handoff",
            expected_output_type="chain",
            deadline_at=utc_now() - timedelta(seconds=1),
        )
        self.store.insert_handoff(handoff)
        self.store.insert_handoff(expired)

        consumed_count = self.store.consume_handoffs_for_task(analysis_task)
        expired_count = self.store.expire_handoffs()
        handoffs = {item.id: item for item in self.store.list_handoffs(limit=10)}

        self.assertEqual(consumed_count, 1)
        self.assertEqual(expired_count, 1)
        self.assertEqual(handoffs[handoff.id].status, HandoffStatus.CONSUMED)
        self.assertEqual(handoffs[expired.id].status, HandoffStatus.EXPIRED)

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
