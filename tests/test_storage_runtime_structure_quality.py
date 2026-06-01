from __future__ import annotations

from pathlib import Path
import unittest

from primordial.core.quality.structure import audit_structure


class StorageRuntimeStructureQualityTests(unittest.TestCase):
    def test_insert_model_eval_ledger_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/storage/runtime.py"
            and record.kind == "function"
            and record.name == "insert_model_eval_ledger"
        ]
        self.assertEqual(records, [])

    def test_append_document_chunk_metadata_filters_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/storage/runtime.py"
            and record.kind == "function"
            and record.name == "_append_document_chunk_metadata_filters"
        ]
        self.assertEqual(records, [])

    def test_target_blocking_runtime_record_counts_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/storage/runtime.py"
            and record.kind == "function"
            and record.name == "_target_blocking_runtime_record_counts"
        ]
        self.assertEqual(records, [])

    def test_recover_stale_task_run_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/storage/runtime.py"
            and record.kind == "function"
            and record.name == "recover_stale_task_run"
        ]
        self.assertEqual(records, [])

    def test_block_active_tasks_for_target_in_connection_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/storage/runtime.py"
            and record.kind == "function"
            and record.name == "_block_active_tasks_for_target_in_connection"
        ]
        self.assertEqual(records, [])

    def test_replace_target_scope_assets_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/storage/runtime.py"
            and record.kind == "function"
            and record.name == "replace_target_scope_assets"
        ]
        self.assertEqual(records, [])


if __name__ == "__main__":
    unittest.main()
