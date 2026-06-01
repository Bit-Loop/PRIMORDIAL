from __future__ import annotations

from pathlib import Path
import unittest

from primordial.core.quality.structure import audit_structure


class LMStudioTuningStructureQualityTests(unittest.TestCase):
    def test_lmstudio_tuning_module_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/providers/lmstudio_tuning.py"
            and record.kind == "module"
        ]
        self.assertEqual(records, [])

    def test_performance_tuner_class_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/providers/lmstudio_tuning.py"
            and record.kind == "class"
            and record.name == "LMStudioPerformanceTuner"
        ]
        self.assertEqual(records, [])

    def test_measure_config_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/providers/lmstudio_tuning.py"
            and record.kind == "function"
            and record.name == "_measure_config"
        ]
        self.assertEqual(records, [])

    def test_tune_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/providers/lmstudio_tuning.py"
            and record.kind == "function"
            and record.name == "tune"
        ]
        self.assertEqual(records, [])


if __name__ == "__main__":
    unittest.main()
