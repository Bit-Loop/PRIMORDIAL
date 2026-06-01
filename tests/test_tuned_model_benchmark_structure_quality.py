from __future__ import annotations

from pathlib import Path
import unittest

from primordial.core.quality.structure import audit_structure


class TunedModelBenchmarkStructureQualityTests(unittest.TestCase):
    def test_tuned_model_benchmark_files_have_no_structure_violations(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "scripts/run_tuned_model_benchmark.py"
            or record.path.startswith("primordial/core/providers/tuned_benchmark")
        ]
        self.assertEqual(records, [])


if __name__ == "__main__":
    unittest.main()
