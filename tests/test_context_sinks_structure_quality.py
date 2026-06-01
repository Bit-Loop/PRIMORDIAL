from __future__ import annotations

from pathlib import Path
import unittest

from primordial.core.quality.structure import audit_structure


class ContextSinksStructureQualityTests(unittest.TestCase):
    def test_context_sinks_module_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]
        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/context/sinks.py"
            and record.kind == "module"
        ]
        self.assertEqual(records, [])

    def test_context_sink_validator_class_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]
        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/context/sinks.py"
            and record.kind == "class"
            and record.name == "ContextSinkValidator"
        ]
        self.assertEqual(records, [])

    def test_context_sink_validator_dispatch_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]
        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/context/sinks.py"
            and record.kind == "function"
            and record.name == "validate"
        ]
        self.assertEqual(records, [])

    def test_context_known_source_refs_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]
        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/context/sinks.py"
            and record.kind == "function"
            and record.name == "_context_known_source_refs"
        ]
        self.assertEqual(records, [])

    def test_prompt_sink_validator_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]
        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/context/sinks.py"
            and record.kind == "function"
            and record.name == "_validate_prompt_sink"
        ]
        self.assertEqual(records, [])


if __name__ == "__main__":
    unittest.main()
