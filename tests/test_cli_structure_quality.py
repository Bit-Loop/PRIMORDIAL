from __future__ import annotations

from pathlib import Path
import unittest

from primordial.core.quality.structure import audit_structure


class CliStructureQualityTests(unittest.TestCase):
    def test_cli_build_parser_is_not_oversized(self) -> None:
        records = _records_for("primordial/cli.py", kind="function", name="build_parser")

        self.assertEqual(records, [])

    def test_cli_main_is_not_oversized(self) -> None:
        records = _records_for("primordial/cli.py", kind="function", name="main")

        self.assertEqual(records, [])

    def test_cli_module_is_not_oversized(self) -> None:
        records = _records_for("primordial/cli.py", kind="module")

        self.assertEqual(records, [])

    def test_cli_model_evaluation_formatter_is_not_oversized(self) -> None:
        records = _records_for(
            "primordial/cli_formatters.py",
            kind="function",
            name="_format_model_evaluation",
        )

        self.assertEqual(records, [])


def _records_for(path: str, *, kind: str, name: str | None = None) -> list[object]:
    root = Path(__file__).resolve().parents[1]
    audit = audit_structure(root)
    return [
        record
        for record in audit.records
        if record.path == path
        and record.kind == kind
        and (name is None or record.name == name)
    ]


if __name__ == "__main__":
    unittest.main()
