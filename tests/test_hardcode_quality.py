from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from primordial.core.quality.hardcode import audit_hardcoded_artifacts, main
from tests.support import fixture_ip


class HardcodeQualityTests(unittest.TestCase):
    def test_hardcode_quality_reports_flags_box_names_credentials_and_solve_shortcuts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "solvers" / "candidate.py"
            source.parent.mkdir()
            box_name = "synthetic" + "-box"
            raw_flag = "ctf" + "{synthetic-secret}"
            source.write_text(
                "\n".join(
                    (
                        "if " + "target" + ".name" + " == " + repr(box_name) + ":",
                        "    " + "password" + " = " + repr("Spring2026!"),
                        "    " + "submit" + "(" + repr(raw_flag) + ")",
                    )
                )
                + "\n",
                encoding="utf-8",
            )

            audit = audit_hardcoded_artifacts(root, box_names=(box_name,))

        self.assertEqual(audit.summary["scanned_file_count"], 1)
        self.assertGreaterEqual(audit.summary["violation_count"], 3)
        rule_ids = {record.rule_id for record in audit.records}
        self.assertIn("raw_flag", rule_ids)
        self.assertIn("box_name_literal", rule_ids)
        self.assertIn("credential_literal", rule_ids)
        self.assertIn("challenge_specific_conditional", rule_ids)

    def test_hardcode_quality_skips_runtime_quarantine_archives(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archived = root / "runtime" / "quarantine" / "markdown" / "solver.py"
            archived.parent.mkdir(parents=True)
            archived.write_text("submit(" + repr("ctf" + "{archived-secret}") + ")\n", encoding="utf-8")

            audit = audit_hardcoded_artifacts(root)

        self.assertEqual(audit.summary["scanned_file_count"], 0)
        self.assertEqual(audit.summary["violation_count"], 0)

    def test_hardcode_quality_skips_generated_model_eval_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            generated = root / "artifacts" / "model_eval" / "run" / "model_eval.json"
            generated.parent.mkdir(parents=True)
            generated.write_text(
                '{"transcript": "captured ' + "ctf" + '{generated-artifact}"}\n',
                encoding="utf-8",
            )

            audit = audit_hardcoded_artifacts(root)

        self.assertEqual(audit.summary["scanned_file_count"], 0)
        self.assertEqual(audit.summary["violation_count"], 0)

    def test_hardcode_quality_skips_active_goal_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "codex-goal.instruct").write_text(
                "Example active target: " + fixture_ip(10, 129, 64, 253) + "\n",
                encoding="utf-8",
            )

            audit = audit_hardcoded_artifacts(root)

        self.assertEqual(audit.summary["scanned_file_count"], 0)
        self.assertEqual(audit.summary["violation_count"], 0)

    def test_hardcode_quality_cli_returns_failure_and_writes_json_for_violations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "patch.yaml").write_text(
                "proposed_change: " + repr("submit " + "ctf" + "{hidden-answer}") + "\n",
                encoding="utf-8",
            )
            output_path = root / "hardcode.json"

            result = main(["--root", str(root), "--json", str(output_path)])
            payload = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(result, 1)
        self.assertEqual(payload["summary"]["violation_count"], 1)
        self.assertEqual(payload["records"][0]["rule_id"], "raw_flag")

    def test_hardcode_quality_cli_returns_success_for_clean_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "methodology.yaml").write_text(
                "steps:\n"
                "  - collect scoped evidence\n"
                "  - verify observed service behavior\n",
                encoding="utf-8",
            )
            output_path = root / "hardcode.json"

            result = main(["--root", str(root), "--json", str(output_path)])
            payload = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(result, 0)
        self.assertEqual(payload["summary"]["violation_count"], 0)


if __name__ == "__main__":
    unittest.main()
