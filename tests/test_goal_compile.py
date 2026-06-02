from __future__ import annotations

import io
from contextlib import redirect_stdout
from pathlib import Path
import unittest

from tools import goal_compile


REPO_ROOT = Path(__file__).resolve().parents[1]


class GoalCompileRetirementTests(unittest.TestCase):
    def test_goal_compile_fails_closed_for_generated_goal_commands(self) -> None:
        for args in (
            ["--list"],
            ["--check"],
            ["--verify-generated"],
            ["--slice-pack", "compiler-bootstrap"],
            ["--from-current"],
            ["--advance"],
        ):
            with self.subTest(args=args):
                result, output = _run_goal_compile(*args)

                self.assertEqual(result, 1)
                self.assertIn("goal_compile is retired", output)
                self.assertIn("runtime source behavior", output)

    def test_compact_instruct_contract_stays_under_model_prompt_budget(self) -> None:
        instruct = (REPO_ROOT / "codex-goal.instruct").read_text(encoding="utf-8")

        self.assertLess(len(instruct), 4_000)
        self.assertIn("Implementation comes first.", instruct)
        self.assertIn("Do not use formal workflow schemes", instruct)
        self.assertIn("completion-verifier layers", instruct)
        self.assertIn("Start from missing source behavior", instruct)


def _run_goal_compile(*args: str) -> tuple[int, str]:
    output = io.StringIO()
    with redirect_stdout(output):
        result = goal_compile.main(list(args))
    return result, output.getvalue()


if __name__ == "__main__":
    unittest.main()
