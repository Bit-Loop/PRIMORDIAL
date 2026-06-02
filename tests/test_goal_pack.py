from __future__ import annotations

import io
from contextlib import redirect_stdout
import unittest

from tools import goal_pack


class GoalPackRetirementTests(unittest.TestCase):
    def test_goal_pack_fails_closed_for_all_pack_lifecycle_commands(self) -> None:
        for args in (
            ["status"],
            ["preflight"],
            ["finish", "--skip-validation", "--no-push", "--no-switch"],
        ):
            with self.subTest(args=args):
                result, output = _run_goal_pack(*args)

                self.assertEqual(result, 1)
                self.assertIn("goal_pack is retired", output)
                self.assertIn("generated packs", output)
                self.assertIn("milestone bookkeeping", output)


def _run_goal_pack(*args: str) -> tuple[int, str]:
    output = io.StringIO()
    with redirect_stdout(output):
        result = goal_pack.main(list(args))
    return result, output.getvalue()


if __name__ == "__main__":
    unittest.main()
