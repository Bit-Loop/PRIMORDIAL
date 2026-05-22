from __future__ import annotations

import importlib
import unittest

from primordial.core.context import is_operational_context_purpose


class ContextOperationalPurposeTests(unittest.TestCase):
    def test_operational_purpose_contract_lives_in_dedicated_module(self) -> None:
        purposes = importlib.import_module("primordial.core.context.purposes")
        context = importlib.import_module("primordial.core.context")

        self.assertIs(context.OPERATIONAL_CONTEXT_PURPOSES, purposes.OPERATIONAL_CONTEXT_PURPOSES)
        self.assertIs(context.is_operational_context_purpose, purposes.is_operational_context_purpose)

    def test_planner_uncertainty_review_is_operational_context_purpose(self) -> None:
        self.assertTrue(is_operational_context_purpose("planner_uncertainty_review"))
        self.assertTrue(is_operational_context_purpose("Planner uncertainty review"))

    def test_export_alias_is_operational_context_purpose(self) -> None:
        self.assertTrue(is_operational_context_purpose("export"))
        self.assertTrue(is_operational_context_purpose("Export"))

    def test_durable_sink_aliases_are_operational_context_purposes(self) -> None:
        for purpose in ("evidence", "finding", "report", "task metadata"):
            with self.subTest(purpose=purpose):
                self.assertTrue(is_operational_context_purpose(purpose))

    def test_operator_answer_is_operational_context_purpose(self) -> None:
        self.assertTrue(is_operational_context_purpose("operator_answer"))
        self.assertTrue(is_operational_context_purpose("Operator answer"))

    def test_notification_and_ctf_benchmark_are_operational_context_purposes(self) -> None:
        self.assertTrue(is_operational_context_purpose("notification"))
        self.assertTrue(is_operational_context_purpose("Notification"))
        self.assertTrue(is_operational_context_purpose("ctf_benchmark"))
        self.assertTrue(is_operational_context_purpose("CTF benchmark"))

    def test_typed_prompt_purposes_are_operational_context_purposes(self) -> None:
        self.assertTrue(is_operational_context_purpose("methodology_hint"))
        self.assertTrue(is_operational_context_purpose("Methodology hint"))
        self.assertTrue(is_operational_context_purpose("vuln_hint"))
        self.assertTrue(is_operational_context_purpose("Vuln hint"))
        self.assertTrue(is_operational_context_purpose("patch_planning"))
        self.assertTrue(is_operational_context_purpose("Patch planning"))


if __name__ == "__main__":
    unittest.main()
