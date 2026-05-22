from __future__ import annotations

import unittest

from primordial.core.context import ContextEnvelope, ContextSinkValidator


class ContextTaskProfileSourceTests(unittest.TestCase):
    def test_profile_source_types_cannot_originate_executable_task_metadata(self) -> None:
        for source_type in ("engagement_profile", "profile_label", "scope_profile"):
            with self.subTest(source_type=source_type):
                envelope = ContextEnvelope(
                    ref=f"task:{source_type}-credential-validation",
                    kind="candidate_task",
                    authority="asserted",
                    source_type=source_type,
                    target_id="target-a",
                    active_generation_id="generation:2",
                    purpose="task_generation",
                    sink="task_metadata",
                    content="Profile context must not originate executable task metadata authority.",
                    citations=["policy_decision:assisted-lab", "evidence:credential-artifact"],
                    metadata={
                        "Active intent": "ctf_solve_assisted",
                        "Action class": "Credential validation",
                        "Creates executable task": "true",
                        "Supporting evidence refs": ["evidence:credential-artifact"],
                    },
                )

                result = ContextSinkValidator().validate(
                    "task_metadata",
                    [envelope],
                    known_evidence_refs={"evidence:credential-artifact"},
                )

                self.assertFalse(result.valid)
                self.assertEqual(result.accepted_refs, [])
                self.assertEqual(result.rejected_refs, [f"task:{source_type}-credential-validation"])
                self.assertTrue(any("profile label" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
