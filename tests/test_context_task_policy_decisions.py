from __future__ import annotations

import unittest

from primordial.core.context import ContextEnvelope, ContextSinkValidator


class ContextTaskPolicyDecisionTests(unittest.TestCase):
    def test_executable_task_rejects_policy_decision_without_known_refs_registry(self) -> None:
        envelope = ContextEnvelope(
            ref="task:unregistered-policy-decision",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Executable task metadata must resolve cited policy decisions.",
            citations=["policy_decision:made-up", "evidence:observed-service"],
            metadata={
                "Active intent": "ctf_solve_assisted",
                "Action class": "Tool execution",
                "Creates executable task": "true",
                "Supporting evidence refs": ["evidence:observed-service"],
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:observed-service"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:unregistered-policy-decision"])
        self.assertTrue(any("known policy decision refs" in error for error in result.errors))

    def test_executable_task_rejects_unresolved_policy_decision_when_known_refs_are_supplied(self) -> None:
        envelope = ContextEnvelope(
            ref="task:fabricated-policy-decision",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Executable task metadata must cite an authoritative policy decision.",
            citations=["policy_decision:made-up", "evidence:observed-service"],
            metadata={
                "Active intent": "ctf_solve_assisted",
                "Action class": "Tool execution",
                "Creates executable task": "true",
                "Supporting evidence refs": ["evidence:observed-service"],
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:observed-service"},
            known_policy_decision_refs={"policy_decision:assisted-lab"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:fabricated-policy-decision"])
        self.assertTrue(any("unresolved policy decision" in error for error in result.errors))
        self.assertTrue(any("policy_decision:made-up" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
