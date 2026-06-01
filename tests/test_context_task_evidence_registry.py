from __future__ import annotations

import unittest

from primordial.core.context import ContextEnvelope, ContextSinkValidator


class ContextTaskEvidenceRegistryTests(unittest.TestCase):
    def test_executable_task_rejects_supporting_evidence_without_known_evidence_registry(self) -> None:
        envelope = ContextEnvelope(
            ref="task:fabricated-evidence-no-registry",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Executable task metadata must resolve supporting evidence against a registry.",
            citations=["policy_decision:assisted-lab", "evidence:made-up"],
            metadata={
                "Active intent": "ctf_solve_assisted",
                "Action class": "Tool execution",
                "Creates executable task": "true",
                "Supporting evidence refs": ["evidence:made-up"],
            },
        )

        result = ContextSinkValidator().validate("task_metadata", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:fabricated-evidence-no-registry"])
        self.assertTrue(any("known evidence" in error.lower() for error in result.errors))


if __name__ == "__main__":
    unittest.main()
