from __future__ import annotations

import unittest

from primordial.core.context import ContextEnvelope, ContextSinkValidator


class ContextTaskScopeMetadataTests(unittest.TestCase):
    def test_executable_task_rejects_out_of_scope_metadata(self) -> None:
        for metadata in ({"In scope": "false"}, {"Scope status": "out_of_scope"}):
            with self.subTest(metadata=metadata):
                envelope = ContextEnvelope(
                    ref="task:out-of-scope-service-check",
                    kind="candidate_task",
                    authority="asserted",
                    source_type="tool_output",
                    target_id="target-a",
                    active_generation_id="generation:2",
                    purpose="task_generation",
                    sink="task_metadata",
                    content="Executable task metadata must respect target scope compatibility.",
                    citations=["policy_decision:assisted-lab", "evidence:observed-service"],
                    metadata={
                        "Active intent": "ctf_solve_assisted",
                        "Action class": "Tool execution",
                        "Creates executable task": "true",
                        "Supporting evidence refs": ["evidence:observed-service"],
                        **metadata,
                    },
                )

                result = ContextSinkValidator().validate("task_metadata", [envelope])

                self.assertFalse(result.valid)
                self.assertEqual(result.accepted_refs, [])
                self.assertEqual(result.rejected_refs, ["task:out-of-scope-service-check"])
                self.assertTrue(any("scope" in error.lower() for error in result.errors))


if __name__ == "__main__":
    unittest.main()
