from __future__ import annotations

import unittest

from primordial.core.context import ContextAssembler, ContextEnvelope


class ContextAssemblerTaskMetadataTests(unittest.TestCase):
    def test_assembler_omits_candidate_tasks_with_unresolved_supporting_evidence(self) -> None:
        envelopes = [
            self._envelope(
                "evidence:observed-service",
                "evidence",
                "observed",
                "tool_output",
                ["evidence:observed-service"],
            ),
            self._envelope(
                "task:safe-service-check",
                "candidate_task",
                "asserted",
                "tool_output",
                ["policy_decision:assisted-lab", "evidence:observed-service"],
                metadata={
                    "active_intent": "ctf_solve_assisted",
                    "action_class": "tool_execution",
                    "creates_executable_task": True,
                    "supporting_evidence_refs": ["evidence:observed-service"],
                },
            ),
            self._envelope(
                "task:fabricated-service-check",
                "candidate_task",
                "asserted",
                "tool_output",
                ["policy_decision:assisted-lab", "evidence:made-up"],
                metadata={
                    "active_intent": "ctf_solve_assisted",
                    "action_class": "tool_execution",
                    "creates_executable_task": True,
                    "supporting_evidence_refs": ["evidence:made-up"],
                },
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["MODEL_DERIVED"]], ["task:safe-service-check"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["task:fabricated-service-check"], "task_metadata_invalid")
        self.assertNotIn("task:fabricated-service-check", packet["rendered"])

    def _envelope(
        self,
        ref: str,
        kind: str,
        authority: str,
        source_type: str,
        citations: list[str],
        metadata: dict[str, object] | None = None,
    ) -> ContextEnvelope:
        return ContextEnvelope(
            ref=ref,
            kind=kind,
            authority=authority,
            source_type=source_type,
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content=f"{ref} prompt context.",
            citations=citations,
            metadata=metadata or {},
        )


if __name__ == "__main__":
    unittest.main()
