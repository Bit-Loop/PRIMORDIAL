from __future__ import annotations

import unittest

from primordial.core.context import ContextEnvelope, ContextSinkValidator


class ContextTaskEvidenceRequirementTests(unittest.TestCase):
    def test_executable_task_requires_cited_supporting_evidence(self) -> None:
        envelope = ContextEnvelope(
            ref="task:no-supporting-evidence",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Executable task metadata must be backed by observed target evidence.",
            citations=["policy_decision:assisted-lab"],
            metadata={
                "Active intent": "ctf_solve_assisted",
                "Action class": "Tool execution",
                "Creates executable task": "true",
            },
        )

        result = ContextSinkValidator().validate("task_metadata", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:no-supporting-evidence"])
        self.assertTrue(any("supporting target evidence" in error for error in result.errors))

    def test_executable_task_rejects_non_evidence_supporting_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="task:mixed-supporting-refs",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Executable task metadata must not launder advisory refs as supporting evidence.",
            citations=["policy_decision:assisted-lab", "evidence:observed-service", "rag:cve-advisory"],
            metadata={
                "Active intent": "ctf_solve_assisted",
                "Action class": "Tool execution",
                "Creates executable task": "true",
                "Supporting evidence refs": ["evidence:observed-service", "rag:cve-advisory"],
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:observed-service"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:mixed-supporting-refs"])
        self.assertTrue(any("non-evidence supporting refs" in error for error in result.errors))
        self.assertTrue(any("rag:cve-advisory" in error for error in result.errors))

    def test_recon_only_rejects_vuln_intel_executable_task_even_with_evidence(self) -> None:
        envelope = ContextEnvelope(
            ref="task:vuln-intel-recon-tool",
            kind="candidate_task",
            authority="advisory",
            source_type="vuln_intel",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Vulnerability intelligence may suggest hypotheses, not recon-only executable tasks.",
            citations=["policy_decision:recon-block", "evidence:observed-service", "rag:cve-advisory"],
            metadata={
                "Active intent": "recon_only",
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
        self.assertEqual(result.rejected_refs, ["task:vuln-intel-recon-tool"])
        self.assertTrue(any("vuln_intel" in error for error in result.errors))
        self.assertTrue(any("recon_only" in error for error in result.errors))

    def test_executable_task_rejects_writeup_source_even_with_evidence(self) -> None:
        envelope = ContextEnvelope(
            ref="task:writeup-derived-tool",
            kind="candidate_task",
            authority="advisory",
            source_type="writeup",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Writeup-derived context must not originate executable task authority.",
            citations=["policy_decision:assisted-lab", "evidence:observed-service", "rag:writeup-hint"],
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
        self.assertEqual(result.rejected_refs, ["task:writeup-derived-tool"])
        self.assertTrue(any("writeup-derived action authority" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
