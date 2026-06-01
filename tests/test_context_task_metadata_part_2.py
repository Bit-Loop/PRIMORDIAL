from __future__ import annotations

from tests.test_context_task_metadata_common import *


class ContextTaskMetadataTestsPart2(ContextTaskMetadataTestsBase):
    def test_task_metadata_target_fact_requires_evidence_citation(self) -> None:
        envelope = ContextEnvelope(
            ref="task:rag-only-target-fact",
            kind="candidate_task",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Create a candidate task from a target fact supported only by advisory RAG.",
            citations=["rag:service-methodology"],
            metadata={"contains_target_fact": True},
        )

        result = ContextSinkValidator().validate("task_metadata", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:rag-only-target-fact"])
        self.assertTrue(any("requires evidence:<id>" in error for error in result.errors))

    def test_generated_export_cannot_authorize_executable_task(self) -> None:
        envelope = ContextEnvelope(
            ref="task:export-recursive-service-check",
            kind="candidate_task",
            authority="derived",
            source_type="generated_export",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="A generated export must not loop back into executable task authority.",
            citations=["policy_decision:assisted-lab", "evidence:observed-service"],
            metadata={
                "Active intent": "ctf_solve_assisted",
                "Action class": "Tool execution",
                "Creates executable task": "true",
                "Supporting evidence refs": ["evidence:observed-service"],
            },
        )

        result = ContextSinkValidator().validate("task_metadata", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:export-recursive-service-check"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_generated_export_path_cannot_authorize_executable_task(self) -> None:
        envelope = ContextEnvelope(
            ref="task:export-path-service-check",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="A generated export path must not authorize executable task metadata.",
            citations=["policy_decision:assisted-lab", "evidence:observed-service"],
            metadata={
                "Active intent": "ctf_solve_assisted",
                "Action class": "Tool execution",
                "Creates executable task": "true",
                "Supporting evidence refs": ["evidence:observed-service"],
                "source_file": "findings/notion/rag.htb/notion-export.md",
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:observed-service"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:export-path-service-check"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_human_readable_generated_export_path_cannot_authorize_executable_task(self) -> None:
        envelope = ContextEnvelope(
            ref="task:display-export-path-service-check",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Human-readable generated export metadata must not authorize executable tasks.",
            citations=["policy_decision:assisted-lab", "evidence:observed-service"],
            metadata={
                "Active intent": "ctf_solve_assisted",
                "Action class": "Tool execution",
                "Creates executable task": "true",
                "Supporting evidence refs": ["evidence:observed-service"],
                "Source file": "findings/notion/rag.htb/notion-export.md",
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:observed-service"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:display-export-path-service-check"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_findings_notion_path_cannot_authorize_executable_task(self) -> None:
        envelope = ContextEnvelope(
            ref="task:findings-notion-export-path-service-check",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Any generated Notion export path must not authorize executable task metadata.",
            citations=["policy_decision:assisted-lab", "evidence:observed-service"],
            metadata={
                "Active intent": "ctf_solve_assisted",
                "Action class": "Tool execution",
                "Creates executable task": "true",
                "Supporting evidence refs": ["evidence:observed-service"],
                "Source file": "findings/notion/rag.htb/operator-summary.md",
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:observed-service"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:findings-notion-export-path-service-check"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_source_path_list_cannot_hide_generated_export_task_authority(self) -> None:
        envelope = ContextEnvelope(
            ref="task:list-export-path-service-check",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="List-shaped source path metadata must not hide generated export task authority.",
            citations=["policy_decision:assisted-lab", "evidence:observed-service"],
            metadata={
                "Active intent": "ctf_solve_assisted",
                "Action class": "Tool execution",
                "Creates executable task": "true",
                "Supporting evidence refs": ["evidence:observed-service"],
                "Source path": [
                    "artifacts/tool-output.json",
                    "findings/notion/rag.htb/operator-summary.md",
                ],
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
        self.assertEqual(result.rejected_refs, ["task:list-export-path-service-check"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_source_path_mapping_cannot_hide_generated_export_task_authority(self) -> None:
        envelope = ContextEnvelope(
            ref="task:mapping-export-path-service-check",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Mapping-shaped source path metadata must not hide generated export task authority.",
            citations=["policy_decision:assisted-lab", "evidence:observed-service"],
            metadata={
                "Active intent": "ctf_solve_assisted",
                "Action class": "Tool execution",
                "Creates executable task": "true",
                "Supporting evidence refs": ["evidence:observed-service"],
                "Source path": {
                    "kind": "projection",
                    "path": "findings/notion/rag.htb/operator-summary.md",
                },
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
        self.assertEqual(result.rejected_refs, ["task:mapping-export-path-service-check"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_ctfd_cannot_authorize_executable_task(self) -> None:
        envelope = ContextEnvelope(
            ref="task:ctfd-recursive-service-check",
            kind="candidate_task",
            authority="asserted",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="CTFd challenge metadata must not authorize executable task metadata.",
            citations=["policy_decision:assisted-lab", "evidence:observed-service"],
            metadata={
                "Active intent": "ctf_solve_assisted",
                "Action class": "Tool execution",
                "Creates executable task": "true",
                "Supporting evidence refs": ["evidence:observed-service"],
            },
        )

        result = ContextSinkValidator().validate("task_metadata", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:ctfd-recursive-service-check"])
        self.assertTrue(any("ctfd" in error.lower() for error in result.errors))

__all__ = ["ContextTaskMetadataTestsPart2"]
