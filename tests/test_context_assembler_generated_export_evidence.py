from __future__ import annotations

import unittest

from primordial.core.context import ContextAssembler, ContextEnvelope


class ContextAssemblerGeneratedExportEvidenceTests(unittest.TestCase):
    def test_assembler_omits_model_target_facts_backed_by_generated_export_evidence(self) -> None:
        envelopes = [
            self._envelope(
                "evidence:observed-service",
                "evidence",
                "observed",
                "tool_output",
                ["evidence:observed-service"],
            ),
            self._envelope(
                "evidence:generated-export-service",
                "evidence",
                "observed",
                "tool_output",
                ["evidence:generated-export-service"],
                metadata={"origin": "generated_export"},
            ),
            self._envelope(
                "model:observed-service",
                "model_summary",
                "derived",
                "ai_output",
                ["evidence:observed-service"],
                metadata={"contains_target_fact": True},
            ),
            self._envelope(
                "model:generated-export-service",
                "model_summary",
                "derived",
                "ai_output",
                ["evidence:generated-export-service"],
                metadata={"contains_target_fact": True},
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["OBSERVED_EVIDENCE"]], ["evidence:observed-service"])
        self.assertEqual([item["ref"] for item in packet["sections"]["MODEL_DERIVED"]], ["model:observed-service"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["evidence:generated-export-service"], "generated_export")
        self.assertEqual(omitted_refs["model:generated-export-service"], "invalid_citation")
        self.assertNotIn("model:generated-export-service", packet["rendered"])

    def test_assembler_omits_model_target_facts_backed_by_non_prompt_evidence(self) -> None:
        envelopes = [
            self._envelope(
                "evidence:prompt-service",
                "evidence",
                "observed",
                "tool_output",
                ["evidence:prompt-service"],
            ),
            self._envelope(
                "evidence:notion-export-service",
                "evidence",
                "observed",
                "tool_output",
                ["evidence:notion-export-service"],
                sink="notion_export",
            ),
            self._envelope(
                "model:prompt-service",
                "model_summary",
                "derived",
                "ai_output",
                ["evidence:prompt-service"],
                metadata={"contains_target_fact": True},
            ),
            self._envelope(
                "model:notion-export-service",
                "model_summary",
                "derived",
                "ai_output",
                ["evidence:notion-export-service"],
                metadata={"contains_target_fact": True},
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["OBSERVED_EVIDENCE"]], ["evidence:prompt-service"])
        self.assertEqual([item["ref"] for item in packet["sections"]["MODEL_DERIVED"]], ["model:prompt-service"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["evidence:notion-export-service"], "sink_mismatch")
        self.assertEqual(omitted_refs["model:notion-export-service"], "invalid_citation")
        self.assertNotIn("model:notion-export-service", packet["rendered"])

    def _envelope(
        self,
        ref: str,
        kind: str,
        authority: str,
        source_type: str,
        citations: list[str],
        metadata: dict[str, object] | None = None,
        sink: str = "prompt",
    ) -> ContextEnvelope:
        return ContextEnvelope(
            ref=ref,
            kind=kind,
            authority=authority,
            source_type=source_type,
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink=sink,
            content=f"{ref} prompt context.",
            citations=citations,
            metadata=metadata or {},
        )


if __name__ == "__main__":
    unittest.main()
