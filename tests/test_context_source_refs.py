from __future__ import annotations

from types import SimpleNamespace
import unittest

from primordial.core.context import ContextEnvelope, ContextSinkValidator
from primordial.core.context.source_refs import source_refs_metadata_errors, source_refs_metadata_values


class ContextSourceRefsTests(unittest.TestCase):
    def test_source_refs_metadata_values_canonicalizes_supported_ref_prefixes(self) -> None:
        carrier = SimpleNamespace(
            metadata={
                "source_refs": [" Evidence:http-banner ", "RAG:ChunkA", "Note:operator"],
            },
            citations=[],
        )

        self.assertEqual(
            source_refs_metadata_values(carrier),
            ["evidence:http-banner", "rag:ChunkA", "note:operator"],
        )

    def test_source_refs_metadata_values_deduplicates_canonical_refs(self) -> None:
        carrier = SimpleNamespace(
            metadata={
                "source_refs": [" Evidence:http-banner ", "evidence:http-banner"],
                "audit": {"Source references": ["RAG:ChunkA", "rag:ChunkA "]},
            },
            citations=[],
        )

        self.assertEqual(
            source_refs_metadata_values(carrier),
            ["evidence:http-banner", "rag:ChunkA"],
        )

    def test_source_refs_metadata_values_accepts_frozenset_refs(self) -> None:
        carrier = SimpleNamespace(
            metadata={
                "source_refs": frozenset({"Evidence:http-banner"}),
            },
            citations=["Evidence:http-banner"],
        )

        self.assertEqual(source_refs_metadata_errors(carrier), [])
        self.assertEqual(source_refs_metadata_values(carrier), ["evidence:http-banner"])

    def test_prompt_sink_accepts_human_readable_source_ref_prefixes(self) -> None:
        envelope = ContextEnvelope(
            ref="model:prompt-human-readable-source-ref",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Prompt summaries may cite supported provenance with human-readable ref prefixes.",
            citations=["evidence:http-banner"],
            metadata={
                "source_refs": ["Evidence:http-banner"],
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
            },
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertTrue(result.valid)
        self.assertEqual(result.accepted_refs, ["model:prompt-human-readable-source-ref"])
        self.assertEqual(result.rejected_refs, [])

    def test_prompt_sink_rejects_ai_summary_with_blank_source_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="model:prompt-blank-source-ref",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Prompt summaries must not hide blank provenance in source_refs metadata.",
            citations=["evidence:http-banner"],
            metadata={
                "source_refs": ["evidence:http-banner", " "],
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
            },
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:prompt-blank-source-ref"])
        self.assertTrue(any("malformed source_refs" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
