from __future__ import annotations

from tests.test_context_envelopes_common import *


class ContextEnvelopeNormalizationTestsPart2(ContextEnvelopeNormalizationTestsBase):
    def test_normalizes_nested_source_reference_aliases_before_payload_export(self) -> None:
        envelope = ContextEnvelope(
            ref="model:summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="operator_answer",
            sink="prompt",
            content="Nested source-reference aliases should not cross envelope boundaries.",
            citations=["Evidence:http-banner", "RAG:ChunkA"],
            metadata={
                "audit": {
                    "Source reference": "Evidence:http-banner",
                    "kept": "value",
                },
                "layers": [{"Source references": ["RAG:ChunkA"]}],
            },
        )

        self.assertEqual(envelope.metadata["source_refs"], ["evidence:http-banner", "rag:ChunkA"])
        self.assertEqual(envelope.metadata["audit"], {"kept": "value"})
        self.assertEqual(envelope.metadata["layers"], [{}])
        self.assertEqual(
            envelope.as_payload()["metadata"],
            {
                "audit": {"kept": "value"},
                "layers": [{}],
                "source_refs": ["evidence:http-banner", "rag:ChunkA"],
            },
        )

    def test_normalizes_tuple_nested_source_reference_aliases_before_payload_export(self) -> None:
        envelope = ContextEnvelope(
            ref="model:summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="operator_answer",
            sink="prompt",
            content="Tuple-nested source-reference aliases should not cross envelope boundaries.",
            citations=["Evidence:http-banner", "RAG:ChunkA"],
            metadata={
                "audit": (
                    {"Source reference": "Evidence:http-banner"},
                    {"Source references": ["RAG:ChunkA"], "kept": "value"},
                ),
            },
        )

        self.assertEqual(envelope.metadata["source_refs"], ["evidence:http-banner", "rag:ChunkA"])
        self.assertEqual(envelope.metadata["audit"], [{}, {"kept": "value"}])
        self.assertEqual(
            envelope.as_payload()["metadata"],
            {
                "audit": [{}, {"kept": "value"}],
                "source_refs": ["evidence:http-banner", "rag:ChunkA"],
            },
        )

    def test_from_rag_chunk_promotes_top_level_source_refs_metadata_before_payload_export(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "chunk-top-level-source-refs",
                "text": "Top-level chunk provenance must not be dropped before envelope export.",
                "Source references": ["Evidence:http-banner"],
                "source_refs": ["RAG:ChunkA"],
                "source_ref": "file:methodology.md:sha256",
                "metadata": {
                    "source_type": "methodology_doc",
                    "source_ref": "file:metadata-locator.md:sha256",
                },
            },
            purpose="operator_answer",
            sink="prompt",
        )

        self.assertEqual(envelope.metadata["source_refs"], ["evidence:http-banner", "rag:ChunkA"])
        self.assertEqual(envelope.metadata["source_ref"], "file:metadata-locator.md:sha256")
        self.assertEqual(
            envelope.as_payload()["metadata"]["source_refs"],
            ["evidence:http-banner", "rag:ChunkA"],
        )

    def test_from_rag_chunk_merges_metadata_and_top_level_source_refs_before_payload_export(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "chunk-merged-source-refs",
                "text": "Chunk and metadata provenance must both survive envelope export.",
                "source_refs": ["RAG:ChunkA"],
                "metadata": {
                    "source_type": "methodology_doc",
                    "source_refs": ["Evidence:http-banner"],
                    "source_ref": "file:metadata-locator.md:sha256",
                },
            },
            purpose="operator_answer",
            sink="prompt",
        )

        self.assertEqual(envelope.metadata["source_refs"], ["evidence:http-banner", "rag:ChunkA"])
        self.assertEqual(envelope.metadata["source_ref"], "file:metadata-locator.md:sha256")

    def test_merges_source_refs_metadata_aliases_before_payload_export(self) -> None:
        envelope = ContextEnvelope(
            ref="model:summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="operator_answer",
            sink="prompt",
            content="Source ref metadata aliases should not drop provenance.",
            citations=["Evidence:http-banner", "RAG:ChunkA"],
            metadata={
                "Source Refs": ["Evidence:http-banner"],
                "source_refs": ["RAG:ChunkA"],
            },
        )

        self.assertNotIn("Source Refs", envelope.metadata)
        self.assertEqual(envelope.metadata["source_refs"], ["evidence:http-banner", "rag:ChunkA"])

    def test_rejects_non_mapping_metadata_at_envelope_boundary(self) -> None:
        with self.assertRaisesRegex(ValueError, "metadata"):
            ContextEnvelope(
                ref="model:bad-metadata",
                kind="model_summary",
                authority="derived",
                source_type="ai_output",
                purpose="operator_answer",
                sink="prompt",
                content="Envelope metadata must be a typed mapping before crossing boundaries.",
                metadata=["contains_raw_flag"],
            )

    def test_from_rag_chunk_rejects_non_mapping_metadata(self) -> None:
        with self.assertRaisesRegex(ValueError, "metadata"):
            ContextEnvelope.from_rag_chunk(
                {
                    "chunk_id": "bad-metadata-rag",
                    "citation_id": "rag:bad-metadata-rag",
                    "text": "Explicit malformed metadata must not be silently dropped.",
                    "metadata": ["poison_flags", "hidden_solution_material"],
                },
                purpose="operator_answer",
                sink="prompt",
            )

    def test_normalizes_typed_identity_fields_to_canonical_keys(self) -> None:
        envelope = ContextEnvelope(
            ref="model:identity",
            kind=" Model Summary ",
            authority=" Low Trust ",
            source_type=" AI Output ",
            purpose="Notion export",
            sink="Discord notification",
            content="Identity fields must not carry human-readable aliases across boundaries.",
            valid_for=[" Report writer "],
            invalid_for=[" Notion export "],
            poison_flags=[" Contains Raw Flag "],
            citations=["model:identity"],
        )

        self.assertEqual(envelope.kind, "model_summary")
        self.assertEqual(envelope.authority, "low_trust")
        self.assertEqual(envelope.source_type, "ai_output")
        self.assertEqual(envelope.purpose, "notion_export")
        self.assertEqual(envelope.sink, "discord_notification")
        self.assertEqual(envelope.valid_for, ["report_writer"])
        self.assertEqual(envelope.invalid_for, ["notion_export"])
        self.assertEqual(envelope.poison_flags, ["contains_raw_flag"])

        payload = envelope.as_payload()
        self.assertEqual(payload["kind"], "model_summary")
        self.assertEqual(payload["source_type"], "ai_output")
        self.assertEqual(payload["purpose"], "notion_export")
        self.assertEqual(payload["sink"], "discord_notification")

__all__ = ["ContextEnvelopeNormalizationTestsPart2"]
