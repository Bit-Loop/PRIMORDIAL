from __future__ import annotations

import unittest

from primordial.core.context import ContextEnvelope


class ContextEnvelopeNormalizationTests(unittest.TestCase):
    def test_from_rag_chunk_canonicalizes_plain_citation_ids(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "chunk-plain",
                "citation_id": "chunk-plain",
                "text": "Plain chunk citations must still become advisory RAG references.",
            },
            purpose="operator_answer",
            sink="prompt",
        )

        self.assertEqual(envelope.ref, "rag:chunk-plain")
        self.assertEqual(envelope.citations, ["rag:chunk-plain"])

    def test_from_rag_chunk_ignores_blank_citation_ids(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "chunk-from-id",
                "citation_id": "  ",
                "text": "Blank citation fields must fall back to the actual chunk ID.",
            },
            purpose="operator_answer",
            sink="prompt",
        )

        self.assertEqual(envelope.ref, "rag:chunk-from-id")
        self.assertEqual(envelope.citations, ["rag:chunk-from-id"])

    def test_from_rag_chunk_ignores_placeholder_citation_ids(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "chunk-from-placeholder",
                "citation_id": "rag:None",
                "text": "Placeholder citation fields must fall back to the actual chunk ID.",
            },
            purpose="operator_answer",
            sink="prompt",
        )

        self.assertEqual(envelope.ref, "rag:chunk-from-placeholder")
        self.assertEqual(envelope.citations, ["rag:chunk-from-placeholder"])

    def test_from_rag_chunk_preserves_payload_target_binding(self) -> None:
        chunk = {
            "chunk_id": "target-bound-rag",
            "citation_id": "rag:target-bound-rag",
            "target_id": "target-a",
            "active_generation_id": "generation:3",
            "text": "Target-bound RAG must keep target and generation metadata.",
            "metadata": {"source_type": "methodology_doc"},
        }

        envelope = ContextEnvelope.from_rag_chunk(
            chunk,
            purpose="planner",
            sink="prompt",
        )
        override = ContextEnvelope.from_rag_chunk(
            chunk,
            purpose="planner",
            sink="prompt",
            target_id="target-explicit",
            active_generation_id="generation:explicit",
        )

        self.assertEqual(envelope.target_id, "target-a")
        self.assertEqual(envelope.active_generation_id, "generation:3")
        self.assertEqual(override.target_id, "target-explicit")
        self.assertEqual(override.active_generation_id, "generation:explicit")

    def test_from_rag_chunk_normalizes_human_readable_domain_and_corpus(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "human-readable-domain",
                "citation_id": "rag:human-readable-domain",
                "text": "RAG identity fields must not keep human-readable aliases.",
                "metadata": {
                    "Domain": "API Web",
                    "Corpus Type": "HTB Writeup",
                    "source_type": "markdown",
                },
            },
            purpose="operator_answer",
            sink="prompt",
        )

        self.assertEqual(envelope.domain, "api_security")
        self.assertEqual(envelope.corpus, "htb_writeup")
        self.assertEqual(envelope.as_payload()["domain"], "api_security")
        self.assertEqual(envelope.as_payload()["corpus"], "htb_writeup")

    def test_from_rag_chunk_promotes_metadata_control_lists(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "hidden-path",
                "citation_id": "rag:hidden-path",
                "text": "Hidden solve material must keep its safety controls when wrapped.",
                "metadata": {
                    "source_type": "ctf_manifest",
                    "corpus_type": "ctf_benchmark",
                    "domain": "ctf_benchmark",
                    "valid_for": [" Ctf_Solver_Context "],
                    "invalid_for": [" Report "],
                    "poison_flags": [" Hidden_Solution_Material "],
                },
            },
            purpose="ctf_solver_context",
            sink="prompt",
            target_id="lab-target",
            active_generation_id="generation:2",
        )

        self.assertEqual(envelope.valid_for, ["ctf_solver_context"])
        self.assertEqual(envelope.invalid_for, ["report"])
        self.assertEqual(envelope.poison_flags, ["hidden_solution_material"])
        self.assertEqual(envelope.as_payload()["poison_flags"], ["hidden_solution_material"])

    def test_from_rag_chunk_promotes_scalar_metadata_control_fields(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "scalar-hidden-path",
                "citation_id": "rag:scalar-hidden-path",
                "text": "Scalar metadata controls must remain intact when wrapped.",
                "metadata": {
                    "source_type": "ctf_manifest",
                    "valid_for": " Ctf_Solver_Context ",
                    "invalid_for": " Report ",
                    "poison_flags": " Hidden_Solution_Material ",
                },
            },
            purpose="ctf_solver_context",
            sink="prompt",
            target_id="lab-target",
            active_generation_id="generation:2",
        )

        self.assertEqual(envelope.valid_for, ["ctf_solver_context"])
        self.assertEqual(envelope.invalid_for, ["report"])
        self.assertEqual(envelope.poison_flags, ["hidden_solution_material"])
        self.assertEqual(envelope.as_payload()["poison_flags"], ["hidden_solution_material"])

    def test_from_rag_chunk_rejects_mapping_metadata_control_fields(self) -> None:
        with self.assertRaisesRegex(ValueError, "poison_flags"):
            ContextEnvelope.from_rag_chunk(
                {
                    "chunk_id": "mapping-hidden-path",
                    "citation_id": "rag:mapping-hidden-path",
                    "text": "Mapping safety controls must fail closed when wrapped.",
                    "metadata": {
                        "source_type": "ctf_manifest",
                        "poison_flags": {"hidden_solution_material": True},
                    },
                },
                purpose="ctf_solver_context",
                sink="prompt",
            )

    def test_normalizes_control_lists_before_payload_export(self) -> None:
        envelope = ContextEnvelope(
            ref=" note:boundary ",
            kind=" Operator_Note ",
            authority=" Asserted ",
            source_type=" Manual_Artifact ",
            purpose=" Planner ",
            sink=" Prompt ",
            content="Boundary control fields must serialize in canonical form.",
            valid_for=[" Planner ", "", "REPORT_WRITER"],
            invalid_for=[" Prompt ", " "],
            poison_flags=[" Hidden_Solution_Material ", "", "CONTAINS_RAW_FLAG"],
            citations=[" evidence:1 ", "", "RAG:ChunkA "],
        )

        self.assertEqual(envelope.valid_for, ["planner", "report_writer"])
        self.assertEqual(envelope.invalid_for, ["prompt"])
        self.assertEqual(envelope.poison_flags, ["hidden_solution_material", "contains_raw_flag"])
        self.assertEqual(envelope.citations, ["evidence:1", "rag:ChunkA"])

        payload = envelope.as_payload()
        self.assertEqual(payload["valid_for"], ["planner", "report_writer"])
        self.assertEqual(payload["invalid_for"], ["prompt"])
        self.assertEqual(payload["poison_flags"], ["hidden_solution_material", "contains_raw_flag"])
        self.assertEqual(payload["citations"], ["evidence:1", "rag:ChunkA"])

    def test_normalizes_supported_ref_prefix_before_payload_export(self) -> None:
        envelope = ContextEnvelope(
            ref=" RAG:ChunkA ",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="operator_answer",
            sink="prompt",
            content="Supported ref prefixes should serialize canonically.",
            citations=["RAG:ChunkA"],
        )

        self.assertEqual(envelope.ref, "rag:ChunkA")
        self.assertEqual(envelope.citations, ["rag:ChunkA"])
        self.assertEqual(envelope.as_payload()["ref"], "rag:ChunkA")

    def test_normalizes_supported_source_refs_metadata_before_payload_export(self) -> None:
        envelope = ContextEnvelope(
            ref="model:summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="operator_answer",
            sink="prompt",
            content="Source refs should not carry human-readable prefixes across boundaries.",
            citations=["Evidence:http-banner", "RAG:ChunkA"],
            metadata={"source_refs": [" Evidence:http-banner ", "RAG:ChunkA"]},
        )

        self.assertEqual(envelope.metadata["source_refs"], ["evidence:http-banner", "rag:ChunkA"])
        self.assertEqual(envelope.as_payload()["metadata"]["source_refs"], ["evidence:http-banner", "rag:ChunkA"])

    def test_normalizes_human_readable_source_refs_metadata_key_before_payload_export(self) -> None:
        envelope = ContextEnvelope(
            ref="model:summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="operator_answer",
            sink="prompt",
            content="Source ref metadata keys should serialize canonically.",
            citations=["Evidence:http-banner"],
            metadata={"Source Refs": ["Evidence:http-banner"]},
        )

        self.assertNotIn("Source Refs", envelope.metadata)
        self.assertEqual(envelope.metadata["source_refs"], ["evidence:http-banner"])
        self.assertEqual(envelope.as_payload()["metadata"], {"source_refs": ["evidence:http-banner"]})

    def test_normalizes_source_reference_aliases_before_payload_export(self) -> None:
        envelope = ContextEnvelope(
            ref="model:summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="operator_answer",
            sink="prompt",
            content="Source-reference aliases should serialize as canonical source_refs.",
            citations=["Evidence:http-banner", "RAG:ChunkA", "Note:operator"],
            metadata={
                "Source reference": "Evidence:http-banner",
                "Source references": ["RAG:ChunkA"],
                "Source ref": "Note:operator",
            },
        )

        self.assertNotIn("Source reference", envelope.metadata)
        self.assertNotIn("Source references", envelope.metadata)
        self.assertNotIn("Source ref", envelope.metadata)
        self.assertEqual(envelope.metadata["source_refs"], ["evidence:http-banner", "rag:ChunkA", "note:operator"])
        self.assertEqual(
            envelope.as_payload()["metadata"],
            {"source_refs": ["evidence:http-banner", "rag:ChunkA", "note:operator"]},
        )

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


if __name__ == "__main__":
    unittest.main()
