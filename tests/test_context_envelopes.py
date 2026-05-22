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
        self.assertEqual(envelope.citations, ["evidence:1", "RAG:ChunkA"])

        payload = envelope.as_payload()
        self.assertEqual(payload["valid_for"], ["planner", "report_writer"])
        self.assertEqual(payload["invalid_for"], ["prompt"])
        self.assertEqual(payload["poison_flags"], ["hidden_solution_material", "contains_raw_flag"])
        self.assertEqual(payload["citations"], ["evidence:1", "RAG:ChunkA"])

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
