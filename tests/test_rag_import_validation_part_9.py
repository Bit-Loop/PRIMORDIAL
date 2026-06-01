from __future__ import annotations

from tests.test_rag_import_validation_common import *


class RagChunkImporterMetadataTestsPart9(RagChunkImporterMetadataTestsBase):
    def test_metadata_preserves_human_readable_domain_provenance(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)
        record = {
            "chunk_id": "chunk_display_domain_provenance",
            "Domain": "api_security",
            "Secondary domains": ["methodology_standards", "vuln_intel"],
        }

        metadata = importer._metadata(record, domain=importer._domain(record))

        self.assertEqual(metadata["domain"], "api_security")
        self.assertEqual(metadata["original_domain"], "api_security")
        self.assertEqual(metadata["secondary_domains"], ["methodology_standards", "vuln_intel"])

    def test_metadata_preserves_row_level_invalid_for(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)

        metadata = importer._metadata(
            {
                "chunk_id": "prompt_denied_chunk",
                "source_type": "methodology_doc",
                "invalid_for": ["prompt"],
            },
            domain="methodology_standards",
        )

        self.assertEqual(metadata["invalid_for"], ["prompt"])

    def test_metadata_preserves_row_level_valid_for(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)

        metadata = importer._metadata(
            {
                "chunk_id": "report_only_chunk",
                "source_type": "methodology_doc",
                "valid_for": ["report_writer"],
            },
            domain="methodology_standards",
        )

        self.assertEqual(metadata["valid_for"], ["report_writer"])

    def test_metadata_preserves_human_readable_policy_fields(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)
        cases = [
            (
                "row_policy_fields",
                {
                    "chunk_id": "chunk_display_row_policy_fields",
                    "Source refs": ["rag:display-row-source"],
                    "Ingest allowed": False,
                    "Operational retrieval allowed": False,
                    "Valid for": ["report_writer"],
                    "Invalid for": ["prompt"],
                },
            ),
            (
                "nested_policy_fields",
                {
                    "chunk_id": "chunk_display_nested_policy_fields",
                    "metadata": {
                        "Source refs": ["rag:display-nested-source"],
                        "Ingest allowed": False,
                        "Operational retrieval allowed": False,
                        "Valid for": ["methodology_advisor"],
                        "Invalid for": ["task_metadata"],
                    },
                },
            ),
        ]

        for case_id, record in cases:
            with self.subTest(case=case_id):
                metadata = importer._metadata(record, domain="methodology_standards")

                self.assertFalse(metadata["ingest_allowed"])
                self.assertFalse(metadata["operational_retrieval_allowed"])
                self.assertEqual(metadata["source_refs"], record.get("Source refs") or record["metadata"]["Source refs"])
                self.assertEqual(metadata["valid_for"], record.get("Valid for") or record["metadata"]["Valid for"])
                self.assertEqual(metadata["invalid_for"], record.get("Invalid for") or record["metadata"]["Invalid for"])

    def test_metadata_preserves_human_readable_visibility_defaults(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)
        cases = [
            (
                "row_visibility_defaults",
                {
                    "chunk_id": "chunk_display_row_visibility_defaults",
                    "Authority level": "advisory",
                    "Chunk type": "guidance",
                    "Section path": ["Guidance", "Scope"],
                    "Page start": 4,
                    "Page end": 5,
                    "Risk level": "low",
                    "Planner visibility": "methodology_only",
                    "Requires authorized scope": False,
                    "Scope gate required": False,
                    "Requires operator approval": True,
                    "Allowed use modes": ["suggest_only"],
                    "Allowed contexts": ["methodology_hint"],
                    "License status": "redistributable",
                },
            ),
            (
                "nested_visibility_defaults",
                {
                    "chunk_id": "chunk_display_nested_visibility_defaults",
                    "metadata": {
                        "Authority level": "advisory",
                        "Chunk type": "guidance",
                        "Section path": ["Guidance", "Nested"],
                        "Page start": 6,
                        "Page end": 7,
                        "Risk level": "low",
                        "Planner visibility": "methodology_only",
                        "Requires authorized scope": False,
                        "Scope gate required": False,
                        "Requires operator approval": True,
                        "Allowed use modes": ["suggest_only"],
                        "Allowed contexts": ["methodology_hint"],
                        "License status": "redistributable",
                    },
                },
            ),
        ]

        for case_id, record in cases:
            expected = record.get("metadata", record)
            with self.subTest(case=case_id):
                metadata = importer._metadata(record, domain="methodology_standards")

                self.assertEqual(metadata["authority_level"], "advisory")
                self.assertEqual(metadata["chunk_type"], "guidance")
                self.assertEqual(metadata["section_path"], expected["Section path"])
                self.assertEqual(metadata["page_start"], expected["Page start"])
                self.assertEqual(metadata["page_end"], expected["Page end"])
                self.assertEqual(metadata["risk_level"], "low")
                self.assertEqual(metadata["planner_visibility"], "methodology_only")
                self.assertFalse(metadata["requires_authorized_scope"])
                self.assertFalse(metadata["scope_gate_required"])
                self.assertTrue(metadata["requires_operator_approval"])
                self.assertEqual(metadata["allowed_use_modes"], ["suggest_only"])
                self.assertEqual(metadata["allowed_contexts"], ["methodology_hint"])
                self.assertEqual(metadata["license_status"], "redistributable")

__all__ = ["RagChunkImporterMetadataTestsPart9"]
