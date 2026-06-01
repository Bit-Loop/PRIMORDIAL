from __future__ import annotations

from tests.test_rag_import_validation_common import *


class RagChunkImporterMetadataTestsPart8(RagChunkImporterMetadataTestsBase):
    def test_metadata_preserves_row_level_citation_id(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)

        metadata = importer._metadata(
            {
                "chunk_id": "chunk_from_preprocessor",
                "citation_id": "rag:curated-source-ref",
                "source_type": "markdown",
            },
            domain="methodology_standards",
        )

        self.assertEqual(metadata["citation_id"], "rag:curated-source-ref")

    def test_metadata_preserves_human_readable_citation_and_source_ids(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)
        cases = [
            (
                "row_ids",
                {
                    "chunk_id": "chunk_display_row_ids",
                    "Citation ID": "rag:display-row-citation",
                    "Source ID": "display-row-source",
                    "source_type": "markdown",
                },
                "rag:display-row-citation",
                "display-row-source",
            ),
            (
                "nested_ids",
                {
                    "chunk_id": "chunk_display_nested_ids",
                    "source_type": "markdown",
                    "metadata": {
                        "Citation ID": "display-nested-citation",
                        "Source ID": "display-nested-source",
                    },
                },
                "rag:display-nested-citation",
                "display-nested-source",
            ),
        ]

        for case_id, record, expected_citation, expected_doc_id in cases:
            with self.subTest(case=case_id):
                metadata = importer._metadata(record, domain="methodology_standards")

                self.assertEqual(metadata["citation_id"], expected_citation)
                self.assertEqual(metadata["doc_id"], expected_doc_id)

    def test_metadata_preserves_human_readable_source_fields(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)
        cases = [
            (
                "row_source_fields",
                {
                    "chunk_id": "chunk_display_row_source_fields",
                    "Source file": "findings/notion/rag.htb/notion-export.md",
                    "Source path": "findings/notion/rag.htb/notion-export.md",
                    "Source type": "generated_export",
                },
            ),
            (
                "nested_source_fields",
                {
                    "chunk_id": "chunk_display_nested_source_fields",
                    "metadata": {
                        "Source file": "findings/notion/helix.htb/notion-export.md",
                        "Source path": "findings/notion/helix.htb/notion-export.md",
                        "Source type": "generated_export",
                    },
                },
            ),
        ]

        for case_id, record in cases:
            with self.subTest(case=case_id):
                metadata = importer._metadata(record, domain="methodology_standards")

                self.assertTrue(metadata["source_file"].endswith("notion-export.md"))
                self.assertTrue(metadata["source_path"].endswith("notion-export.md"))
                self.assertEqual(metadata["source_type"], "generated_export")

    def test_filters_and_artifact_preserve_human_readable_source_fields(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)
        record = {
            "chunk_id": "chunk_display_source_artifact",
            "Source ID": "display-source-doc",
            "Source file": "findings/notion/rag.htb/notion-export.md",
            "Source path": "findings/notion/rag.htb/notion-export.md",
            "source_sha256": "c" * 64,
            "retrieval_text": "Display-key source provenance must not bypass importer source filtering.",
        }

        self.assertTrue(
            importer._record_matches_filters(
                record,
                RagImportOptions(
                    chunks_dir="unused",
                    source_files={"findings/notion/rag.htb/notion-export.md"},
                ),
            )
        )

        chunk = importer._chunk_from_record(record, target_id="target_rag_corpus")
        artifact = importer._artifact_for_record(record, target_id="target_rag_corpus")

        self.assertEqual(chunk.title, "findings/notion/rag.htb/notion-export.md")
        self.assertEqual(artifact.path, "rag-preprocess:findings/notion/rag.htb/notion-export.md")
        self.assertEqual(artifact.metadata["doc_id"], "display-source-doc")
        self.assertEqual(artifact.metadata["source_file"], "findings/notion/rag.htb/notion-export.md")
        self.assertEqual(artifact.metadata["source_path"], "findings/notion/rag.htb/notion-export.md")

    def test_filter_accepts_human_readable_corpus_type_domain(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)
        record = {
            "chunk_id": "chunk_display_domain_filter",
            "Corpus type": "HTB Writeup",
            "source_sha256": "d" * 64,
            "retrieval_text": "Display domain filters should find canonicalized writeup chunks.",
        }

        self.assertTrue(
            importer._record_matches_filters(
                record,
                RagImportOptions(
                    chunks_dir="unused",
                    domains={"HTB Writeup"},
                ),
            )
        )

    def test_artifact_preserves_human_readable_source_hash_and_corpus(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)
        record = {
            "chunk_id": "chunk_display_source_hash_artifact",
            "Source ID": "display-vuln-source",
            "Source file": "CVE-2026-9000.vuln-intel-card",
            "Source SHA256": "f" * 64,
            "Corpus type": ["vulnerability_intel"],
            "Retrieval text": "Display-key source hash and corpus must remain advisory provenance.",
        }

        artifact = importer._artifact_for_record(record, target_id="target_rag_corpus")
        metadata = importer._metadata(record, domain=importer._domain(record))

        self.assertEqual(artifact.sha256, "f" * 64)
        self.assertEqual(artifact.metadata["domain"], "vuln_intel")
        self.assertEqual(metadata["source_sha256"], "f" * 64)
        self.assertEqual(metadata["domain"], "vuln_intel")
        self.assertEqual(metadata["corpus_type"], "vuln_intel")

    def test_metadata_canonicalizes_human_readable_writeup_corpus_type(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)
        record = {
            "chunk_id": "chunk_display_writeup_corpus",
            "Source SHA256": "e" * 64,
            "Corpus type": "HTB Writeup",
            "Writeup access policy": "Postmortem Only",
            "Purpose": "Postmortem",
            "Retrieval text": "Display-key writeup corpus metadata must remain writeup-gated after import.",
        }

        domain = importer._domain(record)
        metadata = importer._metadata(record, domain=domain)

        self.assertEqual(domain, "htb_writeup")
        self.assertEqual(metadata["domain"], "htb_writeup")
        self.assertEqual(metadata["corpus_type"], "htb_writeup")

    def test_best_record_id_preserves_human_readable_failure_ids(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)
        cases = [
            ({"Chunk ID": "chunk_display_failure"}, "chunk_display_failure"),
            ({"Record ID": "record_display_failure"}, "record_display_failure"),
            ({"Doc ID": "doc_display_failure"}, "doc_display_failure"),
            ({"metadata": {"Source ID": "source_display_failure"}}, "source_display_failure"),
        ]

        for record, expected_id in cases:
            with self.subTest(record=record):
                self.assertEqual(importer._best_record_id(json.dumps(record)), expected_id)

    def test_chunk_preserves_human_readable_chunk_fields(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)
        record = {
            "Chunk ID": "chunk_display_chunk_fields",
            "Retrieval text": "Display-key chunk text must preserve advisory RAG provenance.",
            "Source SHA256": "d" * 64,
            "Chunk index": 3,
            "Token estimate": 9,
            "Title": "Display-key chunk title",
        }

        chunk = importer._chunk_from_record(record, target_id="target_rag_corpus")

        self.assertEqual(chunk.id, "chunk_display_chunk_fields")
        self.assertEqual(chunk.text, "Display-key chunk text must preserve advisory RAG provenance.")
        self.assertEqual(chunk.source_sha256, "d" * 64)
        self.assertEqual(chunk.chunk_index, 3)
        self.assertEqual(chunk.token_count, 9)
        self.assertEqual(chunk.title, "Display-key chunk title")

    def test_metadata_derives_citation_id_when_chunk_id_is_missing(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)
        record = {
            "doc_id": "source_api",
            "source_sha256": "b" * 64,
            "chunk_index": 2,
            "retrieval_text": "Derived chunks must not serialize placeholder rag citations.",
        }

        metadata = importer._metadata(record, domain="api_security")
        expected_chunk_id = importer._derive_chunk_id(record, record["retrieval_text"], 2)

        self.assertEqual(metadata["citation_id"], f"rag:{expected_chunk_id}")
        self.assertNotEqual(metadata["citation_id"], "rag:None")

    def test_metadata_derives_citation_id_from_human_readable_chunk_fields(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)
        record = {
            "Source ID": "display-source-doc",
            "Source SHA256": "e" * 64,
            "Chunk index": 4,
            "Retrieval text": "Display-key chunk fields must produce stable RAG citations.",
        }
        canonical_record = {
            "source_id": "display-source-doc",
            "source_sha256": "e" * 64,
        }

        metadata = importer._metadata(record, domain="api_security")
        expected_chunk_id = importer._derive_chunk_id(canonical_record, record["Retrieval text"], 4)

        self.assertEqual(metadata["citation_id"], f"rag:{expected_chunk_id}")
        self.assertNotEqual(metadata["citation_id"], "rag:unknown")

    def test_metadata_preserves_human_readable_raw_text(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)
        raw_text = "Display-key raw advisory source text must remain hashable provenance."
        record = {
            "chunk_id": "chunk_display_raw_text",
            "source_type": "markdown",
            "Raw text": raw_text,
        }

        metadata = importer._metadata(record, domain="methodology_standards")

        self.assertEqual(metadata["raw_text"], raw_text)
        self.assertEqual(metadata["raw_text_sha256"], hashlib.sha256(raw_text.encode("utf-8")).hexdigest())

__all__ = ["RagChunkImporterMetadataTestsPart8"]
