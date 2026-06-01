from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from primordial.core.catalog.loader import CatalogValidationError
from primordial.core.catalog.rag_advisory_corpus import RagAdvisoryCorpusCatalog


REPO_ROOT = Path(__file__).resolve().parents[1]
RAG_SOURCE_PATHS = (
    "docs/RAG_SRC/0x10-api-security-risks.md",
    "docs/RAG_SRC/0x11-t10.md",
    "docs/RAG_SRC/0xa1-broken-object-level-authorization.md",
    "docs/RAG_SRC/0xa2-broken-authentication.md",
    "docs/RAG_SRC/0xa3-broken-object-property-level-authorization.md",
    "docs/RAG_SRC/0xa4-unrestricted-resource-consumption.md",
    "docs/RAG_SRC/0xa5-broken-function-level-authorization.md",
    "docs/RAG_SRC/0xa6-unrestricted-access-to-sensitive-business-flows.md",
    "docs/RAG_SRC/0xa7-server-side-request-forgery.md",
    "docs/RAG_SRC/0xa8-security-misconfiguration.md",
    "docs/RAG_SRC/0xa9-improper-inventory-management.md",
    "docs/RAG_SRC/0xaa-unsafe-consumption-of-apis.md",
    "docs/RAG_SRC/0xb0-next-devs.md",
    "docs/RAG_SRC/0xb1-next-devsecops.md",
    "docs/RAG_SRC/0xd0-about-data.md",
    "docs/RAG_SRC/0xd1-acknowledgments.md",
)


class RagAdvisoryCorpusCatalogTests(unittest.TestCase):
    def test_rag_source_markdown_is_migrated_to_typed_advisory_manifest(self) -> None:
        corpus = RagAdvisoryCorpusCatalog(REPO_ROOT / "catalog" / "rag").load()

        self.assertEqual(corpus.id, "owasp_api_security_top_10_2023")
        self.assertEqual(corpus.source_directory, "docs/RAG_SRC")
        self.assertEqual(corpus.status, "migrated_external_advisory_corpus")
        self.assertEqual(corpus.authority, "advisory_not_target_truth")
        self.assertEqual(corpus.source_type, "validated_external")
        self.assertEqual(corpus.corpus_type, "api_security_standards")
        self.assertFalse(corpus.source_markdown_ingest_allowed)
        self.assertFalse(corpus.operational_retrieval_allowed)
        self.assertIn("closed_book", corpus.denied_use_modes)
        self.assertIn("target_truth", corpus.denied_use_modes)
        self.assertIn("evidence", corpus.denied_use_modes)

    def test_all_docs_rag_src_files_are_listed_with_quarantine_destinations(self) -> None:
        corpus = RagAdvisoryCorpusCatalog(REPO_ROOT / "catalog" / "rag").load()
        documents = {document.source_path: document for document in corpus.documents}

        self.assertEqual(set(documents), set(RAG_SOURCE_PATHS))
        for source_path in RAG_SOURCE_PATHS:
            with self.subTest(source_path=source_path):
                document = documents[source_path]
                self.assertTrue(document.title)
                self.assertEqual(document.source_family, "owasp_api_security_top_10_2023")
                self.assertEqual(document.quarantine_path, f"runtime/quarantine/markdown/{source_path}")
                self.assertFalse(document.ingest_allowed)
                self.assertFalse(document.operational_retrieval_allowed)

    def test_catalog_rejects_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "advisory_corpus.yaml").write_text(
                "id: owasp_api_security_top_10_2023\n"
                "source_directory: docs/RAG_SRC\n"
                "status: migrated_external_advisory_corpus\n"
                "authority: advisory_not_target_truth\n"
                "source_type: validated_external\n"
                "corpus_type: api_security_standards\n"
                "source_markdown_ingest_allowed: false\n"
                "operational_retrieval_allowed: false\n"
                "allowed_use_modes: []\n"
                "denied_use_modes: []\n"
                "documents: []\n"
                "unknown: true\n",
                encoding="utf-8",
            )

            with self.assertRaises(CatalogValidationError):
                RagAdvisoryCorpusCatalog(root).load()


if __name__ == "__main__":
    unittest.main()
