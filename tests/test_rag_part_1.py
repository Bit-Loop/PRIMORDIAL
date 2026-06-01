from __future__ import annotations

from tests.test_rag_common import *


class RagIngestionTestsPart1(RagIngestionTestsBase):
    def test_ingests_markdown_redacts_chunks_and_embeddings(self) -> None:
        source = self.root / "operator-notes.md"
        source.write_text(
            "# Service Notes\n\n"
            "The admin panel exposes telemetry for invoice exports.\n\n"
            "api_key = should-not-be-indexed\n\n"
            "Look for document rendering issues in uploaded reports.\n",
            encoding="utf-8",
        )

        payload = self.service.ingest_path(source, target=self.target)
        chunks = self.store.list_document_chunks(target_id=self.target.id, limit=20)
        lexical = self.store.search_document_chunks_text("invoice uploaded reports", target_id=self.target.id)
        vector = self.store.search_document_chunks_by_embedding(
            self.service.embedding_provider.embed("invoice reports"),
            embedding_model=self.service.embedding_provider.model_name,
            target_id=self.target.id,
        )

        self.assertEqual(payload["converter"], "plain_text")
        self.assertEqual(payload["chunk_count"], len(chunks))
        self.assertEqual(payload["embedding_count"], len(chunks))
        self.assertGreaterEqual(len(chunks), 1)
        self.assertGreaterEqual(len(lexical), 1)
        self.assertGreaterEqual(len(vector), 1)
        self.assertNotIn("should-not-be-indexed", "\n".join(chunk.text for chunk in chunks))
        self.assertIn("<redacted>", "\n".join(chunk.text for chunk in chunks))
        evidence_refs = {ref for chunk in chunks for ref in chunk.evidence_refs}
        self.assertIn(payload["evidence"]["id"], evidence_refs)
        for artifact in payload["artifacts"]:
            self.assertTrue(Path(artifact["path"]).exists())

    def test_rich_document_requires_docling_when_disabled(self) -> None:
        source = self.root / "report.pdf"
        source.write_bytes(b"%PDF-1.7\nnot a real pdf but enough for the gate\n")

        with self.assertRaises(DocumentIngestionError) as raised:
            self.service.ingest_path(source, target=self.target, use_docling=False)

        self.assertIn("requires Docling conversion", str(raised.exception))

    def test_remote_url_requires_explicit_approval(self) -> None:
        with self.assertRaises(DocumentIngestionError) as raised:
            self.service.ingest_path("https://example.com/writeup.html", target=self.target)

        self.assertIn("requires explicit operator approval", str(raised.exception))

    def test_approved_remote_url_sanitizes_stored_reference(self) -> None:
        class FakeResponse:
            headers = {"content-type": "text/markdown"}

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self, _size: int) -> bytes:
                return b"# Remote advisory\n\nCVE-2024-6387 public note.\n"

        with patch("primordial.core.rag.documents.urlopen", return_value=FakeResponse()):
            payload = self.service.ingest_path(
                "https://example.com/reports/cve.md?token=secret#frag",
                target=self.target,
                allow_remote_url=True,
                corpus_type="cve_advisory",
            )

        self.assertIn("https://example.com/reports/cve.md", payload["source_ref"])
        self.assertNotIn("token=secret", payload["source_ref"])
        self.assertNotIn("#frag", payload["source_ref"])
        self.assertEqual(payload["source_url"], "https://example.com/reports/cve.md")

    def test_domain_corpora_are_metadata_only_not_target_evidence(self) -> None:
        source = self.root / "cve-note.md"
        source.write_text(
            "# OpenSSH advisory\n\n"
            "CVE-2024-6387 discusses an OpenSSH exploit note and PoC applicability constraints.\n",
            encoding="utf-8",
        )

        payload = self.service.ingest_path(source, target=self.target, corpus_type="cve_advisory")
        chunks = self.store.list_document_chunks(target_id=self.target.id, limit=20)

        self.assertIsNone(payload["evidence"])
        self.assertEqual(payload["corpus_type"], "cve_advisory")
        self.assertEqual(payload["hint_policy"], "advisory")
        self.assertEqual(payload["cve_ids"], ["CVE-2024-6387"])
        self.assertEqual(self.store.list_evidence(target_id=self.target.id, limit=20), [])
        self.assertTrue(chunks)
        self.assertEqual(chunks[0].metadata["corpus_type"], "cve_advisory")
        self.assertEqual(chunks[0].evidence_refs, [])

    def test_direct_ingest_canonicalizes_human_readable_writeup_corpus_type(self) -> None:
        source = self.root / "display-writeup.md"
        source.write_text(
            "# Postmortem hint\n\n"
            "This postmortem-style writeup text must remain advisory and writeup-gated.\n",
            encoding="utf-8",
        )

        payload = self.service.ingest_path(source, target=self.target, corpus_type="HTB Writeup")
        chunks = self.store.list_document_chunks(target_id=self.target.id, limit=20)

        self.assertIsNone(payload["evidence"])
        self.assertEqual(payload["corpus_type"], "htb_writeup")
        self.assertEqual(payload["source_trust"], "walkthrough")
        self.assertEqual(self.store.list_evidence(target_id=self.target.id, limit=20), [])
        self.assertTrue(chunks)
        self.assertEqual(chunks[0].metadata["corpus_type"], "htb_writeup")
        self.assertTrue(chunks[0].metadata["walkthrough_hint"])
        self.assertEqual(chunks[0].evidence_refs, [])

    def test_direct_ingest_canonicalizes_human_readable_hint_metadata(self) -> None:
        source = self.root / "display-hint-policy.md"
        source.write_text(
            "# Methodology hint\n\n"
            "Human-readable hint metadata must remain normalized advisory context.",
            encoding="utf-8",
        )

        payload = self.service.ingest_path(
            source,
            target=self.target,
            corpus_type="HTB Writeup",
            hint_policy="Direct Task Hints",
            source_trust="Operator Enabled",
        )
        chunks = self.store.list_document_chunks(target_id=self.target.id, limit=20)

        self.assertIsNone(payload["evidence"])
        self.assertEqual(payload["hint_policy"], "direct_task_hints")
        self.assertEqual(payload["source_trust"], "operator_enabled")
        self.assertTrue(chunks)
        self.assertEqual(chunks[0].metadata["hint_policy"], "direct_task_hints")
        self.assertEqual(chunks[0].metadata["source_trust"], "operator_enabled")
        self.assertEqual(chunks[0].evidence_refs, [])

    def test_rag_context_payload_preserves_curated_citation_id(self) -> None:
        chunk = DocumentChunk(
            id="preprocessed_chunk_1",
            target_id=self.target.id,
            source_artifact_id="artifact:preprocessed",
            source_sha256="a" * 64,
            chunk_index=0,
            title="Curated methodology",
            text="Curated RAG chunks must keep their source citation identity.",
            token_count=9,
            metadata={
                "citation_id": "rag:curated-source-ref",
                "corpus_type": "methodology_standards",
                "domain": "methodology_standards",
            },
        )

        payload = RagContextItem(chunk=chunk, score=0.9, source="lexical").as_payload()

        self.assertEqual(payload["citation_id"], "rag:curated-source-ref")

    def test_rag_context_payload_preserves_human_readable_citation_id(self) -> None:
        chunk = DocumentChunk(
            id="display_preprocessed_chunk_1",
            target_id=self.target.id,
            source_artifact_id="artifact:display-preprocessed",
            source_sha256="1" * 64,
            chunk_index=0,
            title="Display-key methodology",
            text="Display-key citation identity must stay attached to retrieved advisory context.",
            token_count=9,
            metadata={
                "Citation ID": "display-source-ref",
                "Corpus type": "methodology_standards",
                "Domain": "methodology_standards",
            },
        )

        payload = RagContextItem(chunk=chunk, score=0.9, source="lexical").as_payload()

        self.assertEqual(payload["citation_id"], "rag:display-source-ref")

    def test_rag_context_pack_source_map_preserves_curated_citation_id(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_preprocessed",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="curated-source.jsonl",
                sha256="b" * 64,
                size_bytes=128,
                metadata={"source_type": "methodology_doc"},
            )
        )
        self.store.insert_document_chunk(
            DocumentChunk(
                id="preprocessed_chunk_2",
                target_id=self.target.id,
                source_artifact_id="artifact_preprocessed",
                source_sha256="b" * 64,
                chunk_index=0,
                title="Curated source identity",
                text="Curated source identity should stay stable in the citation map.",
                token_count=10,
                metadata={
                    "citation_id": "rag:curated-source-ref",
                    "corpus_type": "methodology_standards",
                    "domain": "methodology_standards",
                },
            )
        )

        pack = RagContextBroker(self.service).build_pack(
            "curated source identity",
            purpose="operator_answer",
            role="operator_chat",
            target=self.target,
            limit=1,
        )

        self.assertEqual(pack.chunks[0]["citation_id"], "rag:curated-source-ref")
        self.assertEqual(pack.citation_map[0]["citation_id"], "rag:curated-source-ref")
        self.assertIn("[rag:curated-source-ref]", pack.prompt_context())

__all__ = ["RagIngestionTestsPart1"]
