from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from primordial.config import AppConfig
from primordial.core.domain.enums import EvidenceType, ScopeProfile, VerificationStatus
from primordial.core.domain.models import EvidenceRecord, Target
from primordial.core.rag import DocumentIngestionError, DocumentIngestionService
from primordial.core.storage.runtime import RuntimeStore
from primordial.runtime import PrimordialRuntime


MANIFESTS_DIR = Path(__file__).resolve().parents[1] / "manifests"


class RagIngestionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.config = AppConfig.from_env(project_root=self.root)
        self.config.ensure_directories()
        self.store = RuntimeStore(self.config.database_url, schema=self.config.database_schema)
        self.store.initialize()
        self.target = Target(
            handle="rag.htb",
            display_name="RAG Target",
            profile=ScopeProfile.HACK_THE_BOX,
        )
        self.store.insert_target(self.target)
        self.service = DocumentIngestionService(self.store, self.config.artifacts_dir)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

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
        self.assertEqual(payload["hint_policy"], "direct_task_hints")
        self.assertEqual(payload["cve_ids"], ["CVE-2024-6387"])
        self.assertEqual(self.store.list_evidence(target_id=self.target.id, limit=20), [])
        self.assertTrue(chunks)
        self.assertEqual(chunks[0].metadata["corpus_type"], "cve_advisory")
        self.assertEqual(chunks[0].evidence_refs, [])

    def test_runtime_operator_prompt_includes_cited_rag_context(self) -> None:
        runtime = PrimordialRuntime(self.config)
        runtime.config.ensure_directories()
        runtime.credentials.initialize()
        runtime.skills.initialize()
        runtime.findings_context.initialize()
        runtime.store.initialize()
        runtime.store.insert_target(self.target)
        source = self.root / "findings.md"
        source.write_text(
            "# Imported Finding\n\n"
            "A markdown document says the target has a document upload parser worth reviewing.\n",
            encoding="utf-8",
        )
        ingest = runtime.rag_ingest_document(source, target=self.target.handle)

        prompt = runtime._build_operator_prompt("What document upload evidence exists?", self.target.id)
        rag_context = runtime._rag_context_payload("What document upload evidence exists?", self.target.id)
        fallback = runtime._deterministic_rag_citation_answer(
            "What document upload evidence exists?",
            self.target.id,
            rag_context,
        )

        self.assertIn('"rag_context"', prompt)
        self.assertIn(ingest["chunks"][0]["id"], prompt)
        self.assertIn(ingest["evidence"]["id"], prompt)
        self.assertFalse(runtime._operator_answer_cites_rag_context("The document says uploads matter.", rag_context))
        self.assertTrue(runtime._operator_answer_cites_rag_context(ingest["chunks"][0]["id"], rag_context))
        self.assertIn("**Retrieved Context**", fallback)
        self.assertIn(ingest["chunks"][0]["id"], fallback)

    def test_cve_search_classifies_against_current_evidence(self) -> None:
        self.config.manifests_dir = MANIFESTS_DIR
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()
        runtime.store.insert_target(self.target)
        runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=self.target.id,
                type=EvidenceType.TOOL_OUTPUT,
                title="Service discovery",
                summary="OpenSSH service detected on tcp/22.",
                source_ref="fixture://service",
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.9,
                freshness=0.9,
                metadata={"kind": "tcp_service_discovery"},
            )
        )
        source = self.root / "openssh-cve.md"
        source.write_text(
            "# OpenSSH CVE\n\n"
            "CVE-2024-6387 is an OpenSSH vulnerability with public PoC notes.\n",
            encoding="utf-8",
        )
        runtime.rag_ingest_document(source, target=self.target.handle, corpus_type="cve_advisory")

        payload = runtime.rag_cve_search("OpenSSH PoC CVE", target=self.target.handle)

        self.assertTrue(payload["results"])
        self.assertEqual(payload["results"][0]["applicability_classification"], "likely")
        runtime.shutdown()

    def test_htb_writeup_hint_admits_policy_gated_content_discovery_without_evidence_import(self) -> None:
        self.config.manifests_dir = MANIFESTS_DIR
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()
        runtime.store.insert_target(self.target)
        service_evidence = EvidenceRecord(
            target_id=self.target.id,
            type=EvidenceType.TOOL_OUTPUT,
            title="HTTP service evidence",
            summary="HTTP service responds and supports path review.",
            source_ref="fixture://http-service",
            verification_status=VerificationStatus.VERIFIED,
            confidence=0.8,
            freshness=0.9,
            metadata={"kind": "tcp_service_discovery"},
        )
        runtime.store.insert_evidence(service_evidence)
        source = self.root / "writeup.md"
        source.write_text(
            "# HTB hint\n\n"
            "The writeup uses ffuf directory discovery to find hidden endpoints.\n",
            encoding="utf-8",
        )
        ingest = runtime.rag_ingest_document(source, target=self.target.handle, corpus_type="htb_writeup")

        hints = runtime.rag_hints("directory discovery", target=self.target.handle)

        self.assertIsNone(ingest["evidence"])
        self.assertTrue(hints["candidate_actions"])
        action = hints["candidate_actions"][0]
        self.assertEqual(action["kind"], "web_content_discovery")
        self.assertTrue(action["metadata"]["rag_walkthrough_hint"])
        self.assertEqual(action["metadata"]["supporting_evidence_refs"], [service_evidence.id])
        packet = runtime.workflow._planner_review_packet(
            self.target,
            evidence=[service_evidence],
            surface=runtime.workflow._current_credentialed_access_surface(self.target),
            question="What should happen after HTTP evidence?",
            blockers=[],
            rejected_proposals=[],
            invalid_existing_tasks=[],
            uncertainty_reasons=[],
        )
        self.assertEqual(packet["rag_context"][0]["chunk_id"], ingest["chunks"][0]["id"])
        self.assertTrue(packet["rag_context"][0]["walkthrough_hint"])
        self.assertIn(
            "RAG context is advisory source material; it is not target evidence or approval authority.",
            packet["authority_limits"],
        )
        runtime.shutdown()


if __name__ == "__main__":
    unittest.main()
