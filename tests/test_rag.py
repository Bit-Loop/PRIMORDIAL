from __future__ import annotations

from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch

from primordial.config import AppConfig
from primordial.core.domain.enums import (
    AgentRole,
    ArtifactKind,
    EvidenceType,
    MethodologyPhase,
    ScopeProfile,
    TaskKind,
    VerificationStatus,
)
from primordial.core.domain.models import ArtifactRecord, DocumentChunk, EvidenceRecord, Target, Task
from primordial.core.providers.ollama import OllamaEmbeddingResponse, OllamaModelListResult
from primordial.core.rag import DeterministicHashEmbeddingProvider, DocumentIngestionError, DocumentIngestionService
from primordial.core.rag.citations import disallowed_rag_synthesis_model, validate_rag_citations
from primordial.core.rag.context import RagContextBroker, RagContextPack
from primordial.core.rag.documents import RagContextItem
from primordial.core.rag.embeddings import OllamaEmbeddingProvider
from primordial.core.rag.importer import RagChunkImporter, RagImportOptions
from primordial.core.storage.runtime import RuntimeStore
from primordial.runtime import PrimordialRuntime


MANIFESTS_DIR = Path(__file__).resolve().parents[1] / "manifests"


class RagContextBrokerPolicyTests(unittest.TestCase):
    def test_operator_rag_pack_omits_closed_book_writeup_chunks(self) -> None:
        target = Target(
            handle="closed-book.htb",
            display_name="Closed Book Target",
            profile=ScopeProfile.HACK_THE_BOX,
        )
        chunk = DocumentChunk(
            id="closed_book_writeup_chunk",
            target_id=target.id,
            source_artifact_id="artifact:closed-book-writeup",
            source_sha256="8" * 64,
            chunk_index=0,
            title="Closed-book writeup",
            text="Closed-book writeup hints must not enter operational RAG prompts.",
            token_count=10,
            metadata={
                "citation_id": "rag:closed-book-writeup",
                "corpus_type": "htb_writeup",
                "domain": "htb_writeup",
                "source_type": "writeup",
                "benchmark_mode": "closed_book",
            },
        )

        pack = RagContextBroker(_StaticRagService([chunk])).build_pack(
            "closed book writeup hints",
            purpose="operator_answer",
            role="operator_chat",
            target=target,
            limit=5,
        )

        self.assertEqual(pack.chunks, [])
        self.assertEqual(pack.omitted_sources[0]["citation_id"], "rag:closed-book-writeup")
        self.assertIn("writeup in closed_book", pack.omitted_sources[0]["reason"])
        self.assertNotIn("Closed-book writeup hints", pack.prompt_context())

    def test_operator_rag_pack_omits_human_readable_restricted_visibility_chunks(self) -> None:
        chunk = DocumentChunk(
            id="display_restricted_visibility_chunk",
            target_id=None,
            source_artifact_id="artifact:restricted-visibility",
            source_sha256="9" * 64,
            chunk_index=0,
            title="Restricted visibility advisory",
            text="Restricted advisory context must require explicit gated use.",
            token_count=9,
            metadata={
                "citation_id": "rag:restricted-visibility",
                "corpus_type": "api_security",
                "domain": "api_security",
                "source_type": "methodology_doc",
                "Planner Visibility": "Restricted",
            },
        )

        pack = RagContextBroker(_StaticRagService([chunk])).build_pack(
            "restricted advisory context",
            purpose="operator_answer",
            role="operator_chat",
            limit=5,
        )

        self.assertEqual(pack.chunks, [])
        self.assertEqual(pack.omitted_sources[0]["citation_id"], "rag:restricted-visibility")
        self.assertIn("restricted source requires explicit gated", pack.omitted_sources[0]["reason"])
        self.assertNotIn("Restricted advisory context", pack.prompt_context())

    def test_operator_rag_pack_normalizes_human_readable_omitted_risk_level(self) -> None:
        chunk = DocumentChunk(
            id="display_restricted_risk_chunk",
            target_id=None,
            source_artifact_id="artifact:restricted-risk",
            source_sha256="e" * 64,
            chunk_index=0,
            title="Restricted risk advisory",
            text="Exploit validation advisory context must remain gated.",
            token_count=8,
            metadata={
                "citation_id": "rag:restricted-risk",
                "corpus_type": "api_security",
                "domain": "api_security",
                "source_type": "methodology_doc",
                "Risk Level": "Exploit Validation",
            },
        )

        pack = RagContextBroker(_StaticRagService([chunk])).build_pack(
            "exploit validation advisory context",
            purpose="operator_answer",
            role="operator_chat",
            limit=5,
        )

        self.assertEqual(pack.chunks, [])
        self.assertEqual(pack.omitted_sources[0]["citation_id"], "rag:restricted-risk")
        self.assertEqual(pack.omitted_sources[0]["risk_level"], "exploit_validation")
        self.assertIn("restricted source requires explicit gated", pack.omitted_sources[0]["reason"])

    def test_action_selection_omits_human_readable_taxonomy_only_visibility_chunks(self) -> None:
        chunk = DocumentChunk(
            id="display_taxonomy_only_chunk",
            target_id=None,
            source_artifact_id="artifact:taxonomy-only",
            source_sha256="a" * 64,
            chunk_index=0,
            title="Taxonomy-only advisory",
            text="Taxonomy-only advisory context must not drive action selection.",
            token_count=9,
            metadata={
                "citation_id": "rag:taxonomy-only",
                "corpus_type": "api_security",
                "domain": "api_security",
                "source_type": "methodology_doc",
                "Planner Visibility": "Taxonomy Only",
            },
        )

        pack = RagContextBroker(_StaticRagService([chunk])).build_pack(
            "taxonomy action selection",
            purpose="action_selection",
            role="operator_chat",
            limit=5,
        )

        self.assertEqual(pack.chunks, [])
        self.assertEqual(pack.omitted_sources[0]["citation_id"], "rag:taxonomy-only")
        self.assertIn("taxonomy-only material cannot drive action selection", pack.omitted_sources[0]["reason"])
        self.assertNotIn("Taxonomy-only advisory context", pack.prompt_context())

    def test_rag_synthesis_marks_human_readable_taxonomy_visibility_usage_policy(self) -> None:
        chunk = DocumentChunk(
            id="display_taxonomy_policy_chunk",
            target_id=None,
            source_artifact_id="artifact:taxonomy-policy",
            source_sha256="d" * 64,
            chunk_index=0,
            title="Taxonomy policy advisory",
            text="Taxonomy-only advisory context may be cited for synthesis but not action selection.",
            token_count=10,
            metadata={
                "citation_id": "rag:taxonomy-policy",
                "corpus_type": "api_security",
                "domain": "api_security",
                "source_type": "methodology_doc",
                "Planner Visibility": "Taxonomy Only",
            },
        )

        pack = RagContextBroker(_StaticRagService([chunk])).build_pack(
            "taxonomy policy advisory",
            purpose="rag_synthesis",
            role="report_writer",
            limit=5,
        )

        self.assertEqual([item["citation_id"] for item in pack.chunks], ["rag:taxonomy-policy"])
        self.assertEqual(pack.chunks[0]["metadata"]["usage_policy"], "taxonomy_only")
        self.assertEqual(pack.citation_map[0]["usage_policy"], "taxonomy_only")
        self.assertEqual(pack.citation_map[0]["planner_visibility"], "taxonomy_only")

    def test_operator_rag_pack_accepts_human_readable_safe_domain_chunks(self) -> None:
        chunk = DocumentChunk(
            id="display_api_security_domain_chunk",
            target_id=None,
            source_artifact_id="artifact:api-security-domain",
            source_sha256="b" * 64,
            chunk_index=0,
            title="API security advisory",
            text="API security advisory context should remain available as safe planning RAG.",
            token_count=10,
            metadata={
                "citation_id": "rag:api-security-display-domain",
                "corpus_type": "API Security",
                "Domain": "API Security",
                "source_type": "methodology_doc",
            },
        )

        pack = RagContextBroker(_StaticRagService([chunk])).build_pack(
            "api security advisory",
            purpose="operator_answer",
            role="operator_chat",
            limit=5,
        )

        self.assertEqual([item["citation_id"] for item in pack.chunks], ["rag:api-security-display-domain"])
        self.assertEqual(pack.chunks[0]["metadata"]["domain"], "api_security")
        self.assertEqual(pack.chunks[0]["metadata"]["corpus_type"], "api_security")
        self.assertEqual(pack.chunks[0]["corpus_type"], "api_security")
        self.assertEqual(pack.omitted_sources, [])

    def test_operator_rag_pack_accepts_human_readable_false_operator_approval_chunks(self) -> None:
        chunk = DocumentChunk(
            id="display_false_operator_approval_chunk",
            target_id=None,
            source_artifact_id="artifact:false-operator-approval",
            source_sha256="c" * 64,
            chunk_index=0,
            title="False operator approval advisory",
            text="Safe advisory context with a display false approval marker should remain available.",
            token_count=10,
            metadata={
                "citation_id": "rag:false-operator-approval",
                "corpus_type": "api_security",
                "domain": "api_security",
                "source_type": "methodology_doc",
                "Requires Operator Approval": "False",
            },
        )

        pack = RagContextBroker(_StaticRagService([chunk])).build_pack(
            "false operator approval advisory",
            purpose="operator_answer",
            role="operator_chat",
            limit=5,
        )

        self.assertEqual([item["citation_id"] for item in pack.chunks], ["rag:false-operator-approval"])
        self.assertEqual(pack.omitted_sources, [])

    def test_operator_rag_pack_normalizes_human_readable_hint_metadata(self) -> None:
        chunk = DocumentChunk(
            id="display_hint_metadata_chunk",
            target_id=None,
            source_artifact_id="artifact:display-hint-metadata",
            source_sha256="f" * 64,
            chunk_index=0,
            title="Display hint metadata advisory",
            text="Safe advisory context should carry normalized hint metadata into the pack.",
            token_count=10,
            metadata={
                "citation_id": "rag:display-hint-metadata",
                "corpus_type": "api_security",
                "domain": "api_security",
                "source_type": "methodology_doc",
                "Source Trust": "Operator Enabled",
                "Hint Policy": "Direct Task Hints",
            },
        )

        pack = RagContextBroker(_StaticRagService([chunk])).build_pack(
            "display hint metadata advisory",
            purpose="operator_answer",
            role="operator_chat",
            limit=5,
        )

        self.assertEqual([item["citation_id"] for item in pack.chunks], ["rag:display-hint-metadata"])
        self.assertEqual(pack.chunks[0]["metadata"]["source_trust"], "operator_enabled")
        self.assertEqual(pack.chunks[0]["metadata"]["hint_policy"], "direct_task_hints")
        self.assertEqual(pack.chunks[0]["source_trust"], "operator_enabled")
        self.assertEqual(pack.chunks[0]["hint_policy"], "direct_task_hints")


class _StaticRagService:
    def __init__(self, chunks: list[DocumentChunk]) -> None:
        self._items = [RagContextItem(chunk=chunk, score=1.0, source="test") for chunk in chunks]

    def retrieve(
        self,
        query: str,
        *,
        target_id: str | None,
        limit: int,
        filters: dict[str, object] | None,
    ) -> list[RagContextItem]:
        return self._items[:limit]


class RagIngestionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.config = AppConfig.from_env(project_root=self.root)
        self.config.rag.embeddings.provider = "deterministic_hash"
        self.config.ensure_directories()
        self.store = RuntimeStore(self.config.database_url, schema=self.config.database_schema)
        self.store.initialize()
        self.target = Target(
            handle="rag.htb",
            display_name="RAG Target",
            profile=ScopeProfile.HACK_THE_BOX,
        )
        self.store.insert_target(self.target)
        self.service = DocumentIngestionService(
            self.store,
            self.config.artifacts_dir,
            embedding_provider=DeterministicHashEmbeddingProvider(),
        )

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

    def test_rag_context_pack_normalizes_uppercase_rag_citation_prefix(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_uppercase_preprocessed",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="uppercase-preprocessed.jsonl",
                sha256="6" * 64,
                size_bytes=128,
                metadata={"source_type": "methodology_doc"},
            )
        )
        self.store.insert_document_chunk(
            DocumentChunk(
                id="uppercase_preprocessed_chunk",
                target_id=self.target.id,
                source_artifact_id="artifact_uppercase_preprocessed",
                source_sha256="6" * 64,
                chunk_index=0,
                title="Uppercase curated source",
                text="Retrieved RAG pack citations should use canonical lowercase prefixes.",
                token_count=9,
                metadata={
                    "citation_id": "RAG:uppercase-curated-source",
                    "corpus_type": "methodology_standards",
                    "domain": "methodology_standards",
                },
            )
        )

        pack = RagContextBroker(self.service).build_pack(
            "uppercase curated source",
            purpose="operator_answer",
            role="operator_chat",
            target=self.target,
            limit=1,
        )

        self.assertEqual(pack.chunks[0]["citation_id"], "rag:uppercase-curated-source")
        self.assertEqual(pack.citation_map[0]["citation_id"], "rag:uppercase-curated-source")
        self.assertIn("[rag:uppercase-curated-source]", pack.prompt_context())

    def test_rag_context_pack_preserves_human_readable_source_metadata(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_display_preprocessed",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="display-preprocessed.jsonl",
                sha256="3" * 64,
                size_bytes=128,
                metadata={"source_type": "methodology_doc"},
            )
        )
        self.store.insert_document_chunk(
            DocumentChunk(
                id="display_preprocessed_chunk",
                target_id=self.target.id,
                source_artifact_id="artifact_display_preprocessed",
                source_sha256="3" * 64,
                chunk_index=0,
                title="",
                text="Display-key source metadata should survive retrieved RAG pack rendering.",
                token_count=9,
                metadata={
                    "Citation ID": "display-pack-source",
                    "Title": "Display pack title",
                    "Source file": "curated/display-pack.md",
                    "Section": "Display pack section",
                    "Page start": 7,
                    "Page end": 8,
                    "Domain": "api_security",
                },
            )
        )

        pack = RagContextBroker(self.service).build_pack(
            "display key source metadata rendering",
            purpose="operator_answer",
            role="operator_chat",
            target=self.target,
            limit=1,
        )

        self.assertEqual(pack.citation_map[0]["citation_id"], "rag:display-pack-source")
        self.assertEqual(pack.citation_map[0]["source_file"], "curated/display-pack.md")
        self.assertEqual(pack.citation_map[0]["source_display"], "Display pack section (curated/display-pack.md pp. 7-8)")
        self.assertIn("[rag:display-pack-source]", pack.prompt_context())

    def test_rag_context_pack_preserves_human_readable_source_display_metadata(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_display_source_label",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="display-source-label.jsonl",
                sha256="8" * 64,
                size_bytes=128,
                metadata={"source_type": "methodology_doc"},
            )
        )
        self.store.insert_document_chunk(
            DocumentChunk(
                id="display_source_label_chunk",
                target_id=self.target.id,
                source_artifact_id="artifact_display_source_label",
                source_sha256="8" * 64,
                chunk_index=0,
                title="",
                text="Display-key source labels should survive retrieved RAG pack rendering.",
                token_count=9,
                metadata={
                    "Citation ID": "display-pack-source-label",
                    "Domain": "api_security",
                    "Source display": "Curated display label from stored source metadata",
                },
            )
        )

        pack = RagContextBroker(self.service).build_pack(
            "display key source label rendering",
            purpose="operator_answer",
            role="operator_chat",
            target=self.target,
            limit=1,
        )

        self.assertEqual(pack.citation_map[0]["citation_id"], "rag:display-pack-source-label")
        self.assertEqual(pack.citation_map[0]["source_display"], "Curated display label from stored source metadata")
        self.assertIn("[rag:display-pack-source-label] Curated display label from stored source metadata", pack.prompt_context())

    def test_rag_context_pack_prompt_labels_human_readable_domain(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_display_domain",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="display-domain.jsonl",
                sha256="5" * 64,
                size_bytes=128,
                metadata={"source_type": "methodology_doc"},
            )
        )
        self.store.insert_document_chunk(
            DocumentChunk(
                id="display_domain_chunk",
                target_id=self.target.id,
                source_artifact_id="artifact_display_domain",
                source_sha256="5" * 64,
                chunk_index=0,
                title="Display domain label",
                text="Display-key domain metadata should remain visible in prompt labels.",
                token_count=9,
                metadata={
                    "Citation ID": "display-domain-source",
                    "Domain": "api_security",
                },
            )
        )

        pack = RagContextBroker(self.service).build_pack(
            "display key domain prompt label",
            purpose="operator_answer",
            role="operator_chat",
            target=self.target,
            limit=1,
        )

        rendered = pack.prompt_context()

        self.assertIn("[rag:display-domain-source]", rendered)
        self.assertIn("domain=api_security", rendered)
        self.assertEqual(pack.chunks[0]["metadata"]["domain"], "api_security")

    def test_rag_context_pack_preserves_human_readable_hint_metadata(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_display_hint_metadata",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="display-hint-metadata.jsonl",
                sha256="6" * 64,
                size_bytes=128,
                metadata={"source_type": "vuln_intel_card"},
            )
        )
        self.store.insert_document_chunk(
            DocumentChunk(
                id="display_hint_metadata_chunk",
                target_id=self.target.id,
                source_artifact_id="artifact_display_hint_metadata",
                source_sha256="6" * 64,
                chunk_index=0,
                title="Display hint metadata",
                text="Display-key advisory hint metadata should remain machine-readable.",
                token_count=9,
                metadata={
                    "Citation ID": "display-hint-metadata-source",
                    "Domain": "cve_advisory",
                    "Source trust": "official_feed",
                    "Hint policy": "advisory",
                    "CVE IDs": ["CVE-2026-0001"],
                    "Walkthrough hint": True,
                },
            )
        )

        pack = RagContextBroker(self.service).build_pack(
            "display key advisory hint metadata",
            purpose="operator_answer",
            role="operator_chat",
            target=self.target,
            limit=1,
        )
        chunk = pack.chunks[0]

        self.assertEqual(chunk["source_trust"], "official_feed")
        self.assertEqual(chunk["hint_policy"], "advisory")
        self.assertEqual(chunk["cve_ids"], ["CVE-2026-0001"])
        self.assertTrue(chunk["walkthrough_hint"])
        self.assertEqual(chunk["metadata"]["source_trust"], "official_feed")
        self.assertEqual(chunk["metadata"]["hint_policy"], "advisory")

    def test_rag_context_pack_blocks_human_readable_taxonomy_metadata_for_actions(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_display_taxonomy",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="display-taxonomy.jsonl",
                sha256="4" * 64,
                size_bytes=128,
                metadata={"source_type": "methodology_doc"},
            )
        )
        self.store.insert_document_chunk(
            DocumentChunk(
                id="display_taxonomy_chunk",
                target_id=self.target.id,
                source_artifact_id="artifact_display_taxonomy",
                source_sha256="4" * 64,
                chunk_index=0,
                title="",
                text="Display-key taxonomy context is useful for mapping but cannot drive action selection.",
                token_count=11,
                metadata={
                    "Citation ID": "display-taxonomy-source",
                    "Domain": "mitre_attack",
                    "Planner Visibility": "taxonomy_only",
                },
            )
        )

        pack = RagContextBroker(self.service).build_pack(
            "display key taxonomy action selection",
            purpose="action_selection",
            role="operator_chat",
            target=self.target,
            limit=1,
        )

        self.assertEqual(pack.chunks, [])
        self.assertEqual(pack.omitted_sources[0]["citation_id"], "rag:display-taxonomy-source")
        self.assertIn("taxonomy-only", pack.omitted_sources[0]["reason"])

    def test_rag_citation_map_normalizes_curated_citation_id_prefix(self) -> None:
        citation_map = RagContextBroker(self.service).citation_map_for_chunks(
            [
                {
                    "chunk_id": "preprocessed_chunk_prefix",
                    "citation_id": "curated-source-without-prefix",
                    "title": "Curated prefix source",
                    "metadata": {
                        "corpus_type": "methodology_standards",
                        "domain": "methodology_standards",
                    },
                }
            ]
        )

        self.assertEqual(citation_map[0]["citation_id"], "rag:curated-source-without-prefix")

    def test_rag_citation_map_normalizes_uppercase_rag_citation_prefix(self) -> None:
        citation_map = RagContextBroker(self.service).citation_map_for_chunks(
            [
                {
                    "chunk_id": "display_uppercase_prefix_chunk",
                    "Citation ID": "RAG:display-uppercase-prefix",
                    "title": "Display uppercase citation prefix source",
                    "metadata": {
                        "corpus_type": "methodology_standards",
                        "domain": "methodology_standards",
                    },
                }
            ]
        )

        self.assertEqual(citation_map[0]["citation_id"], "rag:display-uppercase-prefix")

    def test_rag_citation_map_uses_top_level_human_readable_citation_id(self) -> None:
        citation_map = RagContextBroker(self.service).citation_map_for_chunks(
            [
                {
                    "chunk_id": "display_top_level_citation_chunk",
                    "Citation ID": "display-top-level-source",
                    "title": "Display top-level citation source",
                    "metadata": {
                        "corpus_type": "methodology_standards",
                        "domain": "methodology_standards",
                    },
                }
            ]
        )

        self.assertEqual(citation_map[0]["citation_id"], "rag:display-top-level-source")

    def test_rag_citation_map_preserves_human_readable_source_metadata(self) -> None:
        citation_map = RagContextBroker(self.service).citation_map_for_chunks(
            [
                {
                    "chunk_id": "display_source_chunk",
                    "text": "Display-key source metadata should survive citation-map rendering.",
                    "metadata": {
                        "Citation ID": "display-source-ref",
                        "Title": "Display source title",
                        "Source file": "curated/display-source.md",
                        "Section": "Display source section",
                        "Page start": 3,
                        "Page end": 4,
                        "Domain": "api_security",
                    },
                }
            ]
        )

        self.assertEqual(citation_map[0]["citation_id"], "rag:display-source-ref")
        self.assertEqual(citation_map[0]["source_file"], "curated/display-source.md")
        self.assertEqual(citation_map[0]["source_display"], "Display source section (curated/display-source.md pp. 3-4)")
        self.assertEqual(citation_map[0]["domain"], "api_security")

    def test_rag_citation_map_uses_top_level_human_readable_source_metadata(self) -> None:
        citation_map = RagContextBroker(self.service).citation_map_for_chunks(
            [
                {
                    "chunk_id": "display_top_level_source_chunk",
                    "text": "Display-key top-level source metadata should survive citation-map rendering.",
                    "Citation ID": "display-top-level-source-metadata",
                    "Title": "Display top-level source title",
                    "Source file": "curated/display-top-level-source.md",
                    "Section": "Display top-level source section",
                    "Page start": 5,
                    "Page end": 6,
                    "Domain": "API Security",
                    "Risk Level": "Exploit Validation",
                    "Planner Visibility": "Taxonomy Only",
                    "metadata": {},
                }
            ]
        )

        self.assertEqual(citation_map[0]["citation_id"], "rag:display-top-level-source-metadata")
        self.assertEqual(citation_map[0]["source_file"], "curated/display-top-level-source.md")
        self.assertEqual(
            citation_map[0]["source_display"],
            "Display top-level source section (curated/display-top-level-source.md pp. 5-6)",
        )
        self.assertEqual(citation_map[0]["domain"], "api_security")
        self.assertEqual(citation_map[0]["risk_level"], "exploit_validation")
        self.assertEqual(citation_map[0]["planner_visibility"], "taxonomy_only")
        self.assertEqual(citation_map[0]["usage_policy"], "taxonomy_only")

    def test_rag_citation_map_uses_top_level_human_readable_source_path(self) -> None:
        citation_map = RagContextBroker(self.service).citation_map_for_chunks(
            [
                {
                    "chunk_id": "display_top_level_source_path_chunk",
                    "Citation ID": "display-top-level-source-path",
                    "Title": "Display top-level source path title",
                    "Source path": "curated/display-top-level-source-path.md",
                    "metadata": {"Domain": "api_security"},
                }
            ]
        )

        self.assertEqual(citation_map[0]["citation_id"], "rag:display-top-level-source-path")
        self.assertEqual(citation_map[0]["source_file"], "curated/display-top-level-source-path.md")
        self.assertEqual(
            citation_map[0]["source_display"],
            "Display top-level source path title (curated/display-top-level-source-path.md)",
        )

    def test_rag_citation_map_uses_top_level_human_readable_retrieval_text(self) -> None:
        citation_map = RagContextBroker(self.service).citation_map_for_chunks(
            [
                {
                    "chunk_id": "display_top_level_retrieval_text_chunk",
                    "Citation ID": "display-top-level-retrieval-text",
                    "Title": "Display top-level retrieval text source",
                    "Retrieval text": "Display-key retrieval text should become the citation excerpt.",
                    "metadata": {"Domain": "api_security"},
                }
            ]
        )

        self.assertEqual(citation_map[0]["citation_id"], "rag:display-top-level-retrieval-text")
        self.assertEqual(citation_map[0]["excerpt"], "Display-key retrieval text should become the citation excerpt.")

    def test_rag_citation_map_uses_top_level_human_readable_excerpt(self) -> None:
        citation_map = RagContextBroker(self.service).citation_map_for_chunks(
            [
                {
                    "chunk_id": "display_top_level_excerpt_chunk",
                    "Citation ID": "display-top-level-excerpt",
                    "Title": "Display top-level excerpt source",
                    "Excerpt": "Display-key excerpt should become the citation excerpt.",
                    "metadata": {"Domain": "api_security"},
                }
            ]
        )

        self.assertEqual(citation_map[0]["citation_id"], "rag:display-top-level-excerpt")
        self.assertEqual(citation_map[0]["excerpt"], "Display-key excerpt should become the citation excerpt.")

    def test_rag_citation_map_uses_top_level_human_readable_raw_text(self) -> None:
        citation_map = RagContextBroker(self.service).citation_map_for_chunks(
            [
                {
                    "chunk_id": "display_top_level_raw_text_chunk",
                    "Citation ID": "display-top-level-raw-text",
                    "Title": "Display top-level raw text source",
                    "Raw text": "Display-key raw text should become the citation excerpt.",
                    "metadata": {"Domain": "api_security"},
                }
            ]
        )

        self.assertEqual(citation_map[0]["citation_id"], "rag:display-top-level-raw-text")
        self.assertEqual(citation_map[0]["excerpt"], "Display-key raw text should become the citation excerpt.")

    def test_rag_citation_map_uses_nested_human_readable_excerpt_metadata(self) -> None:
        citation_map = RagContextBroker(self.service).citation_map_for_chunks(
            [
                {
                    "chunk_id": "display_nested_excerpt_chunk",
                    "Citation ID": "display-nested-excerpt",
                    "Title": "Display nested excerpt source",
                    "metadata": {
                        "Domain": "api_security",
                        "Excerpt": "Nested display-key excerpt should become the citation excerpt.",
                    },
                }
            ]
        )

        self.assertEqual(citation_map[0]["citation_id"], "rag:display-nested-excerpt")
        self.assertEqual(citation_map[0]["excerpt"], "Nested display-key excerpt should become the citation excerpt.")

    def test_rag_citation_map_preserves_human_readable_source_display_metadata(self) -> None:
        citation_map = RagContextBroker(self.service).citation_map_for_chunks(
            [
                {
                    "chunk_id": "display_source_display_chunk",
                    "Citation ID": "display-source-display",
                    "metadata": {
                        "Domain": "api_security",
                        "Source display": "Curated display label from source metadata",
                    },
                }
            ]
        )

        self.assertEqual(citation_map[0]["citation_id"], "rag:display-source-display")
        self.assertEqual(citation_map[0]["source_display"], "Curated display label from source metadata")

    def test_rag_context_prompt_normalizes_curated_citation_ids(self) -> None:
        pack = RagContextPack(
            query="curated prompt rendering",
            purpose="operator_answer",
            role="operator_chat",
            chunks=[
                {
                    "chunk_id": "prompt_chunk",
                    "citation_id": "curated-prompt-source",
                    "title": "Curated prompt source",
                    "text": "Curated source context should render with canonical RAG citations.",
                    "metadata": {"domain": "api_security"},
                }
            ],
            omitted_sources=[{"citation_id": "omitted-curated-source", "reason": "role_forbidden"}],
        )

        rendered = pack.prompt_context()

        self.assertIn("[rag:curated-prompt-source]", rendered)
        self.assertIn("rag:omitted-curated-source:role_forbidden", rendered)
        self.assertNotIn("[curated-prompt-source]", rendered)
        self.assertNotIn(" omitted-curated-source:role_forbidden", rendered)

    def test_rag_context_prompt_normalizes_uppercase_rag_citation_prefixes(self) -> None:
        pack = RagContextPack(
            query="uppercase rag citation prompt rendering",
            purpose="operator_answer",
            role="operator_chat",
            chunks=[
                {
                    "chunk_id": "uppercase_prompt_chunk",
                    "Citation ID": "RAG:uppercase-prompt-source",
                    "title": "Uppercase prompt source",
                    "text": "Uppercase RAG citation prefixes should render canonically.",
                    "metadata": {"domain": "api_security"},
                }
            ],
            omitted_sources=[
                {
                    "Citation ID": "RAG:uppercase-omitted-source",
                    "reason": "role_forbidden",
                }
            ],
        )

        rendered = pack.prompt_context()

        self.assertIn("[rag:uppercase-prompt-source]", rendered)
        self.assertIn("rag:uppercase-omitted-source:role_forbidden", rendered)
        self.assertNotIn("rag:RAG:", rendered)

    def test_rag_context_prompt_labels_direct_human_readable_metadata(self) -> None:
        pack = RagContextPack(
            query="display metadata prompt rendering",
            purpose="operator_answer",
            role="operator_chat",
            chunks=[
                {
                    "chunk_id": "display_prompt_chunk",
                    "title": "Display prompt source",
                    "text": "Direct payloads should preserve display-key prompt labels.",
                    "metadata": {"Domain": "api_security", "Usage policy": "advisory_only"},
                }
            ],
        )

        rendered = pack.prompt_context()

        self.assertIn("domain=api_security", rendered)
        self.assertIn("policy=advisory_only", rendered)

    def test_rag_context_prompt_labels_top_level_human_readable_metadata(self) -> None:
        pack = RagContextPack(
            query="top level display metadata prompt rendering",
            purpose="operator_answer",
            role="operator_chat",
            chunks=[
                {
                    "chunk_id": "top_level_display_prompt_chunk",
                    "title": "Top-level display prompt source",
                    "text": "Top-level display metadata should preserve prompt labels.",
                    "Domain": "api_security",
                    "Usage policy": "taxonomy_only",
                    "metadata": {},
                }
            ],
        )

        rendered = pack.prompt_context()

        self.assertIn("domain=api_security", rendered)
        self.assertIn("policy=taxonomy_only", rendered)

    def test_rag_context_prompt_uses_human_readable_metadata_citation_id(self) -> None:
        pack = RagContextPack(
            query="display citation prompt rendering",
            purpose="operator_answer",
            role="operator_chat",
            chunks=[
                {
                    "chunk_id": "display_prompt_chunk",
                    "title": "Display prompt source",
                    "text": "Display-key citations should render as RAG source citations.",
                    "metadata": {
                        "Citation ID": "display-prompt-source",
                        "Domain": "api_security",
                    },
                }
            ],
            omitted_sources=[
                {
                    "chunk_id": "display_omitted_chunk",
                    "reason": "role_forbidden",
                    "metadata": {"Citation ID": "display-omitted-source"},
                }
            ],
        )

        rendered = pack.prompt_context()

        self.assertIn("[rag:display-prompt-source]", rendered)
        self.assertIn("rag:display-omitted-source:role_forbidden", rendered)
        self.assertNotIn("[rag:display_prompt_chunk]", rendered)
        self.assertNotIn("rag:display_omitted_chunk:role_forbidden", rendered)

    def test_rag_context_prompt_uses_human_readable_retrieval_text(self) -> None:
        pack = RagContextPack(
            query="display retrieval text prompt rendering",
            purpose="operator_answer",
            role="operator_chat",
            chunks=[
                {
                    "chunk_id": "display_text_chunk",
                    "title": "Display prompt source",
                    "metadata": {
                        "Citation ID": "display-text-source",
                        "Domain": "api_security",
                        "Retrieval text": "Display-key retrieval text must render in advisory prompt context.",
                    },
                }
            ],
        )

        rendered = pack.prompt_context()

        self.assertIn("[rag:display-text-source]", rendered)
        self.assertIn("Display-key retrieval text must render in advisory prompt context.", rendered)

    def test_rag_context_prompt_uses_human_readable_raw_text(self) -> None:
        pack = RagContextPack(
            query="display raw text prompt rendering",
            purpose="operator_answer",
            role="operator_chat",
            chunks=[
                {
                    "chunk_id": "display_raw_text_chunk",
                    "title": "Display raw prompt source",
                    "metadata": {
                        "Citation ID": "display-raw-text-source",
                        "Domain": "api_security",
                        "Raw text": "Display-key raw text must render in advisory prompt context.",
                    },
                }
            ],
        )

        rendered = pack.prompt_context()

        self.assertIn("[rag:display-raw-text-source]", rendered)
        self.assertIn("Display-key raw text must render in advisory prompt context.", rendered)

    def test_rag_context_prompt_uses_human_readable_source_file_as_label(self) -> None:
        pack = RagContextPack(
            query="display source file prompt rendering",
            purpose="operator_answer",
            role="operator_chat",
            chunks=[
                {
                    "chunk_id": "display_source_file_chunk",
                    "Citation ID": "display-source-file",
                    "Retrieval text": "Source-file-only context should still render an advisory source label.",
                    "metadata": {
                        "Domain": "api_security",
                        "Source file": "curated/display-source-file.md",
                    },
                }
            ],
        )

        rendered = pack.prompt_context()

        self.assertIn("[rag:display-source-file] curated/display-source-file.md", rendered)
        self.assertIn("Source-file-only context should still render an advisory source label.", rendered)

    def test_rag_context_prompt_combines_title_and_source_file_in_default_label(self) -> None:
        pack = RagContextPack(
            query="display source provenance prompt rendering",
            purpose="operator_answer",
            role="operator_chat",
            chunks=[
                {
                    "chunk_id": "display_title_source_file_chunk",
                    "Citation ID": "display-title-source-file",
                    "Title": "Display prompt source title",
                    "Retrieval text": "Title-bearing context should still show source-file provenance.",
                    "metadata": {
                        "Domain": "api_security",
                        "Source file": "curated/display-title-source-file.md",
                    },
                }
            ],
        )

        rendered = pack.prompt_context()

        self.assertIn(
            "[rag:display-title-source-file] Display prompt source title (curated/display-title-source-file.md)",
            rendered,
        )
        self.assertIn("Title-bearing context should still show source-file provenance.", rendered)

    def test_rag_context_prompt_preserves_section_and_page_source_location(self) -> None:
        pack = RagContextPack(
            query="display section page prompt rendering",
            purpose="operator_answer",
            role="operator_chat",
            chunks=[
                {
                    "chunk_id": "display_section_page_chunk",
                    "Citation ID": "display-section-page-source",
                    "Title": "Display prompt source title",
                    "Retrieval text": "Section-bearing context should keep source location provenance.",
                    "metadata": {
                        "Domain": "api_security",
                        "Source file": "curated/display-section-page.md",
                        "Section": "Display prompt source section",
                        "Page start": 2,
                        "Page end": 3,
                    },
                }
            ],
        )

        rendered = pack.prompt_context()

        self.assertIn(
            "[rag:display-section-page-source] "
            "Display prompt source section (curated/display-section-page.md pp. 2-3)",
            rendered,
        )
        self.assertIn("Section-bearing context should keep source location provenance.", rendered)

    def test_rag_context_prompt_uses_human_readable_top_level_source_display(self) -> None:
        pack = RagContextPack(
            query="display source prompt rendering",
            purpose="operator_answer",
            role="operator_chat",
            chunks=[
                {
                    "chunk_id": "display_source_chunk",
                    "Citation ID": "display-source-top-level",
                    "Source display": "Top-level display source label",
                    "Retrieval text": "Top-level display retrieval text should render.",
                    "metadata": {"Domain": "api_security"},
                }
            ],
        )

        rendered = pack.prompt_context()

        self.assertIn("[rag:display-source-top-level] Top-level display source label", rendered)
        self.assertIn("Top-level display retrieval text should render.", rendered)
        self.assertNotIn("[rag:display_source_chunk]", rendered)

    def test_rag_chunk_inspect_resolves_curated_citation_id(self) -> None:
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()
        runtime.store.insert_target(self.target)
        runtime.store.insert_artifact(
            ArtifactRecord(
                id="artifact_inspect_curated",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="inspect-curated-source.jsonl",
                sha256="c" * 64,
                size_bytes=128,
                metadata={"source_type": "methodology_doc"},
            )
        )
        runtime.store.insert_document_chunk(
            DocumentChunk(
                id="preprocessed_chunk_inspect",
                target_id=self.target.id,
                source_artifact_id="artifact_inspect_curated",
                source_sha256="c" * 64,
                chunk_index=0,
                title="Inspectable curated source",
                text="Chunk inspection should resolve curated citation identifiers.",
                token_count=8,
                metadata={
                    "citation_id": "rag:inspect-curated-source",
                    "corpus_type": "methodology_standards",
                    "domain": "methodology_standards",
                },
            )
        )

        inspected = runtime.rag_chunk_inspect("rag:inspect-curated-source")

        self.assertEqual(inspected["chunk"]["id"], "preprocessed_chunk_inspect")
        self.assertEqual(inspected["chunk"]["citation_id"], "rag:inspect-curated-source")
        runtime.shutdown()

    def test_rag_source_profile_preserves_curated_sample_citation_id(self) -> None:
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()
        runtime.store.insert_target(self.target)
        runtime.store.insert_artifact(
            ArtifactRecord(
                id="artifact_profile_curated",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="profile-curated-source.jsonl",
                sha256="d" * 64,
                size_bytes=128,
                metadata={"source_type": "methodology_doc"},
            )
        )
        runtime.store.insert_document_chunk(
            DocumentChunk(
                id="preprocessed_chunk_profile",
                target_id=self.target.id,
                source_artifact_id="artifact_profile_curated",
                source_sha256="d" * 64,
                chunk_index=0,
                title="Profiled curated source",
                text="Source profile sample chunks should preserve curated citation identifiers.",
                token_count=9,
                metadata={
                    "doc_id": "curated_doc",
                    "citation_id": "rag:profile-curated-source",
                    "corpus_type": "methodology_standards",
                    "domain": "methodology_standards",
                },
            )
        )

        profile = runtime.rag_source_profile("curated_doc", limit=1)

        self.assertEqual(profile["sample_chunks"][0]["chunk_id"], "preprocessed_chunk_profile")
        self.assertEqual(profile["sample_chunks"][0]["citation_id"], "rag:profile-curated-source")
        runtime.shutdown()

    def test_rag_eval_probes_normalizes_curated_top_citations(self) -> None:
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()

        def fake_rag_search(
            query: str,
            *,
            target: str | None = None,
            limit: int = 5,
            corpus_types: list[str] | None = None,
            filters: dict[str, object] | None = None,
        ) -> dict[str, object]:
            return {
                "query": query,
                "target": target,
                "corpus_types": corpus_types or [],
                "filters": filters or {},
                "results": [
                    {
                        "chunk_id": "eval_chunk",
                        "citation_id": "eval-curated-source",
                        "text": "Curated advisory context for retrieval evaluation.",
                        "metadata": {"domain": "api_security"},
                    }
                ],
                "citation_map": [],
            }

        runtime.rag_search = fake_rag_search  # type: ignore[method-assign]
        payload = runtime.rag_eval_probes(["retrieval evaluation"], limit=1)

        self.assertEqual(payload["results"][0]["top_citations"], ["rag:eval-curated-source"])
        runtime.shutdown()

    def test_generated_notion_exports_are_not_ingested_as_active_rag(self) -> None:
        export_dir = self.root / "findings" / "notion" / self.target.handle
        export_dir.mkdir(parents=True)
        source = export_dir / "notion-export.md"
        source.write_text(
            "# RAG Target Notion Export\n\n"
            "## Evidence References\n\n"
            "- `evidence:current` Sparse real evidence.\n\n"
            "## AI Summaries\n\n"
            "- Generated strategy text must not become active RAG.\n",
            encoding="utf-8",
        )

        with self.assertRaises(DocumentIngestionError) as raised:
            self.service.ingest_path(source, target=self.target, corpus_type="operator_note")

        self.assertIn("generated export", str(raised.exception))
        self.assertEqual(self.store.count_document_chunks(), 0)
        self.assertEqual(self.store.list_evidence(target_id=self.target.id, limit=20), [])

    def test_generic_generated_exports_are_not_ingested_as_active_rag(self) -> None:
        source = self.root / "generated-export.md"
        source.write_text(
            "# Generated Export\n\n"
            "Generated context exports must not recurse into active RAG ingestion.\n",
            encoding="utf-8",
        )

        with self.assertRaises(DocumentIngestionError) as raised:
            self.service.ingest_path(source, target=self.target, corpus_type="operator_note")

        self.assertIn("generated export", str(raised.exception))
        self.assertEqual(self.store.count_document_chunks(), 0)
        self.assertEqual(self.store.list_evidence(target_id=self.target.id, limit=20), [])

    def test_findings_notion_exports_are_not_ingested_by_absolute_path(self) -> None:
        export_dir = self.root / "findings" / "notion" / self.target.handle
        export_dir.mkdir(parents=True)
        source = export_dir / "current-summary.md"
        source.write_text(
            "# Current Summary\n\n"
            "Any findings/notion markdown export must not recurse into active RAG ingestion.\n",
            encoding="utf-8",
        )

        with self.assertRaises(DocumentIngestionError) as raised:
            self.service.ingest_path(source, target=self.target, corpus_type="operator_note")

        self.assertIn("generated export", str(raised.exception))
        self.assertEqual(self.store.count_document_chunks(), 0)
        self.assertEqual(self.store.list_evidence(target_id=self.target.id, limit=20), [])

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
        self.assertTrue(runtime._operator_answer_cites_rag_context(f"rag:{ingest['chunks'][0]['id']}", rag_context))
        self.assertIn("**RAG Hints (not evidence)**", fallback)
        self.assertIn(f"rag:{ingest['chunks'][0]['id']}", fallback)

    def test_deterministic_operator_rag_fallback_preserves_curated_citation_id(self) -> None:
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()
        runtime.store.insert_target(self.target)

        fallback = runtime._deterministic_rag_citation_answer(
            "What source guidance applies?",
            self.target.id,
            [
                {
                    "chunk_id": "preprocessed_operator_context",
                    "citation_id": "rag:operator-curated-source",
                    "source_display": "Curated operator source",
                    "text": "Curated source identities must survive deterministic fallback answers.",
                    "evidence_refs": [],
                    "metadata": {
                        "corpus_type": "methodology_standards",
                        "domain": "methodology_standards",
                    },
                }
            ],
        )

        self.assertIn("`rag:operator-curated-source`", fallback)
        self.assertNotIn("`rag:preprocessed_operator_context`", fallback)
        runtime.shutdown()

    def test_operator_answer_citation_gate_counts_curated_citation_without_chunk_id(self) -> None:
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()
        rag_context = [
            {
                "citation_id": "rag:operator-curated-only",
                "text": "Curated-only citation context still requires an explicit citation.",
                "metadata": {
                    "corpus_type": "methodology_standards",
                    "domain": "methodology_standards",
                },
            }
        ]

        self.assertFalse(runtime._operator_answer_cites_rag_context("Uncited use of RAG.", rag_context))
        self.assertTrue(runtime._operator_answer_cites_rag_context("Cited use of RAG. rag:operator-curated-only", rag_context))
        runtime.shutdown()

    def test_operator_answer_rag_context_withholds_taxonomy_by_default(self) -> None:
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()
        runtime.store.insert_target(self.target)
        source = self.root / "mitre-mobile.md"
        source.write_text(
            "# MITRE ATT&CK mobile relationship\n\n"
            "FluBot can use Accessibility Services to make removal difficult.\n",
            encoding="utf-8",
        )
        runtime.rag_ingest_document(
            source,
            target=self.target.handle,
            corpus_type="mitre_attack",
            embed=False,
        )

        ordinary = runtime._rag_context_pack_payload("What does FluBot do?", self.target.id)
        mapping = runtime._rag_context_pack_payload("Map FluBot to MITRE detection context", self.target.id)

        self.assertEqual(ordinary["purpose"], "operator_answer")
        self.assertEqual(ordinary["chunks"], [])
        self.assertTrue(any("withheld" in item.get("reason", "") for item in ordinary["omitted_sources"]))
        self.assertEqual(mapping["purpose"], "report_mapping")
        self.assertTrue(mapping["chunks"])
        runtime.shutdown()

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

    def test_cve_search_preserves_human_readable_advisory_metadata(self) -> None:
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()
        runtime.store.insert_target(self.target)
        runtime.store.insert_artifact(
            ArtifactRecord(
                id="artifact_display_cve",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="display-cve.jsonl",
                sha256="8" * 64,
                size_bytes=128,
                metadata={"source_type": "vuln_intel_card"},
            )
        )
        runtime.store.insert_document_chunk(
            DocumentChunk(
                id="display_cve_chunk",
                target_id=self.target.id,
                source_artifact_id="artifact_display_cve",
                source_sha256="8" * 64,
                chunk_index=0,
                title="Display CVE metadata",
                text="CVE-2026-0003 describes advisory-only OpenSSH vulnerability context.",
                token_count=9,
                metadata={
                    "corpus_type": "cve_advisory",
                    "CVE IDs": ["CVE-2026-0003"],
                    "Source trust": "official_feed",
                },
            )
        )

        payload = runtime.rag_cve_search("OpenSSH CVE-2026-0003", target=self.target.handle)

        self.assertTrue(payload["results"])
        self.assertEqual(payload["results"][0]["cve_ids"], ["CVE-2026-0003"])
        self.assertEqual(payload["results"][0]["source_trust"], "official_feed")
        runtime.shutdown()

    def test_runtime_imports_preprocessed_chunk_and_search_returns_citation(self) -> None:
        chunks_dir = self._write_preprocessed_chunks(
            [
                {
                    "chunk_id": "chunk_test_api_1",
                    "doc_id": "source_api",
                    "source_file": "owasp-api.md",
                    "source_sha256": "a" * 64,
                    "source_type": "markdown",
                    "domain": "api_web",
                    "corpus_type": ["api_security"],
                    "chunk_index": 0,
                    "chunk_type": "docling_hybrid",
                    "title": "BOLA",
                    "section": "Broken Object Level Authorization",
                    "retrieval_text": "BOLA testing checks object ownership before returning API objects.",
                    "raw_text": "BOLA testing checks object ownership before returning API objects.",
                    "requires_authorized_scope": True,
                    "planner_visibility": "normal",
                    "risk_level": "safe_planning",
                }
            ]
        )
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()

        payload = runtime.rag_import_chunks(chunks_dir, limit=1)
        search = runtime.rag_search("object ownership API", limit=3, filters={"domain": ["api_security"]})

        self.assertEqual(payload["records_seen"], 1)
        self.assertEqual(payload["chunks_inserted"], 1)
        self.assertEqual(payload["embeddings_inserted"], 1)
        self.assertTrue(search["results"])
        self.assertEqual(search["results"][0]["citation_id"], "rag:chunk_test_api_1")
        self.assertEqual(search["citation_map"][0]["source_display"], "Broken Object Level Authorization (owasp-api.md)")
        self.assertEqual(runtime.store.list_targets(), [self.target])
        runtime.shutdown()

    def test_retrieve_honors_human_readable_corpus_type_filter(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_display_corpus",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="display-corpus.jsonl",
                sha256="b" * 64,
                size_bytes=128,
                metadata={"source_type": "methodology_doc"},
            )
        )
        self.store.insert_document_chunk(
            DocumentChunk(
                id="chunk_display_corpus",
                source_artifact_id="artifact_display_corpus",
                source_sha256="b" * 64,
                target_id=self.target.id,
                chunk_index=0,
                title="Display corpus metadata",
                text="Display corpus metadata should still satisfy API security retrieval.",
                token_count=9,
                metadata={"Corpus type": "api_security"},
            )
        )

        results = self.service.retrieve(
            "display corpus metadata",
            target_id=self.target.id,
            corpus_types=["api_security"],
            use_embeddings=False,
        )

        self.assertEqual([item.chunk.id for item in results], ["chunk_display_corpus"])

    def test_retrieve_normalizes_human_readable_metadata_filter_values(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_display_filter",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="display-filter.jsonl",
                sha256="c" * 64,
                size_bytes=256,
                metadata={"source_type": "methodology_doc"},
            )
        )
        for chunk_id, corpus_type in (
            ("chunk_filter_api", "api_security"),
            ("chunk_filter_writeup", "htb_writeup"),
        ):
            self.store.insert_document_chunk(
                DocumentChunk(
                    id=chunk_id,
                    source_artifact_id="artifact_display_filter",
                    source_sha256="c" * 64,
                    target_id=self.target.id,
                    chunk_index=0,
                    title="Display filter boundary",
                    text="Display filter boundary text should be constrained by metadata filters.",
                    token_count=10,
                    metadata={"corpus_type": corpus_type},
                )
            )

        results = self.service.retrieve(
            "display filter boundary",
            target_id=self.target.id,
            filters={"domain": ["HTB Writeup"]},
            use_embeddings=False,
        )

        self.assertEqual([item.chunk.id for item in results], ["chunk_filter_writeup"])

    def test_store_document_chunk_filters_normalize_human_readable_keys(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_display_store_filter",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="display-store-filter.jsonl",
                sha256="d" * 64,
                size_bytes=256,
                metadata={"source_type": "methodology_doc"},
            )
        )
        for chunk_index, (chunk_id, corpus_type) in enumerate(
            (
                ("chunk_store_api", "api_security"),
                ("chunk_store_formal", "formal_methods"),
            )
        ):
            self.store.insert_document_chunk(
                DocumentChunk(
                    id=chunk_id,
                    source_artifact_id="artifact_display_store_filter",
                    source_sha256="d" * 64,
                    target_id=self.target.id,
                    chunk_index=chunk_index,
                    title="Display store filter boundary",
                    text="Display store filter boundary text.",
                    token_count=5,
                    metadata={"corpus_type": corpus_type},
                )
            )

        chunks = self.store.list_document_chunks(
            target_id=self.target.id,
            metadata_filters={"Corpus type": ["formal_methods"]},
            limit=10,
        )

        self.assertEqual(self.store.count_document_chunks(metadata_filters={"Corpus type": ["formal_methods"]}), 1)
        self.assertEqual([chunk.id for chunk in chunks], ["chunk_store_formal"])

    def test_store_document_chunk_filters_normalize_human_readable_domain_values(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_display_store_value_filter",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="display-store-value-filter.jsonl",
                sha256="e" * 64,
                size_bytes=256,
                metadata={"source_type": "methodology_doc"},
            )
        )
        for chunk_index, (chunk_id, corpus_type) in enumerate(
            (
                ("chunk_store_value_api", "api_security"),
                ("chunk_store_value_writeup", "htb_writeup"),
            )
        ):
            self.store.insert_document_chunk(
                DocumentChunk(
                    id=chunk_id,
                    source_artifact_id="artifact_display_store_value_filter",
                    source_sha256="e" * 64,
                    target_id=self.target.id,
                    chunk_index=chunk_index,
                    title="Display store value filter boundary",
                    text="Display store value filter boundary text.",
                    token_count=6,
                    metadata={"corpus_type": corpus_type},
                )
            )

        chunks = self.store.list_document_chunks(
            target_id=self.target.id,
            metadata_filters={"domain": ["HTB Writeup"]},
            limit=10,
        )

        self.assertEqual(self.store.count_document_chunks(metadata_filters={"domain": ["HTB Writeup"]}), 1)
        self.assertEqual([chunk.id for chunk in chunks], ["chunk_store_value_writeup"])

    def test_role_aware_rag_pack_filters_and_gates_restricted_sources(self) -> None:
        chunks_dir = self._write_preprocessed_chunks(
            [
                {
                    "chunk_id": "chunk_api_safe",
                    "doc_id": "source_api",
                    "source_file": "owasp-api.md",
                    "source_sha256": "d" * 64,
                    "domain": "api_security",
                    "chunk_index": 0,
                    "chunk_type": "docling_hybrid",
                    "title": "API authorization",
                    "section": "BOLA checklist",
                    "retrieval_text": "context anchor BOLA authorization checks object ownership safely.",
                    "raw_text": "context anchor BOLA authorization checks object ownership safely.",
                    "requires_authorized_scope": True,
                    "risk_level": "safe_planning",
                    "planner_visibility": "normal",
                },
                {
                    "chunk_id": "chunk_kernel_restricted",
                    "doc_id": "source_kernel",
                    "source_file": "guide-to-kernel-exploitation.pdf",
                    "source_sha256": "e" * 64,
                    "domain": "kernel_security",
                    "chunk_index": 0,
                    "chunk_type": "docling_hybrid",
                    "title": "Kernel exploitation",
                    "section": "Applicability review",
                    "retrieval_text": "context anchor kernel exploitation source for applicability review only.",
                    "raw_text": "context anchor kernel exploitation source for applicability review only.",
                    "requires_authorized_scope": True,
                    "requires_operator_approval": True,
                    "risk_level": "exploit_validation",
                    "planner_visibility": "restricted",
                },
                {
                    "chunk_id": "chunk_attack_taxonomy",
                    "doc_id": "source_attack",
                    "source_file": "mitre-enterprise-attack.json",
                    "source_sha256": "f" * 64,
                    "domain": "mitre_attack",
                    "chunk_index": 0,
                    "chunk_type": "attack_technique",
                    "title": "ATT&CK technique",
                    "section": "Technique mapping",
                    "retrieval_text": "context anchor MITRE ATT&CK taxonomy for reporting and detection mapping.",
                    "raw_text": "context anchor MITRE ATT&CK taxonomy for reporting and detection mapping.",
                    "requires_authorized_scope": True,
                    "risk_level": "safe_planning",
                    "planner_visibility": "taxonomy_only",
                },
            ]
        )
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()
        runtime.rag_import_chunks(chunks_dir)

        fast_pack = runtime.build_rag_context_pack(
            "context anchor authorization exploitation taxonomy",
            purpose="worker_ai_review",
            role="local_fast",
            target=self.target,
            limit=5,
        )
        code_task = Task(
            target_id=self.target.id,
            phase=MethodologyPhase.EXPLOITATION,
            kind=TaskKind.POC_APPLICABILITY_VALIDATION,
            title="PoC applicability review",
            summary="Review restricted source only for gated applicability.",
            role=AgentRole.CODE_WORKER,
            metadata={"allow_ai_review": True},
        )
        runtime.set_operator_intent("htb_lab")
        code_pack = runtime.build_rag_context_pack(
            "context anchor kernel exploitation applicability",
            purpose="worker_ai_review",
            role="local_code",
            task=code_task,
            limit=5,
        )
        action_pack = runtime.build_rag_context_pack(
            "context anchor taxonomy",
            purpose="action_selection",
            role="local_deep",
            target=self.target,
            limit=5,
        )

        self.assertIn("chunk_api_safe", {item["chunk_id"] for item in fast_pack["chunks"]})
        self.assertNotIn("chunk_kernel_restricted", {item["chunk_id"] for item in fast_pack["chunks"]})
        self.assertTrue(any(item["chunk_id"] == "chunk_kernel_restricted" for item in fast_pack["omitted_sources"]))
        self.assertIn("chunk_kernel_restricted", {item["chunk_id"] for item in code_pack["chunks"]})
        self.assertTrue(any(item["chunk_id"] == "chunk_attack_taxonomy" for item in action_pack["omitted_sources"]))
        self.assertTrue(code_pack["prompt_context"])
        runtime.shutdown()

    def test_importer_dry_run_and_duplicate_embedding_skip(self) -> None:
        chunks_dir = self._write_preprocessed_chunks(
            [
                {
                    "chunk_id": "chunk_test_formal_1",
                    "doc_id": "source_formal",
                    "source_file": "decision-procedures.pdf",
                    "source_sha256": "b" * 64,
                    "domain": "formal_methods",
                    "chunk_index": 0,
                    "retrieval_text": "Decision procedures support program verification queries.",
                    "raw_text": "Decision procedures support program verification queries.",
                    "chunk_type": "docling_hybrid",
                    "requires_authorized_scope": True,
                }
            ]
        )
        importer = RagChunkImporter(self.store, DeterministicHashEmbeddingProvider())
        dry_run = importer.import_chunks(RagImportOptions(chunks_dir=chunks_dir, dry_run=True))
        first = importer.import_chunks(RagImportOptions(chunks_dir=chunks_dir))
        second = importer.import_chunks(RagImportOptions(chunks_dir=chunks_dir))
        changed_model = RagChunkImporter(self.store, DeterministicHashEmbeddingProvider(model_name="local-hash-embedding-v2"))
        third = changed_model.import_chunks(RagImportOptions(chunks_dir=chunks_dir))

        self.assertEqual(dry_run.records_seen, 1)
        self.assertEqual(self.store.count_document_chunks(metadata_filters={"domain": "formal_methods"}), 1)
        self.assertEqual(first.embeddings_inserted, 1)
        self.assertEqual(second.embeddings_skipped, 1)
        self.assertEqual(third.embeddings_inserted, 1)

    def test_importer_blocks_policy_blocked_rows(self) -> None:
        chunks_dir = self._write_preprocessed_chunks(
            [
                {
                    "chunk_id": "chunk_blocked",
                    "source_sha256": "c" * 64,
                    "chunk_index": 0,
                    "retrieval_text": "Blocked commercial text.",
                    "policy_blocked": True,
                }
            ]
        )
        importer = RagChunkImporter(self.store, DeterministicHashEmbeddingProvider())
        summary = importer.import_chunks(RagImportOptions(chunks_dir=chunks_dir))

        self.assertEqual(summary.failures, 1)
        self.assertEqual(self.store.count_document_chunks(), 0)

    def test_importer_blocks_human_readable_policy_blocked_rows(self) -> None:
        chunks_dir = self._write_preprocessed_chunks(
            [
                {
                    "Chunk ID": "chunk_display_blocked",
                    "Source SHA256": "d" * 64,
                    "Chunk index": 0,
                    "Retrieval text": "Display-key blocked text must not enter advisory RAG.",
                    "Policy blocked": True,
                }
            ]
        )
        importer = RagChunkImporter(self.store, DeterministicHashEmbeddingProvider())
        summary = importer.import_chunks(RagImportOptions(chunks_dir=chunks_dir))

        self.assertEqual(summary.failures, 1)
        self.assertEqual(self.store.count_document_chunks(), 0)

    def test_importer_rejects_generated_export_rows(self) -> None:
        chunks_dir = self._write_preprocessed_chunks(
            [
                {
                    "chunk_id": "chunk_export",
                    "doc_id": "source_export",
                    "source_file": "findings/notion/rag.htb/notion-export.md",
                    "source_sha256": "g" * 64,
                    "source_type": "generated_export",
                    "domain": "operator_note",
                    "corpus_type": "operator_note",
                    "chunk_index": 0,
                    "retrieval_text": "Generated Notion export should not become active operational RAG.",
                    "raw_text": "Generated Notion export should not become active operational RAG.",
                    "metadata": {
                        "source_type": "generated_export",
                        "ingest_allowed": False,
                        "operational_retrieval_allowed": False,
                    },
                }
            ]
        )
        importer = RagChunkImporter(self.store, DeterministicHashEmbeddingProvider())
        summary = importer.import_chunks(RagImportOptions(chunks_dir=chunks_dir))

        self.assertEqual(summary.failures, 1)
        self.assertEqual(summary.failed_record_ids, ["chunk_export"])
        self.assertTrue(any("rag_index rejects" in error for error in summary.errors))
        self.assertEqual(self.store.count_document_chunks(), 0)

    def test_corpus_domain_aliases_and_unknown_fallback(self) -> None:
        self.assertEqual(self.service._normalize_corpus_type("api_security"), "api_security")
        self.assertEqual(self.service._normalize_corpus_type("api-web"), "api_security")
        self.assertEqual(self.service._normalize_corpus_type("formal_methods"), "formal_methods")
        self.assertEqual(self.service._normalize_corpus_type("operator_note"), "operator_note")
        self.assertEqual(self.service._normalize_corpus_type("future-domain"), "general_security")

    def test_citation_validator_rejects_invented_and_missing_citations(self) -> None:
        retrieved = [{"chunk_id": "chunk_known", "citation_id": "rag:chunk_known", "metadata": {"domain": "api_security"}}]

        invented = validate_rag_citations("Claim. rag:chunk_other", retrieved)
        missing = validate_rag_citations("Claim without citation.", retrieved)
        valid = validate_rag_citations("Claim with citation. rag:chunk_known", retrieved)

        self.assertFalse(invented.valid)
        self.assertEqual(invented.invented_ids, ["rag:chunk_other"])
        self.assertFalse(missing.valid)
        self.assertTrue(missing.missing_citations)
        self.assertTrue(valid.valid)

    def test_citation_validator_counts_human_readable_metadata_citation_id(self) -> None:
        retrieved = [
            {
                "metadata": {
                    "Citation ID": "display-curated-source",
                    "Domain": "api_security",
                },
            }
        ]

        result = validate_rag_citations("Claim with display-key citation. rag:display-curated-source", retrieved)

        self.assertTrue(result.valid)
        self.assertEqual(result.retrieved_ids, ["rag:display-curated-source"])
        self.assertEqual(result.invented_ids, [])

    def test_mitre_taxonomy_is_blocked_for_action_selection(self) -> None:
        retrieved = [{"chunk_id": "attack_T0001", "metadata": {"domain": "mitre_attack", "planner_visibility": "taxonomy_only"}}]

        result = validate_rag_citations("Use this taxonomy only for reporting. rag:attack_T0001", retrieved, mode="action_selection")

        self.assertFalse(result.valid)
        self.assertEqual(result.blocked_source_use, ["rag:attack_T0001"])

    def test_blocked_source_use_normalizes_curated_citation_id(self) -> None:
        retrieved = [
            {
                "chunk_id": "attack_T0002",
                "citation_id": "curated-attack-source",
                "metadata": {"domain": "mitre_attack", "planner_visibility": "taxonomy_only"},
            }
        ]

        result = validate_rag_citations(
            "Use this taxonomy only for reporting. rag:curated-attack-source",
            retrieved,
            mode="action_selection",
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.blocked_source_use, ["rag:curated-attack-source"])

    def test_blocked_source_use_counts_human_readable_taxonomy_metadata(self) -> None:
        retrieved = [
            {
                "metadata": {
                    "Citation ID": "display-attack-source",
                    "Domain": "mitre_attack",
                    "Planner Visibility": "taxonomy_only",
                },
            }
        ]

        result = validate_rag_citations(
            "Use this taxonomy only for reporting. rag:display-attack-source",
            retrieved,
            mode="action_selection",
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.blocked_source_use, ["rag:display-attack-source"])

    def test_rag_synthesis_rejects_qwen_model(self) -> None:
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()
        runtime.config.rag.synthesis.model = "qwen3-coder-next:q4_K_M"
        result = runtime.synthesize_rag_answer(
            "What is BOLA?",
            retrieved_chunks=[
                {
                    "chunk_id": "chunk_api",
                    "citation_id": "rag:chunk_api",
                    "text": "BOLA means Broken Object Level Authorization.",
                    "metadata": {"domain": "api_security"},
                }
            ],
        )

        self.assertEqual(result["status"], "disallowed_model")
        self.assertEqual(disallowed_rag_synthesis_model("qwen3-coder-next:q4_K_M", ("qwen",)), "qwen")
        runtime.shutdown()

    def test_operational_rag_synthesis_rejects_supplied_generated_export_chunks(self) -> None:
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()
        runtime.config.rag.synthesis.model = "allowed-model"
        result = runtime.synthesize_rag_answer(
            "What should the planner do next?",
            mode="planner",
            retrieved_chunks=[
                {
                    "chunk_id": "generated-export",
                    "citation_id": "rag:generated-export",
                    "text": "Generated export prose must not be synthesized into operational guidance.",
                    "metadata": {
                        "source_type": "generated_export",
                        "origin": "generated_export",
                        "ingest_allowed": False,
                        "operational_retrieval_allowed": False,
                    },
                }
            ],
        )

        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "invalid_rag_context")
        self.assertIn("generated_export", result["error"])
        runtime.shutdown()

    def test_operational_rag_synthesis_accepts_supplied_markdown_advisory_chunks(self) -> None:
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()
        runtime.config.rag.synthesis.model = "qwen3-coder-next:q4_K_M"
        result = runtime.synthesize_rag_answer(
            "What should the planner do next?",
            mode="planner",
            retrieved_chunks=[
                {
                    "chunk_id": "methodology",
                    "citation_id": "rag:methodology",
                    "text": "Advisory methodology context should survive validation.",
                    "metadata": {
                        "source_type": "markdown",
                        "domain": "api_security",
                        "corpus_type": "api_security",
                    },
                }
            ],
        )

        self.assertEqual(result["status"], "disallowed_model")
        self.assertEqual(result["retrieved_ids"], ["rag:methodology"])
        runtime.shutdown()

    def test_rag_synthesis_disallowed_model_normalizes_curated_retrieved_ids(self) -> None:
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()
        runtime.config.rag.synthesis.model = "qwen3-coder-next:q4_K_M"
        result = runtime.synthesize_rag_answer(
            "What should the planner do next?",
            mode="planner",
            retrieved_chunks=[
                {
                    "chunk_id": "methodology_diag",
                    "citation_id": "methodology-curated-diag",
                    "text": "Advisory methodology context should retain its curated citation.",
                    "metadata": {
                        "source_type": "markdown",
                        "domain": "api_security",
                        "corpus_type": "api_security",
                    },
                }
            ],
        )

        self.assertEqual(result["status"], "disallowed_model")
        self.assertEqual(result["retrieved_ids"], ["rag:methodology-curated-diag"])
        runtime.shutdown()

    def test_operator_rag_pack_omits_legacy_generated_export_chunks(self) -> None:
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()
        runtime.store.insert_target(self.target)
        runtime.store.insert_artifact(
            ArtifactRecord(
                id="artifact_legacy_generated_export",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.EXPORT,
                path="findings/notion/rag.htb/generated-export.md",
                sha256="e" * 64,
                size_bytes=0,
                metadata={"origin": "generated_export", "ingest_allowed": False},
            )
        )
        runtime.store.insert_document_chunk(
            DocumentChunk(
                id="legacy_generated_export_chunk",
                target_id=self.target.id,
                source_artifact_id="artifact_legacy_generated_export",
                source_sha256="e" * 64,
                chunk_index=0,
                title="Generated export",
                text="Generated export operator strategy must not enter operational prompts.",
                token_count=9,
                metadata={
                    "corpus_type": "operator_note",
                    "domain": "operator_note",
                    "source_type": "generated_export",
                    "origin": "generated_export",
                    "operational_retrieval_allowed": False,
                },
            )
        )

        pack = runtime.build_rag_context_pack(
            "generated export operator strategy",
            purpose="operator_answer",
            role="operator_chat",
            target=self.target,
            limit=5,
        )

        self.assertEqual(pack["chunks"], [])
        self.assertTrue(any(item["chunk_id"] == "legacy_generated_export_chunk" for item in pack["omitted_sources"]))
        self.assertTrue(any("generated_export" in item["reason"] for item in pack["omitted_sources"]))
        runtime.shutdown()

    def test_operator_rag_pack_omits_operational_retrieval_disabled_advisory_chunks(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_disabled_advisory",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="disabled-advisory.jsonl",
                sha256="f" * 64,
                size_bytes=0,
                metadata={"source_type": "methodology_doc"},
            )
        )
        self.store.insert_document_chunk(
            DocumentChunk(
                id="disabled_advisory_chunk",
                target_id=self.target.id,
                source_artifact_id="artifact_disabled_advisory",
                source_sha256="f" * 64,
                chunk_index=0,
                title="Retrieval disabled advisory",
                text="Retrieval disabled advisory context must not enter operational RAG prompts.",
                token_count=10,
                metadata={
                    "citation_id": "rag:disabled-advisory",
                    "corpus_type": "methodology_standards",
                    "domain": "methodology_standards",
                    "source_type": "methodology_doc",
                    "operational_retrieval_allowed": False,
                },
            )
        )

        pack = RagContextBroker(self.service).build_pack(
            "retrieval disabled advisory context",
            purpose="operator_answer",
            role="operator_chat",
            target=self.target,
            limit=5,
        )

        self.assertEqual(pack.chunks, [])
        self.assertEqual(pack.omitted_sources[0]["citation_id"], "rag:disabled-advisory")
        self.assertEqual(pack.omitted_sources[0]["reason"], "operational_retrieval_disabled")

    def test_operator_rag_pack_omits_unsupported_source_refs_metadata(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_unsupported_source_refs",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="unsupported-source-refs.jsonl",
                sha256="7" * 64,
                size_bytes=0,
                metadata={"source_type": "methodology_doc"},
            )
        )
        self.store.insert_document_chunk(
            DocumentChunk(
                id="unsupported_source_refs_chunk",
                target_id=self.target.id,
                source_artifact_id="artifact_unsupported_source_refs",
                source_sha256="7" * 64,
                chunk_index=0,
                title="Unsupported source refs",
                text="Unsupported provenance refs must not enter operational RAG prompts.",
                token_count=9,
                metadata={
                    "citation_id": "rag:unsupported-source-refs",
                    "corpus_type": "methodology_standards",
                    "domain": "methodology_standards",
                    "source_type": "methodology_doc",
                    "source_refs": ["github:issue-42"],
                },
            )
        )

        pack = RagContextBroker(self.service).build_pack(
            "unsupported provenance refs",
            purpose="operator_answer",
            role="operator_chat",
            target=self.target,
            limit=5,
        )

        self.assertEqual(pack.chunks, [])
        self.assertEqual(pack.omitted_sources[0]["citation_id"], "rag:unsupported-source-refs")
        self.assertIn("unsupported source_refs", pack.omitted_sources[0]["reason"])

    def test_operator_rag_pack_omits_uncited_source_refs_metadata(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_uncited_source_refs",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="uncited-source-refs.jsonl",
                sha256="8" * 64,
                size_bytes=0,
                metadata={"source_type": "methodology_doc"},
            )
        )
        self.store.insert_document_chunk(
            DocumentChunk(
                id="uncited_source_refs_chunk",
                target_id=self.target.id,
                source_artifact_id="artifact_uncited_source_refs",
                source_sha256="8" * 64,
                chunk_index=0,
                title="Uncited source refs",
                text="Uncited provenance refs must not enter operational RAG prompts.",
                token_count=9,
                metadata={
                    "citation_id": "rag:uncited-source-refs",
                    "corpus_type": "methodology_standards",
                    "domain": "methodology_standards",
                    "source_type": "methodology_doc",
                    "source_refs": ["rag:curated-source"],
                },
            )
        )

        pack = RagContextBroker(self.service).build_pack(
            "uncited provenance refs",
            purpose="operator_answer",
            role="operator_chat",
            target=self.target,
            limit=5,
        )

        self.assertEqual(pack.chunks, [])
        self.assertEqual(pack.omitted_sources[0]["citation_id"], "rag:uncited-source-refs")
        self.assertEqual(pack.omitted_sources[0]["reason"], "uncited source_refs: rag:curated-source")

    def test_operator_rag_pack_omits_legacy_generated_export_source_paths(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_legacy_export_path",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="findings/notion/rag.htb/notion-export.md",
                sha256="1" * 64,
                size_bytes=0,
                metadata={"source_type": "methodology_doc"},
            )
        )
        self.store.insert_document_chunk(
            DocumentChunk(
                id="legacy_generated_export_path_chunk",
                target_id=self.target.id,
                source_artifact_id="artifact_legacy_export_path",
                source_sha256="1" * 64,
                chunk_index=0,
                title="Generated export path",
                text="Generated export path context must not enter operational RAG prompts.",
                token_count=10,
                metadata={
                    "citation_id": "rag:legacy-export-path",
                    "corpus_type": "methodology_standards",
                    "domain": "methodology_standards",
                    "source_type": "methodology_doc",
                    "source_file": "findings/notion/rag.htb/notion-export.md",
                },
            )
        )

        pack = RagContextBroker(self.service).build_pack(
            "generated export path context",
            purpose="operator_answer",
            role="operator_chat",
            target=self.target,
            limit=5,
        )

        self.assertEqual(pack.chunks, [])
        self.assertEqual(pack.omitted_sources[0]["citation_id"], "rag:legacy-export-path")
        self.assertEqual(pack.omitted_sources[0]["reason"], "generated_export")

    def test_operator_rag_pack_omits_human_readable_generated_export_source_paths(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_display_export_path",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="advisory/context-source.txt",
                sha256="2" * 64,
                size_bytes=0,
                metadata={"source_type": "methodology_doc"},
            )
        )
        self.store.insert_document_chunk(
            DocumentChunk(
                id="display_generated_export_path_chunk",
                target_id=self.target.id,
                source_artifact_id="artifact_display_export_path",
                source_sha256="2" * 64,
                chunk_index=0,
                title="Generated export display path",
                text="Display-key generated export path context must not enter operational RAG prompts.",
                token_count=10,
                metadata={
                    "citation_id": "rag:display-export-path",
                    "corpus_type": "methodology_standards",
                    "domain": "methodology_standards",
                    "source_type": "methodology_doc",
                    "Source file": "findings/notion/rag.htb/notion-export.md",
                },
            )
        )

        pack = RagContextBroker(self.service).build_pack(
            "display generated export path context",
            purpose="operator_answer",
            role="operator_chat",
            target=self.target,
            limit=5,
        )

        self.assertEqual(pack.chunks, [])
        self.assertEqual(pack.omitted_sources[0]["citation_id"], "rag:display-export-path")
        self.assertEqual(pack.omitted_sources[0]["reason"], "generated_export")

    def test_operator_rag_pack_omits_generated_export_source_urls(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_export_source_url",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="remote-generated-export.jsonl",
                sha256="3" * 64,
                size_bytes=0,
                metadata={"source_type": "methodology_doc"},
            )
        )
        self.store.insert_document_chunk(
            DocumentChunk(
                id="generated_export_source_url_chunk",
                target_id=self.target.id,
                source_artifact_id="artifact_export_source_url",
                source_sha256="3" * 64,
                chunk_index=0,
                title="Generated export source URL",
                text="Generated export source URLs must not enter operational RAG prompts.",
                token_count=10,
                metadata={
                    "citation_id": "rag:export-source-url",
                    "corpus_type": "methodology_standards",
                    "domain": "methodology_standards",
                    "source_type": "methodology_doc",
                    "source_url": "https://example.invalid/findings/notion/rag.htb/notion-export.md",
                },
            )
        )

        pack = RagContextBroker(self.service).build_pack(
            "generated export source URL context",
            purpose="operator_answer",
            role="operator_chat",
            target=self.target,
            limit=5,
        )

        self.assertEqual(pack.chunks, [])
        self.assertEqual(pack.omitted_sources[0]["citation_id"], "rag:export-source-url")
        self.assertEqual(pack.omitted_sources[0]["reason"], "generated_export")

    def test_operator_rag_pack_omits_nested_generated_export_metadata(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_nested_export_marker",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="nested-export-marker.jsonl",
                sha256="4" * 64,
                size_bytes=0,
                metadata={"source_type": "methodology_doc"},
            )
        )
        self.store.insert_document_chunk(
            DocumentChunk(
                id="nested_generated_export_metadata_chunk",
                target_id=self.target.id,
                source_artifact_id="artifact_nested_export_marker",
                source_sha256="4" * 64,
                chunk_index=0,
                title="Nested generated export marker",
                text="Nested generated export metadata must not enter operational RAG prompts.",
                token_count=10,
                metadata={
                    "citation_id": "rag:nested-export-marker",
                    "corpus_type": "methodology_standards",
                    "domain": "methodology_standards",
                    "source_type": "methodology_doc",
                    "metadata": {"origin": "generated_export"},
                },
            )
        )

        pack = RagContextBroker(self.service).build_pack(
            "nested generated export metadata",
            purpose="operator_answer",
            role="operator_chat",
            target=self.target,
            limit=5,
        )

        self.assertEqual(pack.chunks, [])
        self.assertEqual(pack.omitted_sources[0]["citation_id"], "rag:nested-export-marker")
        self.assertEqual(pack.omitted_sources[0]["reason"], "generated_export")

    def test_ollama_embedding_provider_can_be_mocked(self) -> None:
        with patch("primordial.core.providers.ollama.OllamaClient.list_models") as list_models, patch(
            "primordial.core.providers.ollama.OllamaClient.embed"
        ) as embed:
            list_models.return_value = OllamaModelListResult(ok=True, models=["nomic-embed-text:v1.5"])
            embed.return_value = OllamaEmbeddingResponse(model="nomic-embed-text:v1.5", embeddings=[[0.1, 0.2]])
            provider = OllamaEmbeddingProvider(model_name="nomic-embed-text:v1.5")

            provider.assert_ready()
            vector = provider.embed("hello")

        self.assertEqual(vector, [0.1, 0.2])
        self.assertEqual(provider.dimension, 2)

    def _write_preprocessed_chunks(self, records: list[dict[str, object]]) -> Path:
        chunks_dir = self.root / "chunks"
        chunks_dir.mkdir(parents=True, exist_ok=True)
        path = chunks_dir / "chunks.jsonl"
        path.write_text("\n".join(json.dumps(record, sort_keys=True) for record in records) + "\n", encoding="utf-8")
        return chunks_dir

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
        ingest = runtime.rag_ingest_document(
            source,
            target=self.target.handle,
            corpus_type="htb_writeup",
            hint_policy="direct_task_hints",
        )

        hints = runtime.rag_hints("directory discovery", target=self.target.handle)

        self.assertIsNone(ingest["evidence"])
        self.assertTrue(hints["candidate_actions"], hints)
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

    def test_planner_rag_context_preserves_human_readable_direct_hint_metadata(self) -> None:
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
        runtime.store.insert_artifact(
            ArtifactRecord(
                id="artifact_display_direct_hint",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="display-direct-hint.jsonl",
                sha256="7" * 64,
                size_bytes=128,
                metadata={"source_type": "methodology_doc"},
            )
        )
        runtime.store.insert_document_chunk(
            DocumentChunk(
                id="display_direct_hint_chunk",
                target_id=self.target.id,
                source_artifact_id="artifact_display_direct_hint",
                source_sha256="7" * 64,
                chunk_index=0,
                title="Display direct hint",
                text="The writeup suggests the next approved web review step after HTTP evidence.",
                token_count=10,
                metadata={
                    "corpus_type": "htb_writeup",
                    "Hint policy": "direct_task_hints",
                    "Primitive hint": "content-discovery",
                    "Source trust": "operator_enabled",
                    "CVE IDs": ["CVE-2026-0002"],
                    "Walkthrough hint": True,
                },
            )
        )

        hints = runtime.rag_hints("HTTP evidence next web review", target=self.target.handle)
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

        self.assertTrue(hints["candidate_actions"], hints)
        self.assertEqual(hints["candidate_actions"][0]["kind"], "web_content_discovery")
        self.assertEqual(packet["rag_context"][0]["chunk_id"], "display_direct_hint_chunk")
        self.assertEqual(packet["rag_context"][0]["hint_policy"], "direct_task_hints")
        self.assertEqual(packet["rag_context"][0]["source_trust"], "operator_enabled")
        self.assertEqual(packet["rag_context"][0]["cve_ids"], ["CVE-2026-0002"])
        self.assertTrue(packet["rag_context"][0]["walkthrough_hint"])
        runtime.shutdown()


if __name__ == "__main__":
    unittest.main()
