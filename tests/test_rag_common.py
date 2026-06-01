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

class RagIngestionTestsBase(unittest.TestCase):
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

    def _write_preprocessed_chunks(self, records: list[dict[str, object]]) -> Path:
        chunks_dir = self.root / "chunks"
        chunks_dir.mkdir(parents=True, exist_ok=True)
        path = chunks_dir / "chunks.jsonl"
        path.write_text("\n".join(json.dumps(record, sort_keys=True) for record in records) + "\n", encoding="utf-8")
        return chunks_dir

__all__ = [name for name in globals() if not name.startswith("__")]
