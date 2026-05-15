from __future__ import annotations

from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch

from primordial.config import AppConfig
from primordial.core.domain.enums import AgentRole, EvidenceType, MethodologyPhase, ScopeProfile, TaskKind, VerificationStatus
from primordial.core.domain.models import EvidenceRecord, Target, Task
from primordial.core.providers.ollama import OllamaEmbeddingResponse, OllamaModelListResult
from primordial.core.rag import DeterministicHashEmbeddingProvider, DocumentIngestionError, DocumentIngestionService
from primordial.core.rag.citations import disallowed_rag_synthesis_model, validate_rag_citations
from primordial.core.rag.embeddings import OllamaEmbeddingProvider
from primordial.core.rag.importer import RagChunkImporter, RagImportOptions
from primordial.core.storage.runtime import RuntimeStore
from primordial.runtime import PrimordialRuntime


MANIFESTS_DIR = Path(__file__).resolve().parents[1] / "manifests"


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

    def test_mitre_taxonomy_is_blocked_for_action_selection(self) -> None:
        retrieved = [{"chunk_id": "attack_T0001", "metadata": {"domain": "mitre_attack", "planner_visibility": "taxonomy_only"}}]

        result = validate_rag_citations("Use this taxonomy only for reporting. rag:attack_T0001", retrieved, mode="action_selection")

        self.assertFalse(result.valid)
        self.assertEqual(result.blocked_source_use, ["rag:attack_T0001"])

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
