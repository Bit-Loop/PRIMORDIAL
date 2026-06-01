from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
PREPROCESS_ROOT = REPO_ROOT / "primordial-rag-preprocess"
sys.path.insert(0, str(PREPROCESS_ROOT))

from primordial_preprocess.agent_policy import AgentPolicyValidationError, load_agent_policy  # noqa: E402
from primordial_preprocess.classification import classify_record  # noqa: E402
from primordial_preprocess.config import CorpusPolicy, load_policy  # noqa: E402
from primordial_preprocess.policy import apply_policy_to_record  # noqa: E402


class RagPreprocessAgentPolicyTests(unittest.TestCase):
    def test_agents_markdown_is_migrated_to_local_agent_policy_config(self) -> None:
        policy = load_agent_policy(PREPROCESS_ROOT / "config" / "agent_policy.yaml")

        self.assertEqual(policy.id, "primordial_rag_preprocess_agent_policy")
        self.assertEqual(policy.source_path, "primordial-rag-preprocess/AGENTS.md")
        self.assertEqual(policy.status, "migrated_local_preprocess_policy")
        self.assertFalse(policy.markdown_authoritative)
        self.assertIn("local_only_preprocessing_pipeline", policy.boundaries)
        self.assertIn("do_not_modify_original_corpus_files", policy.boundaries)
        self.assertIn("no_upload_sync_transmit_or_exfiltrate_source_documents_or_extracted_text", policy.boundaries)

    def test_extraction_defaults_and_parser_constraints_are_encoded(self) -> None:
        policy = load_agent_policy(PREPROCESS_ROOT / "config" / "agent_policy.yaml")

        self.assertIn("unknown_commercial_or_proprietary_sources_inventory_only_until_operator_override", policy.defaults)
        self.assertIn("mitre_attack_json_structural_taxonomy_records_only", policy.parser_constraints)
        self.assertIn("do_not_vectorize_raw_attack_bundles_as_giant_chunks", policy.parser_constraints)
        self.assertIn("docling_first_policy_gated_document_extraction", policy.extraction_constraints)
        self.assertIn("no_silent_fallback_extractors_when_docling_unavailable_or_fails", policy.extraction_constraints)
        self.assertIn("epub_handling_pandoc_only", policy.extraction_constraints)
        self.assertIn("ocr_allowed_only_when_docling_allow_ocr_true", policy.extraction_constraints)
        self.assertIn("docling_rapidocr_may_initialize_local_model_artifacts_on_first_use", policy.extraction_constraints)

    def test_policy_config_and_runtime_behavior_match_agent_constraints(self) -> None:
        policy = load_agent_policy(PREPROCESS_ROOT / "config" / "agent_policy.yaml")
        corpus_policy = load_policy(PREPROCESS_ROOT / "config" / "corpus_policy.yaml")

        self.assertFalse(corpus_policy.extract_commercial_unknown_license)
        self.assertTrue(corpus_policy.prefer_docling)
        self.assertTrue(corpus_policy.docling_only)
        self.assertFalse(corpus_policy.fallback_extractors_enabled)
        self.assertEqual(corpus_policy.epub_conversion, "pandoc_only")
        self.assertTrue(corpus_policy.docling_allow_ocr)
        self.assertIn("docling_allow_ocr", policy.explicit_operator_toggles)

        blocked = apply_policy_to_record(
            {
                "sha256": "abc",
                "recommended_keep": True,
                "planner_visibility": "normal",
                "detected_type": "pdf",
                "filename": "Commercial API Security.pdf",
                "license_status": "unknown_commercial_or_proprietary",
            },
            CorpusPolicy(),
        )
        self.assertTrue(blocked["policy_blocked"])
        self.assertIn("operator override", blocked["policy_block_reason"])

    def test_restricted_material_is_not_normal_planner_retrieval_by_default(self) -> None:
        policy = load_agent_policy(PREPROCESS_ROOT / "config" / "agent_policy.yaml")

        for item in (
            "restricted_exploit_material",
            "kernel_security_material",
            "binary_analysis_material",
            "post_exploitation_material",
            "tool_abuse_material",
            "low_authority_hacking_material",
        ):
            self.assertIn(item, policy.restricted_material)

        binary = classify_record({"filename": "practical-binary-analysis.pdf", "relative_path": "books/binary-analysis.pdf"})
        kernel = classify_record({"filename": "linux-kernel-exploitation.pdf", "relative_path": "books/linux-kernel.pdf"})
        tool = classify_record({"filename": "metasploit-guide.pdf", "relative_path": "tools/metasploit-guide.pdf"})

        self.assertEqual(binary["planner_visibility"], "restricted")
        self.assertEqual(kernel["planner_visibility"], "restricted")
        self.assertEqual(tool["planner_visibility"], "quarantine")

    def test_agent_policy_rejects_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "agent_policy.yaml"
            path.write_text(
                "id: primordial_rag_preprocess_agent_policy\n"
                "source_path: primordial-rag-preprocess/AGENTS.md\n"
                "status: migrated_local_preprocess_policy\n"
                "markdown_authoritative: false\n"
                "boundaries: []\n"
                "defaults: []\n"
                "parser_constraints: []\n"
                "extraction_constraints: []\n"
                "explicit_operator_toggles: []\n"
                "restricted_material: []\n"
                "unknown: true\n",
                encoding="utf-8",
            )

            with self.assertRaises(AgentPolicyValidationError):
                load_agent_policy(path)


if __name__ == "__main__":
    unittest.main()
