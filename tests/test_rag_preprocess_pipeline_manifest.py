from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
PREPROCESS_ROOT = REPO_ROOT / "primordial-rag-preprocess"
sys.path.insert(0, str(PREPROCESS_ROOT))

from primordial_preprocess.config import load_policy  # noqa: E402
from primordial_preprocess.pipeline_manifest import PipelineManifestValidationError, load_pipeline_manifest  # noqa: E402


class RagPreprocessPipelineManifestTests(unittest.TestCase):
    def test_readme_is_migrated_to_typed_pipeline_manifest(self) -> None:
        manifest = load_pipeline_manifest(PREPROCESS_ROOT / "config" / "pipeline_manifest.yaml")

        self.assertEqual(manifest.id, "primordial_rag_preprocess_pipeline")
        self.assertEqual(manifest.source_path, "primordial-rag-preprocess/README.md")
        self.assertEqual(manifest.status, "migrated_operational_manifest")
        self.assertFalse(manifest.markdown_authoritative)
        self.assertIn("local_only_preprocessing", manifest.purpose)
        self.assertIn("mixed_cybersecurity_formal_methods_web_kubernetes_binary_analysis_attack_corpus", manifest.purpose)
        self.assertEqual(
            manifest.pipeline_stages,
            (
                "inventory",
                "classify",
                "policy_gate",
                "extract",
                "parse_attack_json",
                "chunk",
                "validate",
                "manifest",
            ),
        )
        self.assertIn("never_modify_source_files", manifest.safety_and_provenance)
        self.assertIn("never_upload_sync_or_transmit_documents_or_extracted_text", manifest.safety_and_provenance)

    def test_manifest_commands_match_actual_run_pipeline_help(self) -> None:
        manifest = load_pipeline_manifest(PREPROCESS_ROOT / "config" / "pipeline_manifest.yaml")
        help_text = subprocess.run(
            [sys.executable, "scripts/run_pipeline.py", "--help"],
            cwd=PREPROCESS_ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout

        for option in manifest.cli_options:
            self.assertIn(option, help_text)
        for phase in ("inventory", "dedupe", "convert", "epub", "profiles", "mitre", "chunk", "merge", "eval", "validate"):
            self.assertIn(phase, help_text)

    def test_config_and_extraction_contracts_are_typed(self) -> None:
        manifest = load_pipeline_manifest(PREPROCESS_ROOT / "config" / "pipeline_manifest.yaml")
        policy = load_policy(PREPROCESS_ROOT / "config" / "corpus_policy.yaml")

        self.assertTrue(policy.prefer_docling)
        self.assertTrue(policy.docling_only)
        self.assertFalse(policy.fallback_extractors_enabled)
        self.assertEqual(policy.epub_conversion, "pandoc_only")
        self.assertTrue(policy.docling_allow_ocr)
        self.assertFalse(policy.extract_commercial_unknown_license)
        self.assertIn("docling_required_for_pdf_markdown_html_and_text", manifest.extraction_contracts)
        self.assertIn("epub_requires_pandoc_before_docling", manifest.extraction_contracts)
        self.assertIn("docling_or_pandoc_failure_records_error_and_continues_without_fallback", manifest.extraction_contracts)
        self.assertIn("commercial_extraction_requires_operator_source_override", manifest.override_rules)
        self.assertIn("do_not_use_overrides_to_bypass_drm_access_controls_or_license_uncertainty", manifest.override_rules)

    def test_output_layout_source_metadata_chunk_schema_and_attack_rules_are_typed(self) -> None:
        manifest = load_pipeline_manifest(PREPROCESS_ROOT / "config" / "pipeline_manifest.yaml")

        self.assertIn("inventory.jsonl", manifest.output_files)
        self.assertIn("classified_sources.jsonl", manifest.output_files)
        self.assertIn("chunks/chunks.jsonl", manifest.output_files)
        self.assertIn("validation_report.json", manifest.output_files)
        self.assertIn("manifest.json", manifest.output_files)
        self.assertIn("classification_report.md", manifest.generated_markdown_outputs)
        self.assertIn("manifest.md", manifest.generated_markdown_outputs)
        self.assertIn("generated_markdown_outputs_runtime_only_not_source_truth", manifest.output_rules)
        self.assertIn("original_path", manifest.source_metadata_fields)
        self.assertIn("sha256", manifest.source_metadata_fields)
        self.assertIn("planner_visibility", manifest.classification_fields)
        self.assertIn("requires_operator_approval", manifest.classification_fields)
        self.assertIn("deterministic_chunk_id", manifest.chunk_schema_fields)
        self.assertIn("allowed_use_modes", manifest.chunk_schema_fields)
        self.assertIn("attack_chunks_planner_visibility_taxonomy_only", manifest.attack_json_rules)
        self.assertIn("do_not_use_attack_to_decide_scope_or_bypass_authorization", manifest.attack_json_rules)

    def test_pipeline_manifest_rejects_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pipeline_manifest.yaml"
            path.write_text(
                "id: primordial_rag_preprocess_pipeline\n"
                "source_path: primordial-rag-preprocess/README.md\n"
                "status: migrated_operational_manifest\n"
                "markdown_authoritative: false\n"
                "purpose: []\n"
                "safety_and_provenance: []\n"
                "install_commands: []\n"
                "cli_options: []\n"
                "pipeline_stages: []\n"
                "phase_modes: []\n"
                "output_files: []\n"
                "generated_markdown_outputs: []\n"
                "output_rules: []\n"
                "source_metadata_fields: []\n"
                "classification_fields: []\n"
                "chunk_schema_fields: []\n"
                "override_rules: []\n"
                "attack_json_rules: []\n"
                "extraction_contracts: []\n"
                "troubleshooting_signals: []\n"
                "unknown: true\n",
                encoding="utf-8",
            )

            with self.assertRaises(PipelineManifestValidationError):
                load_pipeline_manifest(path)


if __name__ == "__main__":
    unittest.main()
