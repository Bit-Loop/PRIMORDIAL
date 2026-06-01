from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from primordial.core.catalog.loader import CatalogValidationError
from primordial.core.catalog.markdown_migrations import MarkdownMigrationCatalog
from primordial.core.catalog.rag_advisory_corpus import RagAdvisoryCorpusCatalog


REPO_ROOT = Path(__file__).resolve().parents[1]
CATALOG_DIR = REPO_ROOT / "catalog"


class MarkdownMigrationCatalogTests(unittest.TestCase):
    def test_every_quarantined_markdown_source_has_migration_record(self) -> None:
        catalog = MarkdownMigrationCatalog(CATALOG_DIR / "policies" / "markdown_migrations.yaml")
        catalog.load()
        quarantine_root = REPO_ROOT / "runtime" / "quarantine" / "markdown"

        missing = [
            path.relative_to(quarantine_root).as_posix()
            for path in sorted(quarantine_root.rglob("*.md"))
            if catalog.get(path.relative_to(quarantine_root).as_posix()) is None
        ]

        self.assertEqual(missing, [])

    def test_operator_intent_and_capability_docs_have_executable_replacements(self) -> None:
        catalog = MarkdownMigrationCatalog(CATALOG_DIR / "policies" / "markdown_migrations.yaml")
        migrations = catalog.load()

        operator_intent = catalog.get("docs/operator_intent.md")
        self.assertIsNotNone(operator_intent)
        self.assertEqual(operator_intent.status, "migrated")
        self.assertIn("catalog/intents/recon_only.yaml", operator_intent.replacement_refs)
        self.assertIn("catalog/intents/htb_lab.yaml", operator_intent.replacement_refs)
        self.assertIn("tests/test_environment_classifier.py", operator_intent.verification_refs)

        capability_catalog = catalog.get("docs/capability_catalog.md")
        self.assertIsNotNone(capability_catalog)
        self.assertEqual(capability_catalog.status, "migrated")
        self.assertIn("catalog/capabilities/semantics.yaml", capability_catalog.replacement_refs)
        self.assertIn("primordial/core/catalog/capabilities.py", capability_catalog.replacement_refs)
        self.assertIn("tests/test_operator_intent_catalog_autonomy.py", capability_catalog.verification_refs)

        self.assertTrue({"docs/operator_intent.md", "docs/capability_catalog.md"} <= {item.source_path for item in migrations})

    def test_historical_reports_are_classified_as_archived_not_authoritative(self) -> None:
        catalog = MarkdownMigrationCatalog(CATALOG_DIR / "policies" / "markdown_migrations.yaml")
        catalog.load()

        for source_path in (
            "AUTONOMOUS_RUNTIME_TEST_REPORT.md",
            "HELIX_RUNTIME_TEST_REPORT.md",
            "PROJECT_COMPLEXITY_REPORT.md",
            "quick-complexity-notes.md",
            "codex_primordial_model_role_benchmark_20260509.md",
            "codex_primordial_OLLAMA-model_role_benchmark_20260509.md",
        ):
            migration = catalog.get(source_path)
            self.assertIsNotNone(migration, source_path)
            self.assertEqual(migration.status, "archived_historical")
            self.assertIn(f"runtime/quarantine/markdown/{source_path}", migration.replacement_refs)
            self.assertIn("primordial/core/quality/markdown.py", migration.verification_refs)

    def test_caido_skill_markdown_is_migrated_to_yaml_manifest(self) -> None:
        catalog = MarkdownMigrationCatalog(CATALOG_DIR / "policies" / "markdown_migrations.yaml")
        catalog.load()

        migration = catalog.get("skills/caido-httpql/SKILL.md")

        self.assertIsNotNone(migration)
        self.assertEqual(migration.status, "migrated")
        self.assertIn("skills/caido-httpql/skill.yaml", migration.replacement_refs)
        self.assertIn("primordial/core/skills.py", migration.replacement_refs)
        self.assertIn("tests/test_caido_and_skills.py", migration.verification_refs)

    def test_findings_readme_is_migrated_to_workspace_manifest(self) -> None:
        catalog = MarkdownMigrationCatalog(CATALOG_DIR / "policies" / "markdown_migrations.yaml")
        catalog.load()

        migration = catalog.get("findings/README.md")

        self.assertIsNotNone(migration)
        self.assertEqual(migration.status, "migrated")
        self.assertIn("findings/workspace.yaml", migration.replacement_refs)
        self.assertIn("primordial/core/findings_context.py", migration.replacement_refs)
        self.assertIn("tests/test_findings_context.py", migration.verification_refs)

    def test_agent_chat_api_readme_is_migrated_to_service_manifest(self) -> None:
        catalog = MarkdownMigrationCatalog(CATALOG_DIR / "policies" / "markdown_migrations.yaml")
        catalog.load()

        migration = catalog.get("agent_chat_api/README.md")

        self.assertIsNotNone(migration)
        self.assertEqual(migration.status, "migrated")
        self.assertIn("agent_chat_api/service.json", migration.replacement_refs)
        self.assertIn("agent_chat_api/manifest.py", migration.replacement_refs)
        self.assertIn("agent_chat_api/test_reporter.py", migration.replacement_refs)
        self.assertIn("agent_chat_api/tests/test_service_manifest.py", migration.verification_refs)

    def test_root_readme_is_migrated_to_project_manifest(self) -> None:
        catalog = MarkdownMigrationCatalog(CATALOG_DIR / "policies" / "markdown_migrations.yaml")
        catalog.load()

        migration = catalog.get("README.md")

        self.assertIsNotNone(migration)
        self.assertEqual(migration.status, "migrated")
        self.assertIn("catalog/project/primordial.yaml", migration.replacement_refs)
        self.assertIn("primordial/core/catalog/project_manifest.py", migration.replacement_refs)
        self.assertIn("tests/test_project_manifest.py", migration.verification_refs)

    def test_v1_todo_is_migrated_to_roadmap_catalog(self) -> None:
        catalog = MarkdownMigrationCatalog(CATALOG_DIR / "policies" / "markdown_migrations.yaml")
        catalog.load()

        migration = catalog.get("TODO-real-v1.md")

        self.assertIsNotNone(migration)
        self.assertEqual(migration.status, "migrated")
        self.assertIn("catalog/project/v1_roadmap.yaml", migration.replacement_refs)
        self.assertIn("primordial/core/catalog/v1_roadmap.py", migration.replacement_refs)
        self.assertIn("tests/test_v1_roadmap_catalog.py", migration.verification_refs)

    def test_ai_agent_current_context_is_migrated_to_typed_catalog(self) -> None:
        catalog = MarkdownMigrationCatalog(CATALOG_DIR / "policies" / "markdown_migrations.yaml")
        catalog.load()

        migration = catalog.get("ai-agent-current-context.md")

        self.assertIsNotNone(migration)
        self.assertEqual(migration.status, "migrated")
        self.assertIn("catalog/project/ai_agent_current_context.yaml", migration.replacement_refs)
        self.assertIn("primordial/core/catalog/ai_agent_context.py", migration.replacement_refs)
        self.assertIn("tests/test_ai_agent_context_catalog.py", migration.verification_refs)

    def test_ai_agent_prd_is_migrated_to_typed_product_requirements(self) -> None:
        catalog = MarkdownMigrationCatalog(CATALOG_DIR / "policies" / "markdown_migrations.yaml")
        catalog.load()

        migration = catalog.get("ai-agent-prd.md")

        self.assertIsNotNone(migration)
        self.assertEqual(migration.status, "migrated")
        self.assertIn("catalog/project/ai_agent_prd.yaml", migration.replacement_refs)
        self.assertIn("primordial/core/catalog/ai_agent_prd.py", migration.replacement_refs)
        self.assertIn("tests/test_ai_agent_prd_catalog.py", migration.verification_refs)

    def test_ai_tuning_is_migrated_to_typed_model_tuning_catalog(self) -> None:
        catalog = MarkdownMigrationCatalog(CATALOG_DIR / "policies" / "markdown_migrations.yaml")
        catalog.load()

        migration = catalog.get("ai-tuning.md")

        self.assertIsNotNone(migration)
        self.assertEqual(migration.status, "migrated")
        self.assertIn("catalog/project/lmstudio_tuning.yaml", migration.replacement_refs)
        self.assertIn("primordial/core/catalog/model_tuning.py", migration.replacement_refs)
        self.assertIn("tests/test_model_tuning_catalog.py", migration.verification_refs)

    def test_conflicting_methodologies_are_migrated_to_decision_pressure_catalog(self) -> None:
        catalog = MarkdownMigrationCatalog(CATALOG_DIR / "policies" / "markdown_migrations.yaml")
        catalog.load()

        migration = catalog.get("docs/CONFLICTING_METHODOLOGIES.md")

        self.assertIsNotNone(migration)
        self.assertEqual(migration.status, "migrated")
        self.assertIn("catalog/project/decision_pressure.yaml", migration.replacement_refs)
        self.assertIn("primordial/core/catalog/decision_pressure.py", migration.replacement_refs)
        self.assertIn("tests/test_decision_pressure_catalog.py", migration.verification_refs)

    def test_floor_plan_is_migrated_to_typed_codebase_floor_plan(self) -> None:
        catalog = MarkdownMigrationCatalog(CATALOG_DIR / "policies" / "markdown_migrations.yaml")
        catalog.load()

        migration = catalog.get("docs/FLOOR_PLAN.md")

        self.assertIsNotNone(migration)
        self.assertEqual(migration.status, "migrated")
        self.assertIn("catalog/project/codebase_floor_plan.yaml", migration.replacement_refs)
        self.assertIn("primordial/core/catalog/codebase_floor_plan.py", migration.replacement_refs)
        self.assertIn("tests/test_codebase_floor_plan_catalog.py", migration.verification_refs)

    def test_how_primordial_works_is_migrated_to_operational_architecture_catalog(self) -> None:
        catalog = MarkdownMigrationCatalog(CATALOG_DIR / "policies" / "markdown_migrations.yaml")
        catalog.load()

        migration = catalog.get("docs/HOW_PRIMORDIAL_WORKS.md")

        self.assertIsNotNone(migration)
        self.assertEqual(migration.status, "migrated")
        self.assertIn("catalog/project/operational_architecture.yaml", migration.replacement_refs)
        self.assertIn("primordial/core/catalog/operational_architecture.py", migration.replacement_refs)
        self.assertIn("tests/test_operational_architecture_catalog.py", migration.verification_refs)

    def test_human_change_guide_is_migrated_to_typed_safety_catalog(self) -> None:
        catalog = MarkdownMigrationCatalog(CATALOG_DIR / "policies" / "markdown_migrations.yaml")
        catalog.load()

        migration = catalog.get("docs/HUMAN_CHANGE_GUIDE.md")

        self.assertIsNotNone(migration)
        self.assertEqual(migration.status, "migrated")
        self.assertIn("catalog/project/human_change_safety.yaml", migration.replacement_refs)
        self.assertIn("primordial/core/catalog/human_change_safety.py", migration.replacement_refs)
        self.assertIn("tests/test_human_change_safety_catalog.py", migration.verification_refs)

    def test_claude_guidance_files_are_migrated_to_typed_assistant_contract(self) -> None:
        catalog = MarkdownMigrationCatalog(CATALOG_DIR / "policies" / "markdown_migrations.yaml")
        catalog.load()

        for source_path in ("CLAUDE.md", "claude-instructions.md"):
            migration = catalog.get(source_path)
            self.assertIsNotNone(migration, source_path)
            self.assertEqual(migration.status, "migrated")
            self.assertIn("catalog/project/assistant_operating_contract.yaml", migration.replacement_refs)
            self.assertIn("primordial/core/catalog/assistant_operating_contract.py", migration.replacement_refs)
            self.assertIn("tests/test_assistant_operating_contract_catalog.py", migration.verification_refs)
            self.assertIn("tests/test_markdown_quality.py", migration.verification_refs)

    def test_docs_rag_src_markdown_files_are_migrated_to_advisory_corpus_manifest(self) -> None:
        corpus = RagAdvisoryCorpusCatalog(CATALOG_DIR / "rag").load()
        catalog = MarkdownMigrationCatalog(CATALOG_DIR / "policies" / "markdown_migrations.yaml")
        catalog.load()

        for document in corpus.documents:
            migration = catalog.get(document.source_path)
            self.assertIsNotNone(migration, document.source_path)
            self.assertEqual(migration.status, "migrated")
            self.assertIn("catalog/rag/advisory_corpus.yaml", migration.replacement_refs)
            self.assertIn("primordial/core/catalog/rag_advisory_corpus.py", migration.replacement_refs)
            self.assertIn(document.quarantine_path, migration.replacement_refs)
            self.assertIn("tests/test_rag_advisory_corpus_catalog.py", migration.verification_refs)
            self.assertIn("tests/test_rag_source_markdown_boundaries.py", migration.verification_refs)
            self.assertIn("tests/test_markdown_quality.py", migration.verification_refs)

    def test_model_selection_notes_are_migrated_to_typed_model_selection_catalog(self) -> None:
        catalog = MarkdownMigrationCatalog(CATALOG_DIR / "policies" / "markdown_migrations.yaml")
        catalog.load()

        migration = catalog.get("docs/MODEL_SELECTION_NOTES.md")

        self.assertIsNotNone(migration)
        self.assertEqual(migration.status, "migrated")
        self.assertIn("catalog/project/model_selection.yaml", migration.replacement_refs)
        self.assertIn("primordial/core/catalog/model_selection.py", migration.replacement_refs)
        self.assertIn("tests/test_model_selection_catalog.py", migration.verification_refs)

    def test_structured_autonomy_is_migrated_to_typed_scaffold_catalog(self) -> None:
        catalog = MarkdownMigrationCatalog(CATALOG_DIR / "policies" / "markdown_migrations.yaml")
        catalog.load()

        migration = catalog.get("docs/structured_autonomy.md")

        self.assertIsNotNone(migration)
        self.assertEqual(migration.status, "migrated")
        self.assertIn("catalog/project/structured_autonomy.yaml", migration.replacement_refs)
        self.assertIn("primordial/core/catalog/structured_autonomy.py", migration.replacement_refs)
        self.assertIn("tests/test_structured_autonomy_catalog.py", migration.verification_refs)

    def test_v2_readme_is_migrated_to_typed_non_runtime_manifest(self) -> None:
        catalog = MarkdownMigrationCatalog(CATALOG_DIR / "policies" / "markdown_migrations.yaml")
        catalog.load()

        migration = catalog.get("docs/v2/README.md")

        self.assertIsNotNone(migration)
        self.assertEqual(migration.status, "migrated")
        self.assertIn("catalog/project/v2_planning.yaml", migration.replacement_refs)
        self.assertIn("primordial/core/catalog/v2_planning.py", migration.replacement_refs)
        self.assertIn("tests/test_v2_planning_manifest.py", migration.verification_refs)

    def test_v2_reverse_engineering_framework_is_migrated_to_typed_catalog(self) -> None:
        catalog = MarkdownMigrationCatalog(CATALOG_DIR / "policies" / "markdown_migrations.yaml")
        catalog.load()

        migration = catalog.get("docs/v2/reverse_engineering_framework.md")

        self.assertIsNotNone(migration)
        self.assertEqual(migration.status, "migrated")
        self.assertIn("catalog/project/v2_reverse_engineering_framework.yaml", migration.replacement_refs)
        self.assertIn("primordial/core/catalog/v2_reverse_engineering_framework.py", migration.replacement_refs)
        self.assertIn("tests/test_v2_reverse_engineering_framework_catalog.py", migration.verification_refs)

    def test_v2_reverse_engineering_test_plan_is_migrated_to_typed_catalog(self) -> None:
        catalog = MarkdownMigrationCatalog(CATALOG_DIR / "policies" / "markdown_migrations.yaml")
        catalog.load()

        migration = catalog.get("docs/v2/reverse_engineering_test_plan.md")

        self.assertIsNotNone(migration)
        self.assertEqual(migration.status, "migrated")
        self.assertIn("catalog/project/v2_reverse_engineering_test_plan.yaml", migration.replacement_refs)
        self.assertIn("primordial/core/catalog/v2_reverse_engineering_test_plan.py", migration.replacement_refs)
        self.assertIn("tests/test_v2_reverse_engineering_test_plan_catalog.py", migration.verification_refs)

    def test_web_review_methodology_example_is_migrated_to_typed_advisory_catalog(self) -> None:
        catalog = MarkdownMigrationCatalog(CATALOG_DIR / "policies" / "markdown_migrations.yaml")
        catalog.load()

        migration = catalog.get("examples/methodology/web_review.md")

        self.assertIsNotNone(migration)
        self.assertEqual(migration.status, "migrated")
        self.assertIn("catalog/project/methodology_examples.yaml", migration.replacement_refs)
        self.assertIn("primordial/core/catalog/methodology_examples.py", migration.replacement_refs)
        self.assertIn("tests/test_methodology_examples_catalog.py", migration.verification_refs)

    def test_rag_preprocess_agents_is_migrated_to_local_agent_policy(self) -> None:
        catalog = MarkdownMigrationCatalog(CATALOG_DIR / "policies" / "markdown_migrations.yaml")
        catalog.load()

        migration = catalog.get("primordial-rag-preprocess/AGENTS.md")

        self.assertIsNotNone(migration)
        self.assertEqual(migration.status, "migrated")
        self.assertIn("primordial-rag-preprocess/config/agent_policy.yaml", migration.replacement_refs)
        self.assertIn("primordial-rag-preprocess/primordial_preprocess/agent_policy.py", migration.replacement_refs)
        self.assertIn("tests/test_rag_preprocess_agent_policy.py", migration.verification_refs)

    def test_rag_preprocess_readme_is_migrated_to_typed_pipeline_manifest(self) -> None:
        catalog = MarkdownMigrationCatalog(CATALOG_DIR / "policies" / "markdown_migrations.yaml")
        catalog.load()

        migration = catalog.get("primordial-rag-preprocess/README.md")

        self.assertIsNotNone(migration)
        self.assertEqual(migration.status, "migrated")
        self.assertIn("primordial-rag-preprocess/config/pipeline_manifest.yaml", migration.replacement_refs)
        self.assertIn("primordial-rag-preprocess/primordial_preprocess/pipeline_manifest.py", migration.replacement_refs)
        self.assertIn("tests/test_rag_preprocess_pipeline_manifest.py", migration.verification_refs)

    def test_migration_catalog_rejects_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "markdown_migrations.yaml"
            path.write_text(
                "migrations:\n"
                "  - source_path: docs/example.md\n"
                "    status: migrated\n"
                "    replacement_refs: []\n"
                "    verification_refs: []\n"
                "    unknown: true\n",
                encoding="utf-8",
            )

            with self.assertRaises(CatalogValidationError):
                MarkdownMigrationCatalog(path).load()


if __name__ == "__main__":
    unittest.main()
