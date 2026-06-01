from __future__ import annotations

from tests.test_markdown_migration_catalog_common import *


class MarkdownMigrationCatalogTestsPart2(MarkdownMigrationCatalogTestsBase):
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

__all__ = ["MarkdownMigrationCatalogTestsPart2"]
