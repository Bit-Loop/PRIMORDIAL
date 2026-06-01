from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from primordial.core.autonomy import MethodologyCompiler
from primordial.core.catalog.loader import CatalogValidationError
from primordial.core.catalog.methodology_examples import MethodologyExamplesCatalog


REPO_ROOT = Path(__file__).resolve().parents[1]


class MethodologyExamplesCatalogTests(unittest.TestCase):
    def test_web_review_markdown_is_migrated_to_advisory_methodology_catalog(self) -> None:
        catalog = MethodologyExamplesCatalog(REPO_ROOT / "catalog" / "project").load()
        examples = {example.id: example for example in catalog.examples}
        web_review = examples["web_review"]

        self.assertEqual(catalog.id, "primordial_methodology_examples")
        self.assertEqual(catalog.status, "migrated_advisory_examples")
        self.assertEqual(catalog.authority, "typed_advisory_examples_not_runtime_policy")
        self.assertFalse(catalog.markdown_authoritative)
        self.assertIn("proposal_only", catalog.boundaries)
        self.assertIn("not_executable_by_default", catalog.boundaries)
        self.assertIn("baseline_catalogs_not_mutated_by_examples", catalog.boundaries)
        self.assertEqual(web_review.source_path, "examples/methodology/web_review.md")
        self.assertEqual(web_review.title, "Web Review Methodology")

    def test_web_review_preserves_assumptions_steps_and_promotion_requirements(self) -> None:
        catalog = MethodologyExamplesCatalog(REPO_ROOT / "catalog" / "project").load()
        web_review = {example.id: example for example in catalog.examples}["web_review"]

        self.assertEqual(
            web_review.assumptions,
            (
                "target_in_scope",
                "low_risk_http_review_allowed",
            ),
        )
        self.assertEqual(
            web_review.steps,
            (
                "collect_reachable_endpoints",
                "classify_auth_surfaces",
                "review_parameters",
                "document_missing_verification_primitives",
            ),
        )
        self.assertEqual(
            web_review.promotion_requirements,
            (
                "strict_catalog_validation",
                "focused_tests",
                "operator_approval",
            ),
        )

    def test_web_review_matches_methodology_compiler_proposal_semantics(self) -> None:
        catalog = MethodologyExamplesCatalog(REPO_ROOT / "catalog" / "project").load()
        web_review = {example.id: example for example in catalog.examples}["web_review"]

        self.assertEqual(web_review.compiler_input_format, "markdown")
        self.assertEqual(web_review.generated_artifact_path, "proposals/methodology/web_review/proposal.md")
        self.assertIn("operator_review_required_before_promotion", web_review.proposal_semantics)
        self.assertIn("strict_catalog_validation_required_before_promotion", web_review.proposal_semantics)

        proposal = MethodologyCompiler(Path("proposals/methodology")).compile_markdown(
            "# Web Review Methodology\n\n## Assumptions\nThe target is in scope.",
            name="web_review",
        )
        self.assertEqual(proposal.kind, "methodology")
        self.assertEqual(proposal.title, web_review.title)
        self.assertEqual(proposal.generated_artifacts[0].path, Path(web_review.generated_artifact_path))

    def test_methodology_examples_catalog_rejects_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "methodology_examples.yaml").write_text(
                "id: primordial_methodology_examples\n"
                "status: migrated_advisory_examples\n"
                "authority: typed_advisory_examples_not_runtime_policy\n"
                "markdown_authoritative: false\n"
                "boundaries: []\n"
                "examples: []\n"
                "unknown: true\n",
                encoding="utf-8",
            )

            with self.assertRaises(CatalogValidationError):
                MethodologyExamplesCatalog(root).load()


if __name__ == "__main__":
    unittest.main()
