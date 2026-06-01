import importlib
from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
PYTHON_SOFT_MAX_LINES = 500
GENERATED_EXPORT_RULE_TOKENS = (
    "GENERATED_EXPORT_KINDS =",
    "GENERATED_EXPORT_SOURCE_TYPES =",
    "GENERATED_EXPORT_ORIGINS =",
    "PROMPT_GENERATED_EXPORT_KINDS =",
    "PROMPT_GENERATED_EXPORT_SOURCE_TYPES =",
    "PROMPT_GENERATED_EXPORT_ORIGINS =",
    "def _is_generated_export_record",
    "def _is_generated_export_context",
    "def _is_prompt_generated_export",
)
METADATA_FLAG_RULE_TOKENS = (
    "FALSY_METADATA_FLAG_VALUES =",
    "def _metadata_value_is_false",
)
TRUTH_LIKE_AUTHORITY_RULE_TOKENS = (
    "AUTHORITATIVE_AUTHORITIES =",
    "TRUTH_LIKE_CTFD_AUTHORITIES =",
    "TRUTH_LIKE_EXPORT_AUTHORITIES =",
    "TRUTH_LIKE_GITHUB_AUTHORITIES =",
    "TRUTH_LIKE_INBOUND_AUTHORITIES =",
    "TRUTH_LIKE_REPORT_AUTHORITIES =",
)
AI_DERIVED_PROVENANCE_RULE_TOKENS = (
    "AI_DERIVED_REPORT_CITATION_PREFIXES =",
    "AI_SUMMARY_SOURCE_REF_PREFIXES =",
    "EXPORT_CITATION_PREFIXES =",
)


class ContextModularityTests(unittest.TestCase):
    def test_context_assembler_stays_below_soft_module_limit(self) -> None:
        assembler_path = REPO_ROOT / "primordial" / "core" / "context" / "assembler.py"

        line_count = len(assembler_path.read_text(encoding="utf-8").splitlines())

        self.assertLessEqual(line_count, PYTHON_SOFT_MAX_LINES)

    def test_generated_export_recursion_rules_have_single_context_module(self) -> None:
        generated_exports = importlib.import_module("primordial.core.context.generated_exports")

        self.assertTrue(generated_exports.is_generated_export_context)
        context_dir = REPO_ROOT / "primordial" / "core" / "context"
        duplicated_rules: list[str] = []
        for path in context_dir.glob("*.py"):
            if path.name == "generated_exports.py":
                continue
            text = path.read_text(encoding="utf-8")
            duplicated_rules.extend(
                f"{path.name}:{token}" for token in GENERATED_EXPORT_RULE_TOKENS if token in text
            )

        self.assertEqual([], duplicated_rules)

    def test_falsy_metadata_flag_rules_have_single_context_module(self) -> None:
        metadata_flags = importlib.import_module("primordial.core.context.metadata_flags")

        self.assertTrue(metadata_flags.metadata_value_is_false)
        context_dir = REPO_ROOT / "primordial" / "core" / "context"
        duplicated_rules: list[str] = []
        for path in context_dir.glob("*.py"):
            if path.name == "metadata_flags.py":
                continue
            text = path.read_text(encoding="utf-8")
            duplicated_rules.extend(f"{path.name}:{token}" for token in METADATA_FLAG_RULE_TOKENS if token in text)

        self.assertEqual([], duplicated_rules)

    def test_truth_like_authority_rules_have_single_context_module(self) -> None:
        source_types = importlib.import_module("primordial.core.context.source_types")

        self.assertTrue(source_types.TRUTH_LIKE_AUTHORITIES)
        context_dir = REPO_ROOT / "primordial" / "core" / "context"
        duplicated_rules: list[str] = []
        for path in context_dir.glob("*.py"):
            if path.name == "source_types.py":
                continue
            text = path.read_text(encoding="utf-8")
            duplicated_rules.extend(
                f"{path.name}:{token}" for token in TRUTH_LIKE_AUTHORITY_RULE_TOKENS if token in text
            )

        self.assertEqual([], duplicated_rules)

    def test_ai_derived_provenance_rules_have_single_context_module(self) -> None:
        source_refs = importlib.import_module("primordial.core.context.source_refs")

        self.assertTrue(source_refs.AI_DERIVED_SOURCE_REF_PREFIXES)
        context_dir = REPO_ROOT / "primordial" / "core" / "context"
        duplicated_rules: list[str] = []
        for path in context_dir.glob("*.py"):
            if path.name == "source_refs.py":
                continue
            text = path.read_text(encoding="utf-8")
            duplicated_rules.extend(
                f"{path.name}:{token}" for token in AI_DERIVED_PROVENANCE_RULE_TOKENS if token in text
            )

        self.assertEqual([], duplicated_rules)


if __name__ == "__main__":
    unittest.main()
