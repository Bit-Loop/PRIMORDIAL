from __future__ import annotations

from pathlib import Path

import tempfile

import unittest

from primordial.core.catalog.loader import CatalogValidationError

from primordial.core.catalog.markdown_migrations import MarkdownMigrationCatalog

from primordial.core.catalog.rag_advisory_corpus import RagAdvisoryCorpusCatalog

REPO_ROOT = Path(__file__).resolve().parents[1]

CATALOG_DIR = REPO_ROOT / "catalog"

class MarkdownMigrationCatalogTestsBase(unittest.TestCase):
    pass

__all__ = [name for name in globals() if not name.startswith("__")]
