from __future__ import annotations

import hashlib

import json

import unittest

from types import SimpleNamespace

from primordial.core.context.generated_exports import GENERATED_EXPORT_PATH_KEYS

from primordial.core.rag import context as rag_context

from primordial.core.rag.importer import RagChunkImporter, RagImportOptions

from primordial.core.rag.import_validation import RagImportRecordValidator, SOURCE_PATH_METADATA_KEYS

class RagImportRecordValidatorTestsBase(unittest.TestCase):
    pass

class RagChunkImporterMetadataTestsBase(unittest.TestCase):
    pass

class _CapturingSinkValidator:
    def __init__(self) -> None:
        self.envelopes = []

    def validate(self, sink, envelopes):
        self.sink = sink
        self.envelopes = list(envelopes)
        return SimpleNamespace(valid=True, errors=[])

__all__ = [name for name in globals() if not name.startswith("__")]
