from __future__ import annotations

import unittest

from primordial.core.context import CitationValidator, ContextEnvelope, ContextSinkValidator

from primordial.runtime import PrimordialRuntime

class ContextBoundaryTestsBase(unittest.TestCase):
    def _runtime_without_store(self) -> PrimordialRuntime:
        runtime = PrimordialRuntime.__new__(PrimordialRuntime)
        runtime.rag_search = _blocked_rag_search  # type: ignore[method-assign]
        return runtime

def _blocked_rag_search(*_args: object, **_kwargs: object) -> dict[str, object]:
    raise AssertionError("unscoped fallback search was called")

__all__ = [name for name in globals() if not name.startswith("__")]
