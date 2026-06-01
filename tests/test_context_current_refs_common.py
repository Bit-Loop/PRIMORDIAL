from __future__ import annotations

import unittest

from primordial.core.context.current_refs import (
    current_evidence_refs,
    current_note_refs,
    current_rag_refs,
    prompt_context_omission_reason,
)

from primordial.core.context.envelopes import ContextEnvelope

class ContextCurrentRefsTestsBase(unittest.TestCase):
    pass

__all__ = [name for name in globals() if not name.startswith("__")]
