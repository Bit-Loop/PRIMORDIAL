from __future__ import annotations

from pathlib import Path
import unittest

from primordial.core.quality.structure import audit_structure


class AgentChatStructureQualityTests(unittest.TestCase):
    def test_agent_chat_module_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/providers/agent_chat.py"
            and record.kind == "module"
        ]
        self.assertEqual(records, [])

    def test_premium_review_execute_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/providers/agent_chat.py"
            and record.kind == "function"
            and record.name == "_execute"
        ]
        self.assertEqual(records, [])


if __name__ == "__main__":
    unittest.main()
