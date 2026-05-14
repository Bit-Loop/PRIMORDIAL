from __future__ import annotations

import unittest

try:
    from agent_chat_api.tests.support import PACKAGE_ROOT
except ModuleNotFoundError:
    from support import PACKAGE_ROOT


class ServiceAssetTests(unittest.TestCase):
    def test_user_systemd_service_targets_subfolder(self) -> None:
        service_path = PACKAGE_ROOT / "systemd" / "agent-chat-api.service"
        content = service_path.read_text(encoding="utf-8")
        self.assertIn("WorkingDirectory=/home/bitloop/Desktop/PRIMORDIAL/agent_chat_api", content)
        self.assertIn("--host 127.0.0.1 --port 8787", content)
        self.assertIn("--workspace-root /home/bitloop/Desktop/PRIMORDIAL/agent_chat_api", content)
        self.assertIn("EnvironmentFile=-/home/bitloop/Desktop/PRIMORDIAL/agent_chat_api/runtime/agent-chat-api.env", content)
        self.assertIn("Restart=on-failure", content)
        self.assertIn("WantedBy=default.target", content)


if __name__ == "__main__":
    unittest.main()
