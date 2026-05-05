from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from primordial.adapters.caido import CaidoIntegrationService
from primordial.config import AppConfig
from primordial.core.credentials import CredentialStore
from primordial.runtime import PrimordialRuntime


class CaidoAndSkillTests(unittest.TestCase):
    def test_caido_status_fails_closed_until_configured(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = CredentialStore(Path(temp_dir) / "secrets" / "credentials.json")
            store.initialize()
            service = CaidoIntegrationService(store)

            status = service.status()

            self.assertFalse(status["configured"])
            self.assertFalse(status["ok"])
            self.assertIn("not configured", status["error"])

    def test_caido_health_uses_bearer_graphql_request(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = CredentialStore(Path(temp_dir) / "secrets" / "credentials.json")
            store.initialize()
            store.update_service(
                "caido",
                {
                    "graphql_url": "http://127.0.0.1:8080/graphql",
                    "api_token": "secret-token",
                },
            )
            service = CaidoIntegrationService(store)

            class FakeResponse:
                status = 200

                def __enter__(self):
                    return self

                def __exit__(self, *_args):
                    return False

                def read(self):
                    return json.dumps({"data": {"__typename": "Query"}}).encode("utf-8")

            captured = {}

            def fake_urlopen(req, timeout):
                captured["url"] = req.full_url
                captured["headers"] = dict(req.header_items())
                captured["timeout"] = timeout
                return FakeResponse()

            with patch("primordial.adapters.caido.request.urlopen", side_effect=fake_urlopen):
                health = service.health()

            self.assertTrue(health["ok"])
            self.assertEqual(captured["url"], "http://127.0.0.1:8080/graphql")
            self.assertEqual(captured["headers"]["Authorization"], "Bearer secret-token")

    def test_skills_are_loaded_into_runtime_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            skill_dir = root / "skills" / "caido-httpql"
            skill_dir.mkdir(parents=True)
            (skill_dir / "SKILL.md").write_text(
                "---\nid: caido-httpql\nsummary: Use Caido HTTPQL for scoped traffic review.\ntags: caido,httpql\n---\n# Caido\nBody",
                encoding="utf-8",
            )
            config = AppConfig.from_env(project_root=root)
            config.ensure_directories()
            runtime = PrimordialRuntime(config)
            runtime.initialize()

            payload = runtime.skills_payload()

            self.assertEqual(payload["skills"][0]["id"], "caido-httpql")
            self.assertIn("Caido HTTPQL", payload["skills"][0]["summary"])
            self.assertIn("caido-httpql", runtime.skills.context_digest())
            runtime.shutdown()


if __name__ == "__main__":
    unittest.main()
