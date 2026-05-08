from __future__ import annotations

import json
import stat
import tempfile
import unittest
from pathlib import Path

from primordial.core.credentials import CredentialStore


class CredentialStoreTests(unittest.TestCase):
    def test_credentials_are_stored_with_restricted_permissions_and_redacted_status(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "secrets" / "credentials.json"
            store = CredentialStore(path)
            store.initialize()

            store.update_service("discord", {"webhook_url": "https://discord.com/api/webhooks/super-secret"})

            self.assertEqual(store.get("discord", "webhook_url"), "https://discord.com/api/webhooks/super-secret")
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

            status = store.status()
            field = status["services"]["discord"]["webhook_url"]
            self.assertTrue(field["configured"])
            self.assertEqual(field["source"], "local_store")
            self.assertNotEqual(field["hint"], "https://discord.com/api/webhooks/super-secret")
            self.assertNotIn("super-secret", field["hint"])

    def test_initialize_removes_obsolete_web_api_token(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "secrets" / "credentials.json"
            store = CredentialStore(path)
            store.initialize()
            store.update_service("discord", {"webhook_url": "https://discord.com/api/webhooks/keep"})
            payload = {
                "version": 1,
                "services": {
                    "discord": {"webhook_url": {"value": "https://discord.com/api/webhooks/keep"}},
                    "web": {"bearer_token": {"value": "obsolete"}},
                },
            }
            path.write_text(json.dumps(payload), encoding="utf-8")

            store.initialize()

            status = store.status()
            self.assertIn("discord", status["services"])
            self.assertNotIn("web", status["services"])
            self.assertEqual(store.get("discord", "webhook_url"), "https://discord.com/api/webhooks/keep")

    def test_caido_credentials_are_supported_and_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "secrets" / "credentials.json"
            store = CredentialStore(path)
            store.initialize()

            store.update_service(
                "caido",
                {
                    "graphql_url": "http://127.0.0.1:8080/graphql",
                    "api_token": "caido-secret-token",
                },
            )

            status = store.status()
            self.assertEqual(store.get("caido", "graphql_url"), "http://127.0.0.1:8080/graphql")
            self.assertEqual(store.get("caido", "api_token"), "caido-secret-token")
            self.assertTrue(status["services"]["caido"]["graphql_url"]["configured"])
            self.assertTrue(status["services"]["caido"]["api_token"]["configured"])
            self.assertNotIn("caido-secret-token", json.dumps(status))

    def test_known_credentials_are_canonical_and_lab_is_compat_alias(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "secrets" / "credentials.json"
            store = CredentialStore(path)
            store.initialize()

            store.update_service("lab", {"username": "legacy-user", "password": "legacy-pass"})
            status = store.status()
            self.assertEqual(store.get("known", "username"), "legacy-user")
            self.assertTrue(status["services"]["known"]["username"]["configured"])
            self.assertIn("alias:lab", status["services"]["known"]["username"]["source"])

            store.update_service("known", {"username": "known-user", "password": "known-pass", "domain": "EXAMPLE"})
            self.assertEqual(store.get("known", "username"), "known-user")
            self.assertEqual(store.get("lab", "username"), "known-user")
            self.assertEqual(store.get("known", "domain"), "EXAMPLE")


if __name__ == "__main__":
    unittest.main()
