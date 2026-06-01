from __future__ import annotations

import unittest

try:
    from agent_chat_api.tests.support import PACKAGE_ROOT
except ModuleNotFoundError:
    from support import PACKAGE_ROOT

from agent_chat_api.manifest import load_service_manifest


class ServiceManifestTests(unittest.TestCase):
    def test_manifest_preserves_http_surface_and_safe_defaults(self) -> None:
        manifest = load_service_manifest(PACKAGE_ROOT / "service.json")

        self.assertEqual(manifest.service_id, "agent_chat_api")
        self.assertIn("standard library", manifest.runtime_boundary.lower())
        self.assertEqual(manifest.default_provider, "codex")
        self.assertEqual(manifest.fallback_providers, ("codex", "claude"))
        self.assertIn(("GET", "/health"), manifest.endpoints)
        self.assertIn(("POST", "/api/chat"), manifest.endpoints)
        self.assertIn(("POST", "/v1/chat/completions"), manifest.endpoints)
        self.assertEqual(manifest.provider_defaults["codex"]["sandbox"], "read-only")
        self.assertTrue(manifest.provider_defaults["codex"]["ephemeral"])
        self.assertEqual(manifest.provider_defaults["claude"]["tools"], "")
        self.assertFalse(manifest.provider_defaults["shell_allowed"])

    def test_manifest_marks_generated_markdown_reports_non_authoritative(self) -> None:
        manifest = load_service_manifest(PACKAGE_ROOT / "service.json")

        self.assertEqual(manifest.generated_markdown.path, "runtime/test-results")
        self.assertFalse(manifest.generated_markdown.ingest_allowed)
        self.assertFalse(manifest.generated_markdown.operational_retrieval_allowed)


if __name__ == "__main__":
    unittest.main()
