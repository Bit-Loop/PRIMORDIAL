from __future__ import annotations

from email.message import Message
from types import SimpleNamespace
import unittest

from primordial.modes.security.execution_probe_tools import PrimitiveProbeToolMixin
from primordial.modes.security.execution_web_tools import PrimitiveWebToolMixin


class _ReconHarness(PrimitiveWebToolMixin, PrimitiveProbeToolMixin):
    def __init__(self) -> None:
        self.config = SimpleNamespace(max_evidence_items=5)

    def _run_content_discovery(self, base_url: str, host_header: str | None) -> list[dict[str, object]]:
        return []


class CTFLiveSolverReconTests(unittest.TestCase):
    def test_http_probe_parser_extracts_surface_metadata_for_local_ctf_html(self) -> None:
        headers = Message()
        headers["Content-Type"] = "text/html; charset=utf-8"
        body = b'<html><head><title>Local CTF</title></head><body><a href="/login?token=secret">Login</a><form action="/submit"></form></body></html>'

        probe = _ReconHarness()._normalize_probe_response(
            asset_label="local-ctf",
            requested_url="http://127.0.0.1:3100/?token=secret",
            effective_url="http://127.0.0.1:3100/",
            status_code=200,
            response_headers=headers,
            body=body,
            resolved_ips=["127.0.0.1"],
            ssl_verification_disabled=False,
            host_header=None,
        )

        self.assertEqual(probe["title"], "Local CTF")
        self.assertEqual(probe["page_links"], ["/login?token=%3Credacted%3E"])
        self.assertEqual(probe["forms"], ["/submit"])
        self.assertTrue(probe["surface_urls_redacted"])
        self.assertNotIn("secret", str(probe))

    def test_web_content_title_parser_is_available_to_ctf_content_discovery(self) -> None:
        title = _ReconHarness()._title_from_body("text/html", b"<title>Bounded Discovery</title>")

        self.assertEqual(title, "Bounded Discovery")


if __name__ == "__main__":
    unittest.main()
