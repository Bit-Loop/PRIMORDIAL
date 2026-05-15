from __future__ import annotations

import unittest

from primordial.core.primitives.aliases import normalize_primitive_hint


class PrimitiveAliasTests(unittest.TestCase):
    def test_common_planner_aliases_canonicalize_to_registered_primitives(self) -> None:
        cases = {
            "web_content_discovery": "content-discovery",
            "web-directory-enumeration": "content-discovery",
            "http_header_analysis": "http-probe",
            "web_probe": "http-probe",
            "service-identification": "tcp-service-discovery",
            "service_version_detection": "tcp-service-discovery",
            "service-version-fingerprinting": "tcp-service-discovery",
        }

        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(normalize_primitive_hint(raw), expected)

    def test_unsupported_vulnerability_scan_hint_is_not_mapped(self) -> None:
        self.assertEqual(normalize_primitive_hint("web_vulnerability_scan"), "web-vulnerability-scan")


if __name__ == "__main__":
    unittest.main()
