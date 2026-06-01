from __future__ import annotations

import unittest

from primordial.labs.ctf import load_ctf_target_manifest, validate_vulhub_exploit_applicability
from tests.support import fixture_flag


class VulhubApplicabilityContractTests(unittest.TestCase):
    def test_vulhub_applicability_accepts_affected_observed_version_evidence(self) -> None:
        target = _vulhub_target()

        result = validate_vulhub_exploit_applicability(
            target,
            observed_product="Apache HTTP Server",
            observed_version="2.4.49",
            evidence_refs=["evidence:http-server-header"],
        )

        self.assertEqual(result.status, "applicable")
        self.assertEqual(result.target_id, "vulhub-cve-2021-41773")
        self.assertEqual(result.cve_id, "CVE-2021-41773")
        self.assertEqual(result.observed_product, "Apache HTTP Server")
        self.assertEqual(result.observed_version, "2.4.49")
        self.assertEqual(result.evidence_refs, ("evidence:http-server-header",))
        self.assertEqual(result.exit_gates, ("exploit_applicability_checked_against_observed_evidence",))
        self.assertIn("affected version observed", result.reasons)
        self.assertEqual(result.as_payload()["status"], "applicable")

    def test_vulhub_applicability_marks_fixed_version_not_applicable(self) -> None:
        target = _vulhub_target()

        result = validate_vulhub_exploit_applicability(
            target,
            observed_product="Apache HTTP Server",
            observed_version="2.4.51",
            evidence_refs=["evidence:http-server-header"],
        )

        self.assertEqual(result.status, "not_applicable")
        self.assertIn("fixed version observed", result.reasons)

    def test_vulhub_applicability_marks_unknown_version_as_unknown(self) -> None:
        target = _vulhub_target()

        result = validate_vulhub_exploit_applicability(
            target,
            observed_product="Apache HTTP Server",
            observed_version="2.4.52",
            evidence_refs=["evidence:http-server-header"],
        )

        self.assertEqual(result.status, "unknown")
        self.assertIn("observed version not listed", result.reasons)

    def test_vulhub_applicability_requires_evidence_refs(self) -> None:
        target = _vulhub_target()

        with self.assertRaisesRegex(ValueError, "evidence_refs"):
            validate_vulhub_exploit_applicability(
                target,
                observed_product="Apache HTTP Server",
                observed_version="2.4.49",
                evidence_refs=[],
            )

    def test_vulhub_applicability_rejects_non_evidence_refs(self) -> None:
        target = _vulhub_target()

        with self.assertRaisesRegex(ValueError, "evidence:<id>"):
            validate_vulhub_exploit_applicability(
                target,
                observed_product="Apache HTTP Server",
                observed_version="2.4.49",
                evidence_refs=["note:http-server-header"],
            )

    def test_vulhub_applicability_rejects_hidden_material(self) -> None:
        target = _vulhub_target()

        with self.assertRaisesRegex(ValueError, "hidden flag material"):
            validate_vulhub_exploit_applicability(
                target,
                observed_product="Apache HTTP Server",
                observed_version="2.4.49",
                evidence_refs=["evidence:http-server-header"],
                observations={"banner": fixture_flag()},
            )

    def test_vulhub_applicability_requires_vulhub_target_metadata(self) -> None:
        target = load_ctf_target_manifest(
            {
                "lab_id": "juice-shop-foundation",
                "title": "OWASP Juice Shop Foundation",
                "platform": "docker",
                "category": "web",
                "difficulty": "foundation",
                "scope": {"network": "lab_js_foundation", "assets": ["http://127.0.0.1:3100"]},
                "provisioning": {"mode": "docker", "network": "lab_js_foundation"},
                "policy": {"default_intent": "recon_only"},
            }
        )

        with self.assertRaisesRegex(ValueError, "Vulhub CVE"):
            validate_vulhub_exploit_applicability(
                target,
                observed_product="Apache HTTP Server",
                observed_version="2.4.49",
                evidence_refs=["evidence:http-server-header"],
            )


def _vulhub_target():
    return load_ctf_target_manifest(
        {
            "lab_id": "vulhub-cve-2021-41773",
            "title": "Vulhub Apache CVE-2021-41773",
            "platform": "docker",
            "category": "web",
            "difficulty": "intermediate",
            "target_family": "vulhub_cve_labs",
            "scope": {
                "network": "lab_vulhub_apache_2021_41773",
                "assets": ["http://127.0.0.1:3180"],
            },
            "provisioning": {
                "mode": "docker",
                "compose_project": "vulhub_apache_2021_41773",
                "network": "lab_vulhub_apache_2021_41773",
                "published_ports": [{"host": 3180, "container": 80}],
            },
            "vulnerability": {
                "cve_id": "CVE-2021-41773",
                "product": "Apache HTTP Server",
                "affected_versions": ["2.4.49"],
                "fixed_versions": ["2.4.50", "2.4.51"],
                "observed_version_evidence_required": True,
            },
            "policy": {"default_intent": "recon_only"},
        }
    )


if __name__ == "__main__":
    unittest.main()
