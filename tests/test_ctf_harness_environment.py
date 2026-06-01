from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import unittest

from primordial.labs.ctf import (
    load_ctf_target_manifest,
    probe_local_container_environment,
    probe_vulhub_cve_environment,
    verify_local_container_environment,
)
from tests.support import fixture_flag


class CTFHarnessEnvironmentProofTests(unittest.TestCase):
    def test_local_container_environment_proof_records_phase_gate_and_evidence(self) -> None:
        target = _juice_shop_target()

        proof = verify_local_container_environment(
            target,
            observed_assets=["http://127.0.0.1:3100"],
            evidence_refs=["evidence:container-health", "evidence:reset-ready"],
            reset_evidence_ref="evidence:reset-ready",
            profile="co_internal_lab",
        )

        self.assertEqual(proof.target_id, "juice-shop-foundation")
        self.assertEqual(proof.status, "verified")
        self.assertEqual(proof.profile, "co_internal_lab")
        self.assertEqual(proof.environment_kind, "local_container")
        self.assertEqual(proof.observed_assets, ("http://127.0.0.1:3100",))
        self.assertEqual(proof.evidence_refs, ("evidence:container-health", "evidence:reset-ready"))
        self.assertEqual(proof.reset_evidence_ref, "evidence:reset-ready")
        self.assertEqual(proof.exit_gates, ("local_container_environment_verified",))
        self.assertEqual(
            proof.as_payload()["provisioning"],
            {
                "mode": "docker",
                "network": "lab_js_foundation",
                "compose_project": "js_foundation",
                "published_ports": [{"host": 3100, "container": 3000}],
            },
        )

    def test_local_container_environment_proof_requires_all_target_assets_observed(self) -> None:
        target = _juice_shop_target()

        with self.assertRaisesRegex(ValueError, "observed_assets"):
            verify_local_container_environment(
                target,
                observed_assets=["http://127.0.0.1:3999"],
                evidence_refs=["evidence:container-health", "evidence:reset-ready"],
                reset_evidence_ref="evidence:reset-ready",
                profile="co_internal_lab",
            )

    def test_local_container_environment_proof_requires_evidence_refs(self) -> None:
        target = _juice_shop_target()

        with self.assertRaisesRegex(ValueError, "evidence:<id>"):
            verify_local_container_environment(
                target,
                observed_assets=["http://127.0.0.1:3100"],
                evidence_refs=["note:container-health", "evidence:reset-ready"],
                reset_evidence_ref="evidence:reset-ready",
                profile="co_internal_lab",
            )

    def test_local_container_environment_proof_requires_reset_evidence_in_evidence_refs(self) -> None:
        target = _juice_shop_target()

        with self.assertRaisesRegex(ValueError, "reset_evidence_ref"):
            verify_local_container_environment(
                target,
                observed_assets=["http://127.0.0.1:3100"],
                evidence_refs=["evidence:container-health"],
                reset_evidence_ref="evidence:reset-ready",
                profile="co_internal_lab",
            )

    def test_local_container_environment_proof_rejects_non_container_targets(self) -> None:
        target = load_ctf_target_manifest(
            {
                "lab_id": "manual-web-lab",
                "title": "Manual Web Lab",
                "platform": "manual",
                "category": "web",
                "difficulty": "foundation",
                "scope": {"network": "manual_lab", "assets": ["http://127.0.0.1:3101"]},
                "provisioning": {"mode": "manual", "network": "manual_lab"},
                "policy": {"default_intent": "recon_only"},
            }
        )

        with self.assertRaisesRegex(ValueError, "local container"):
            verify_local_container_environment(
                target,
                observed_assets=["http://127.0.0.1:3101"],
                evidence_refs=["evidence:container-health", "evidence:reset-ready"],
                reset_evidence_ref="evidence:reset-ready",
                profile="co_internal_lab",
            )

    def test_local_container_environment_proof_rejects_hidden_material(self) -> None:
        target = _juice_shop_target()

        with self.assertRaisesRegex(ValueError, "hidden flag material"):
            verify_local_container_environment(
                target,
                observed_assets=["http://127.0.0.1:3100"],
                evidence_refs=["evidence:container-health", "evidence:reset-ready"],
                reset_evidence_ref="evidence:reset-ready",
                profile="co_internal_lab",
                observations={"banner": fixture_flag()},
            )

    def test_local_container_probe_captures_redacted_http_evidence(self) -> None:
        with _local_http_server(body=b"OWASP Juice Shop ready") as base_url:
            target = _juice_shop_target(asset=base_url)

            proof = probe_local_container_environment(
                target,
                reset_evidence_ref="evidence:reset-ready",
                profile="co_internal_lab",
            )

        self.assertEqual(proof.status, "verified")
        self.assertEqual(proof.observed_assets, (base_url,))
        self.assertEqual(proof.reset_evidence_ref, "evidence:reset-ready")
        self.assertEqual(proof.evidence_refs[-1], "evidence:reset-ready")
        self.assertTrue(proof.evidence_refs[0].startswith("evidence:local-container:"))
        observation = proof.observations["http"][0]
        self.assertEqual(observation["asset"], base_url)
        self.assertEqual(observation["status_code"], 200)
        self.assertIn("body_sha256", observation)
        self.assertNotIn("body", observation)

    def test_local_container_probe_rejects_unhealthy_http_status(self) -> None:
        with _local_http_server(status=503, body=b"not ready") as base_url:
            target = _juice_shop_target(asset=base_url)

            with self.assertRaisesRegex(ValueError, "healthy HTTP"):
                probe_local_container_environment(
                    target,
                    reset_evidence_ref="evidence:reset-ready",
                    profile="co_internal_lab",
                )

    def test_local_container_probe_rejects_non_evidence_reset_ref(self) -> None:
        with _local_http_server(body=b"OWASP Juice Shop ready") as base_url:
            target = _juice_shop_target(asset=base_url)

            with self.assertRaisesRegex(ValueError, "reset_evidence_ref"):
                probe_local_container_environment(
                    target,
                    reset_evidence_ref="note:reset-ready",
                    profile="co_internal_lab",
                )

    def test_vulhub_probe_records_environment_and_observed_version_evidence(self) -> None:
        with _local_http_server(body=b"Apache CVE lab ready", server_version="Apache/2.4.49") as base_url:
            target = _vulhub_target(asset=base_url)

            proof = probe_vulhub_cve_environment(
                target,
                reset_evidence_ref="evidence:vulhub-reset-teardown",
                profile="co_internal_lab",
            )

        self.assertEqual(proof.environment_proof.status, "verified")
        self.assertEqual(proof.applicability.status, "applicable")
        self.assertEqual(proof.observed_product, "Apache httpd")
        self.assertEqual(proof.observed_version, "2.4.49")
        self.assertIn("local_container_environment_verified", proof.exit_gates)
        self.assertIn("exploit_applicability_checked_against_observed_evidence", proof.exit_gates)
        self.assertIn("evidence:vulhub-reset-teardown", proof.evidence_refs)
        observation = proof.environment_proof.observations["http"][0]
        self.assertIn("server_banner_sha256", observation)
        self.assertNotIn("body", observation)

    def test_vulhub_probe_requires_observed_target_version_evidence(self) -> None:
        with _local_http_server(body=b"generic lab ready", server_version="BaseHTTP/0.6") as base_url:
            target = _vulhub_target(asset=base_url)

            with self.assertRaisesRegex(ValueError, "observed version"):
                probe_vulhub_cve_environment(
                    target,
                    reset_evidence_ref="evidence:vulhub-reset-teardown",
                    profile="co_internal_lab",
                )


def _juice_shop_target(*, asset: str = "http://127.0.0.1:3100"):
    return load_ctf_target_manifest(
        {
            "lab_id": "juice-shop-foundation",
            "title": "OWASP Juice Shop Foundation",
            "platform": "docker",
            "category": "web",
            "difficulty": "foundation",
            "source": {
                "repo_url": "https://github.com/juice-shop/juice-shop",
                "ctf_export_repo_url": "https://github.com/juice-shop/juice-shop-ctf",
            },
            "scope": {
                "network": "lab_js_foundation",
                "assets": [asset],
            },
            "provisioning": {
                "mode": "docker",
                "compose_project": "js_foundation",
                "network": "lab_js_foundation",
                "published_ports": [{"host": 3100, "container": 3000}],
            },
            "ctfd": {
                "challenge_id": "juice-shop-foundation",
                "hidden_until_runtime": True,
            },
            "closed_book": {
                "strip_paths": ["docs/", "solutions/", "writeups/"],
                "writeup_access_policy": "postmortem_only",
            },
            "mutation": {"enabled": True, "seed_source": "hmac"},
            "evidence": {"required": ["http_request", "http_response"]},
            "policy": {"default_intent": "recon_only"},
        }
    )


def _vulhub_target(*, asset: str = "http://127.0.0.1:3180"):
    return load_ctf_target_manifest(
        {
            "lab_id": "vulhub-cve-2021-41773",
            "title": "Vulhub Apache CVE-2021-41773",
            "platform": "docker",
            "category": "web",
            "difficulty": "intermediate",
            "target_family": "vulhub_cve_labs",
            "source": {
                "repo_url": "https://github.com/vulhub/vulhub",
                "path": "httpd/CVE-2021-41773",
            },
            "scope": {
                "network": "lab_vulhub_apache_2021_41773",
                "assets": [asset],
            },
            "provisioning": {
                "mode": "docker",
                "compose_project": "vulhub_apache_2021_41773",
                "network": "lab_vulhub_apache_2021_41773",
                "published_ports": [{"host": 3180, "container": 80}],
            },
            "vulnerability": {
                "cve_id": "CVE-2021-41773",
                "product": "Apache httpd",
                "affected_versions": ["2.4.49"],
                "fixed_versions": ["2.4.51"],
                "observed_version_evidence_required": True,
            },
            "evidence": {"required": ["http_request", "http_response", "observed_version"]},
            "policy": {"default_intent": "recon_only"},
        }
    )


class _HealthHandler(BaseHTTPRequestHandler):
    status = 200
    body = b"ready"
    server_version = "BaseHTTP/0.6"
    sys_version = ""

    def do_GET(self) -> None:
        self.send_response(self.status)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, format: str, *args: object) -> None:
        return None


class _local_http_server:
    def __init__(self, *, status: int = 200, body: bytes = b"ready", server_version: str = "BaseHTTP/0.6") -> None:
        self.status = status
        self.body = body
        self.server_version = server_version
        self.server: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None

    def __enter__(self) -> str:
        handler = type(
            "HealthHandler",
            (_HealthHandler,),
            {"status": self.status, "body": self.body, "server_version": self.server_version},
        )
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        host, port = self.server.server_address
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return f"http://{host}:{port}"

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        if self.thread is not None:
            self.thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
