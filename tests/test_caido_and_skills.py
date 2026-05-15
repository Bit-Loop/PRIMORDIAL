from __future__ import annotations

import base64
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from primordial.adapters.caido import CaidoIntegrationService
from primordial.config import AppConfig
from primordial.core.credentials import CredentialStore
from primordial.core.domain.enums import ScopeProfile
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
                    "graphql_url": CaidoIntegrationService.DEFAULT_GRAPHQL_URL,
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
            self.assertEqual(captured["url"], CaidoIntegrationService.DEFAULT_GRAPHQL_URL)
            self.assertEqual(captured["headers"]["Authorization"], "Bearer secret-token")

    def test_caido_legacy_default_url_is_normalized_to_8650(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            legacy_url = "http://127.0.0.1:8080/graphql"
            store = CredentialStore(Path(temp_dir) / "secrets" / "credentials.json")
            store.initialize()
            store.update_service(
                "caido",
                {
                    "graphql_url": legacy_url,
                    "api_token": "secret-token",
                },
            )
            service = CaidoIntegrationService(store)

            status = service.status()

            self.assertEqual(status["graphql_url"], CaidoIntegrationService.DEFAULT_GRAPHQL_URL)
            self.assertEqual(status["graphql_url_migrated_from"], legacy_url)

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
                return FakeResponse()

            with patch("primordial.adapters.caido.request.urlopen", side_effect=fake_urlopen):
                health = service.health()

            self.assertTrue(health["ok"])
            self.assertEqual(captured["url"], CaidoIntegrationService.DEFAULT_GRAPHQL_URL)

    def test_caido_search_and_detail_are_normalized_and_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = CredentialStore(Path(temp_dir) / "secrets" / "credentials.json")
            store.initialize()
            store.update_service(
                "caido",
                {
                    "graphql_url": "http://127.0.0.1:8650/graphql",
                    "api_token": "secret-token",
                },
            )
            service = CaidoIntegrationService(store)

            request_raw = base64.b64encode(
                b"POST /login HTTP/1.1\r\nHost: pirate.htb\r\nAuthorization: Bearer abc\r\n\r\npassword=swordfish"
            ).decode("ascii")
            response_raw = base64.b64encode(
                b"HTTP/1.1 200 OK\r\nSet-Cookie: session=abc\r\n\r\nsecret=hidden"
            ).decode("ascii")

            class FakeResponse:
                status = 200

                def __init__(self, payload):
                    self.payload = payload

                def __enter__(self):
                    return self

                def __exit__(self, *_args):
                    return False

                def read(self):
                    return json.dumps(self.payload).encode("utf-8")

            def fake_urlopen(req, timeout):
                body = json.loads(req.data.decode("utf-8"))
                if "requestsByOffset" in body["query"]:
                    return FakeResponse(
                        {
                            "data": {
                                "requestsByOffset": {
                                    "count": {"value": 1},
                                    "nodes": [
                                        {
                                            "id": "42",
                                            "host": "pirate.htb",
                                            "port": 80,
                                            "method": "POST",
                                            "path": "/login",
                                            "query": "",
                                            "isTls": False,
                                            "length": 128,
                                            "createdAt": "2026-05-07T00:00:00Z",
                                            "source": "INTERCEPT",
                                            "metadata": {"id": "m1", "color": None},
                                            "response": {"id": "r1", "statusCode": 200, "length": 64, "roundtripTime": 12},
                                        }
                                    ],
                                }
                            }
                        }
                    )
                return FakeResponse(
                    {
                        "data": {
                            "request": {
                                "id": "42",
                                "host": "pirate.htb",
                                "port": 80,
                                "method": "POST",
                                "path": "/login",
                                "query": "",
                                "isTls": False,
                                "length": 128,
                                "createdAt": "2026-05-07T00:00:00Z",
                                "source": "INTERCEPT",
                                "metadata": {"id": "m1", "color": None},
                                "raw": request_raw,
                                "response": {
                                    "id": "r1",
                                    "statusCode": 200,
                                    "length": 64,
                                    "roundtripTime": 12,
                                    "raw": response_raw,
                                },
                            }
                        }
                    }
                )

            with patch("primordial.adapters.caido.request.urlopen", side_effect=fake_urlopen):
                search = service.search_requests('req.host.eq:"pirate.htb"')
                detail = service.request_detail("42")

            self.assertTrue(search["ok"])
            self.assertEqual(search["requests"][0]["id"], "42")
            self.assertEqual(search["requests"][0]["status"], 200)
            self.assertTrue(detail["ok"])
            serialized_detail = json.dumps(detail)
            self.assertIn("Authorization: [redacted]", serialized_detail)
            self.assertIn("password=[redacted]", serialized_detail)
            self.assertIn("Set-Cookie: [redacted]", serialized_detail)
            self.assertNotIn("swordfish", serialized_detail)
            self.assertNotIn("session=abc", serialized_detail)

    def test_caido_url_validation_and_error_redaction(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = CredentialStore(Path(temp_dir) / "secrets" / "credentials.json")
            store.initialize()
            store.update_service(
                "caido",
                {
                    "graphql_url": "https://public.example/graphql",
                    "api_token": "secret-token",
                },
            )
            service = CaidoIntegrationService(store)
            self.assertIn("Refusing non-local", service.health()["error"])

            store.update_service("caido", {"graphql_url": "http://127.0.0.1:8650/graphql", "api_token": "secret-token"})

            err = __import__("urllib.error").error.HTTPError(
                "http://127.0.0.1:8650/graphql",
                401,
                "Unauthorized",
                {},
                None,
            )
            err.fp = io.BytesIO(b"bad secret-token")
            with patch("primordial.adapters.caido.request.urlopen", side_effect=err):
                result = service.graphql("query { __typename }")

            self.assertFalse(result["ok"])
            self.assertTrue(result["auth_error"])
            self.assertNotIn("secret-token", json.dumps(result))

    def test_caido_status_marks_unauthorized_as_auth_failed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = CredentialStore(Path(temp_dir) / "secrets" / "credentials.json")
            store.initialize()
            store.update_service(
                "caido",
                {
                    "graphql_url": CaidoIntegrationService.DEFAULT_GRAPHQL_URL,
                    "api_token": "secret-token",
                },
            )
            service = CaidoIntegrationService(store)
            calls = []

            def unauthorized(*_args, **_kwargs):
                calls.append("call")
                err = __import__("urllib.error").error.HTTPError(
                    CaidoIntegrationService.DEFAULT_GRAPHQL_URL,
                    401,
                    "Unauthorized",
                    {},
                    None,
                )
                err.fp = io.BytesIO(b'{"error":"Unauthorized","token":"secret-token"}')
                raise err

            with patch("primordial.adapters.caido.request.urlopen", side_effect=unauthorized):
                status = service.status(check_health=True)

            serialized = json.dumps(status)
            self.assertFalse(status["ok"])
            self.assertTrue(status["auth_error"])
            self.assertEqual(status["status_code"], 401)
            self.assertFalse(status["schema"]["ok"])
            self.assertEqual(len(calls), 1)
            self.assertIn("Unauthorized", serialized)
            self.assertNotIn("secret-token", serialized)

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

    def test_caido_import_adds_active_generation_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.ensure_directories()
            runtime = PrimordialRuntime(config)
            runtime.initialize()
            target = runtime.register_target(
                handle="pirate.htb",
                profile=ScopeProfile.HACK_THE_BOX,
                assets=["pirate.htb"],
                metadata={"active_ip": "10.129.244.95", "active_ip_generation": 3},
                emit_event=False,
            )

            class FakeCaido:
                def request_detail(self, request_id: str) -> dict[str, object]:
                    return {
                        "ok": True,
                        "request": {
                            "id": request_id,
                            "host": "pirate.htb",
                            "method": "GET",
                            "path": "/",
                            "status": 200,
                            "request_sha256": "req",
                            "response_sha256": "resp",
                        },
                    }

            runtime.modules._modules["caido"].instance = FakeCaido()

            result = runtime.caido_import_requests(target=target.handle, request_ids=["42"])
            evidence = runtime.store.list_evidence(target_id=target.id, limit=10)[0]

            self.assertEqual(len(result["imported"]), 1)
            self.assertEqual(evidence.metadata["active_ip"], "10.129.244.95")
            self.assertEqual(evidence.metadata["active_ip_generation"], 3)
            runtime.shutdown()


if __name__ == "__main__":
    unittest.main()
