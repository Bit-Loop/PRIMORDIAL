from __future__ import annotations

from tests.test_caido_and_skills_common import *


class CaidoAndSkillTestsPart1(CaidoAndSkillTestsBase):
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

            fake_urlopen = self._caido_fake_urlopen(request_raw, response_raw)

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

    def _caido_fake_urlopen(self, request_raw: str, response_raw: str):
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
                return FakeResponse(self._caido_search_payload())
            return FakeResponse(self._caido_detail_payload(request_raw, response_raw))

        return fake_urlopen

    def _caido_search_payload(self) -> dict[str, object]:
        node = {
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
        return {"data": {"requestsByOffset": {"count": {"value": 1}, "nodes": [node]}}}

    def _caido_detail_payload(self, request_raw: str, response_raw: str) -> dict[str, object]:
        return {
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

__all__ = [name for name in globals() if name.endswith("Part1")]
