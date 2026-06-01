from __future__ import annotations

from tests.test_caido_and_skills_common import *


class CaidoAndSkillTestsPart2(CaidoAndSkillTestsBase):
    def test_caido_search_retries_without_httpql_variable_type(self) -> None:
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
            queries = []

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
                query = body["query"]
                queries.append(query)
                if "filter: $filter" in query:
                    return FakeResponse({"errors": [{"message": 'Variable "filter" cannot be of non-input type "HTTPQL"'}]})
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
                                        "method": "GET",
                                        "path": "/",
                                        "query": "",
                                        "isTls": False,
                                        "length": 32,
                                        "createdAt": "2026-05-15T00:00:00Z",
                                        "source": "REPLAY",
                                        "response": {"id": "r1", "statusCode": 200, "length": 12, "roundtripTime": 3},
                                    }
                                ],
                            }
                        }
                    }
                )

            with patch("primordial.adapters.caido.request.urlopen", side_effect=fake_urlopen):
                search = service.search_requests('req.host.eq:"pirate.htb"')

            self.assertTrue(search["ok"])
            self.assertEqual(search["query_field"], "requestsByOffset")
            self.assertEqual(search["filter_strategy"], "inline:HTTPQLInput.code+order")
            self.assertEqual(search["requests"][0]["id"], "42")
            self.assertTrue(any('Variable "filter"' in item["error"] for item in search["diagnostics"]["attempts"]))
            self.assertFalse(any("$filter: HTTPQL," in query for query in queries))

    def test_caido_search_uses_httpql_input_code_when_supported(self) -> None:
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
            captured_payload = {}

            class FakeResponse:
                status = 200

                def __enter__(self):
                    return self

                def __exit__(self, *_args):
                    return False

                def read(self):
                    return json.dumps(
                        {
                            "data": {
                                "requestsByOffset": {
                                    "count": {"value": 1},
                                    "nodes": [
                                        {
                                            "id": "51",
                                            "host": "pirate.htb",
                                            "port": 80,
                                            "method": "GET",
                                            "path": "/login",
                                            "query": "",
                                            "isTls": False,
                                            "length": 64,
                                            "createdAt": "2026-05-15T00:00:00Z",
                                            "source": "INTERCEPT",
                                            "response": {"id": "r51", "statusCode": 302, "length": 0, "roundtripTime": 5},
                                        }
                                    ],
                                }
                            }
                        }
                    ).encode("utf-8")

            def fake_urlopen(req, timeout):
                captured_payload.update(json.loads(req.data.decode("utf-8")))
                return FakeResponse()

            with patch("primordial.adapters.caido.request.urlopen", side_effect=fake_urlopen):
                search = service.search_requests('req.path.cont:"login" OR req.path.cont:"admin"')

            self.assertTrue(search["ok"])
            self.assertEqual(search["filter_strategy"], "variable:HTTPQLInput.code+order")
            self.assertEqual(captured_payload["variables"]["filter"]["code"], 'req.path.cont:"login" OR req.path.cont:"admin"')
            self.assertEqual(search["requests"][0]["id"], "51")

    def test_caido_search_falls_back_to_httpql_input_query_shape(self) -> None:
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
            queries = []

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
                query = body["query"]
                queries.append(query)
                if "code:" in query or body.get("variables", {}).get("filter", {}).get("code"):
                    return FakeResponse({"errors": [{"message": 'Invalid value for argument "filter", field "query" is required'}]})
                return FakeResponse(
                    {
                        "data": {
                            "requestsByOffset": {
                                "count": {"value": 1},
                                "nodes": [
                                    {
                                        "id": "52",
                                        "host": "pirate.htb",
                                        "port": 80,
                                        "method": "GET",
                                        "path": "/admin",
                                        "query": "",
                                        "isTls": False,
                                        "length": 64,
                                        "createdAt": "2026-05-15T00:00:00Z",
                                        "source": "INTERCEPT",
                                        "response": {"id": "r52", "statusCode": 200, "length": 8, "roundtripTime": 5},
                                    }
                                ],
                            }
                        }
                    }
                )

            with patch("primordial.adapters.caido.request.urlopen", side_effect=fake_urlopen):
                search = service.search_requests('req.path.cont:"admin"')

            self.assertTrue(search["ok"])
            self.assertEqual(search["filter_strategy"], "variable:HTTPQLInput.query+order")
            self.assertTrue(any("HTTPQLInput.code" in query or "code:" in query for query in queries))
            self.assertEqual(search["requests"][0]["id"], "52")

    def test_caido_empty_search_omits_filter_variable(self) -> None:
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
            captured_variables = []

            class FakeResponse:
                status = 200

                def __enter__(self):
                    return self

                def __exit__(self, *_args):
                    return False

                def read(self):
                    return json.dumps({"data": {"requestsByOffset": {"count": {"value": 0}, "nodes": []}}}).encode("utf-8")

            def fake_urlopen(req, timeout):
                body = json.loads(req.data.decode("utf-8"))
                captured_variables.append(body["variables"])
                return FakeResponse()

            with patch("primordial.adapters.caido.request.urlopen", side_effect=fake_urlopen):
                search = service.search_requests("")

            self.assertTrue(search["ok"])
            self.assertEqual(search["filter_strategy"], "unfiltered+order")
            self.assertNotIn("filter", captured_variables[0])

__all__ = [name for name in globals() if name.endswith("Part2")]
