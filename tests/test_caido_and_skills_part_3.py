from __future__ import annotations

from tests.test_caido_and_skills_common import *


class CaidoAndSkillTestsPart3(CaidoAndSkillTestsBase):
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

    def test_caido_health_checks_traffic_authorization_not_only_schema(self) -> None:
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
                if "__typename" in body["query"]:
                    return FakeResponse({"data": {"__typename": "QueryRoot"}})
                return FakeResponse(
                    {
                        "data": None,
                        "errors": [
                            {
                                "message": "Operation error",
                                "extensions": {"CAIDO": {"reason": "INVALID_TOKEN", "code": "AUTHORIZATION"}},
                            }
                        ],
                    }
                )

            with patch("primordial.adapters.caido.request.urlopen", side_effect=fake_urlopen):
                health = service.health()

            self.assertFalse(health["ok"])
            self.assertTrue(health["auth_error"])
            self.assertFalse(health["traffic_access_ok"])
            self.assertIn("authorization", health["error"])
            self.assertIn("INVALID_TOKEN", health["error"])

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

    def test_yaml_skills_are_loaded_into_runtime_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            skill_dir = root / "skills" / "caido-httpql"
            skill_dir.mkdir(parents=True)
            (skill_dir / "skill.yaml").write_text(
                "id: caido-httpql\n"
                "title: Caido HTTPQL Traffic Review\n"
                "summary: Use Caido HTTPQL for scoped traffic review.\n"
                "tags:\n"
                "  - caido\n"
                "  - httpql\n"
                "body: |\n"
                "  Prefer host-scoped HTTPQL filters before broader body searches.\n",
                encoding="utf-8",
            )
            config = AppConfig.from_env(project_root=root)
            config.ensure_directories()
            runtime = PrimordialRuntime(config)
            runtime.initialize()

            payload = runtime.skills_payload(include_body=True)

            self.assertEqual(payload["skills"][0]["id"], "caido-httpql")
            self.assertEqual(payload["skills"][0]["title"], "Caido HTTPQL Traffic Review")
            self.assertIn("Caido HTTPQL", payload["skills"][0]["summary"])
            self.assertIn("host-scoped HTTPQL", payload["skills"][0]["body"])
            self.assertEqual(payload["skills"][0]["tags"], ["caido", "httpql"])
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
                metadata={"active_ip": ACTIVE_IP, "active_ip_generation": 3},
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
            self.assertEqual(evidence.metadata["active_ip"], ACTIVE_IP)
            self.assertEqual(evidence.metadata["active_ip_generation"], 3)
            runtime.shutdown()

__all__ = [name for name in globals() if name.endswith("Part3")]
