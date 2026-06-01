from __future__ import annotations

from tests.test_web_console_common import *


class WebConsoleTestsPart8(WebConsoleTestsBase):
    def test_connector_api_endpoints_have_route_level_contracts(self) -> None:
        raw_request = "GET / HTTP/1.1\nHost: pirate.htb\nConnection: close\n\n"
        raw_sha256 = self.runtime.caido.parse_raw_request(raw_request).raw_sha256

        self._assert_credential_routes_redact_secrets(raw_request)
        self._assert_caido_routes(raw_request, raw_sha256)
        self._assert_bad_connector_requests(raw_request)
        self._assert_queue_processing_route()

    def _assert_credential_routes_redact_secrets(self, raw_request: str) -> None:
        del raw_request
        notion_response = self.app.dispatch(
            "POST",
            "/api/credentials/notion",
            json.dumps(
                {
                    "api_key": "secret_notion_token",
                    "parent_page_id": "parent123",
                    "version": "2022-06-28",
                }
            ).encode("utf-8"),
        )
        discord_response = self.app.dispatch(
            "POST",
            "/api/credentials/discord",
            json.dumps({"webhook_url": "https://discord.com/api/webhooks/123/token"}).encode("utf-8"),
        )
        known_response = self.app.dispatch(
            "POST",
            "/api/credentials/known",
            json.dumps({"username": "operator", "password": "known-secret", "domain": "LAB"}).encode("utf-8"),
        )
        lab_response = self.app.dispatch(
            "POST",
            "/api/credentials/lab",
            json.dumps({"username": "legacy", "password": "legacy-secret", "domain": "LEGACY"}).encode("utf-8"),
        )
        caido_response = self.app.dispatch(
            "POST",
            "/api/credentials/caido",
            json.dumps({"api_token": "caido-secret-token"}).encode("utf-8"),
        )
        credentials_response = self.app.dispatch("GET", "/api/credentials")
        credentials = json.loads(credentials_response.body)
        serialized_credentials = json.dumps(credentials)

        self.assertEqual(notion_response.status, 200)
        self.assertEqual(discord_response.status, 200)
        self.assertEqual(known_response.status, 200)
        self.assertEqual(lab_response.status, 200)
        self.assertEqual(caido_response.status, 200)
        self.assertEqual(credentials_response.status, 200)
        self.assertTrue(credentials["services"]["notion"]["api_key"]["configured"])
        self.assertTrue(credentials["services"]["discord"]["webhook_url"]["configured"])
        self.assertTrue(credentials["services"]["known"]["username"]["configured"])
        self.assertTrue(credentials["services"]["lab"]["username"]["configured"])
        self.assertTrue(credentials["services"]["caido"]["graphql_url"]["configured"])
        self.assertEqual(credentials["services"]["known"]["username"]["hint"], "legacy")
        self.assertEqual(credentials["services"]["lab"]["username"]["hint"], "legacy")
        self.assertEqual(self.runtime.credentials.get("caido", "graphql_url"), CaidoIntegrationService.DEFAULT_GRAPHQL_URL)
        for secret in [
            "secret_notion_token",
            "discord.com/api/webhooks/123/token",
            "known-secret",
            "legacy-secret",
            "caido-secret-token",
        ]:
            self.assertNotIn(secret, serialized_credentials)

    def _assert_caido_routes(self, raw_request: str, raw_sha256: str) -> None:
        with (
            patch.object(
                self.runtime.caido,
                "search_requests",
                return_value={"ok": True, "httpql": 'req.host.eq:"pirate.htb"', "requests": []},
            ) as search,
            patch.object(
                self.runtime.caido,
                "request_detail",
                return_value={"ok": True, "request": {"id": "42", "host": "pirate.htb"}},
            ) as detail,
            patch.object(
                self.runtime.caido,
                "create_replay_draft",
                return_value={
                    "ok": True,
                    "parsed": {"host": "pirate.htb", "raw_sha256": raw_sha256},
                    "session": {"id": "session-1"},
                },
            ) as draft,
            patch.object(self.runtime.caido, "send_replay", return_value={"ok": True, "task": {"id": "task-1"}}) as send,
        ):
            search_response = self.app.dispatch(
                "POST",
                "/api/integrations/caido/search",
                json.dumps({"target": "pirate.htb", "httpql": 'req.host.eq:"pirate.htb"', "limit": 25}).encode(
                    "utf-8"
                ),
            )
            detail_response = self.app.dispatch("GET", "/api/integrations/caido/requests/42")
            draft_response = self.app.dispatch(
                "POST",
                "/api/integrations/caido/replay/draft",
                json.dumps({"target": "pirate.htb", "raw_request": raw_request}).encode("utf-8"),
            )
            send_response = self.app.dispatch(
                "POST",
                "/api/integrations/caido/replay/send",
                json.dumps(
                    {
                        "target": "pirate.htb",
                        "raw_request": raw_request,
                        "session_id": "session-1",
                        "confirmation": raw_sha256,
                    }
                ).encode("utf-8"),
            )

        search_payload = json.loads(search_response.body)
        detail_payload = json.loads(detail_response.body)
        draft_payload = json.loads(draft_response.body)
        send_payload = json.loads(send_response.body)

        self.assertEqual(search_response.status, 200)
        self.assertEqual(detail_response.status, 200)
        self.assertEqual(draft_response.status, 200)
        self.assertEqual(send_response.status, 200)
        self.assertTrue(search_payload["ok"])
        self.assertTrue(detail_payload["ok"])
        self.assertTrue(draft_payload["ok"])
        self.assertTrue(send_payload["ok"])
        self.assertEqual(send_payload["action"], "caido-replay-send")
        search.assert_called_once_with('req.host.eq:"pirate.htb"', limit=25, offset=0)
        detail.assert_called_once_with("42")
        draft.assert_called_once_with(raw_request)
        send.assert_called_once_with(raw_request, session_id="session-1")

    def _assert_bad_connector_requests(self, raw_request: str) -> None:
        bad_search = self.app.dispatch(
            "POST",
            "/api/integrations/caido/search",
            json.dumps({"target": "missing.htb"}).encode("utf-8"),
        )
        bad_import = self.app.dispatch(
            "POST",
            "/api/integrations/caido/import",
            json.dumps({"target": "pirate.htb", "request_ids": "42"}).encode("utf-8"),
        )
        bad_draft = self.app.dispatch(
            "POST",
            "/api/integrations/caido/replay/draft",
            json.dumps({"raw_request": raw_request}).encode("utf-8"),
        )
        invalid_clear = self.app.dispatch("DELETE", "/api/credentials/web")

        self.assertEqual(bad_search.status, 400)
        self.assertEqual(bad_import.status, 400)
        self.assertEqual(bad_draft.status, 400)
        self.assertEqual(invalid_clear.status, 400)

    def _assert_queue_processing_route(self) -> None:
        with (
            patch.object(self.runtime.notion, "process_pending", return_value=2) as notion_pending,
            patch.object(self.runtime.discord, "deliver_pending", return_value=3) as discord_pending,
        ):
            process_response = self.app.dispatch("POST", "/api/actions/process-queues")
        process_payload = json.loads(process_response.body)

        self.assertEqual(process_response.status, 200)
        self.assertEqual(process_payload["action"], "process-queues")
        self.assertEqual(process_payload["result"], {"notion_completed": 2, "discord_delivered": 3})
        notion_pending.assert_called_once_with()
        discord_pending.assert_called_once_with()

    def test_operator_chat_uses_local_model_and_persists_messages(self) -> None:
        with patch.object(
            self.runtime.ollama,
            "generate",
            return_value=OllamaResponse(model="gemma4:e4b", text="Primordial is waiting on recon tasks."),
        ) as generate:
            response = self.app.dispatch(
                "POST",
                "/api/chat",
                json.dumps({"message": "Draft a concise operator note.", "target": "pirate.htb"}).encode("utf-8"),
            )

        payload = json.loads(response.body)
        chat_response = self.app.dispatch("GET", "/api/chat?limit=5&target=pirate.htb")
        chat = json.loads(chat_response.body)

        self.assertEqual(response.status, 200)
        self.assertTrue(payload["result"]["chat"]["ok"])
        self.assertEqual(payload["result"]["chat"]["model"], "deepseek-r1:8b")
        self.assertEqual(len(chat["messages"]), 2)
        self.assertEqual(chat["messages"][-1]["role"], "assistant")
        logs = sorted(self.runtime.config.chat_logs_dir.glob("*/*.json"))
        self.assertEqual(len(logs), 2)
        serialized_logs = "\n".join(path.read_text(encoding="utf-8") for path in logs)
        self.assertIn("Draft a concise operator note.", serialized_logs)
        self.assertIn("Primordial is waiting on recon tasks.", serialized_logs)
        generate.assert_called_once()

    def test_operator_chat_view_surfaces_wrapper_model_label(self) -> None:
        self.runtime.store.insert_operator_message(
            OperatorMessage(role="operator", body="test", target_id=None)
        )
        self.runtime.store.insert_operator_message(
            OperatorMessage(
                role="assistant",
                body="wrapper response",
                target_id=None,
                model="agent_chat_api:claude:provider-default",
            )
        )

        response = self.app.dispatch("GET", "/api/control-plane")
        payload = json.loads(response.body)
        rows = payload["inquiryChat"]

        self.assertEqual(response.status, 200)
        self.assertEqual(rows[-1]["text"], "wrapper response")
        self.assertEqual(rows[-1]["model"], "agent_chat_api:claude:provider-default")

    def test_long_operator_chat_does_not_block_fast_runtime_endpoints(self) -> None:
        started = threading.Event()
        release = threading.Event()
        responses = []

        def slow_chat(message, target=None):
            started.set()
            release.wait(timeout=2)
            return {"ok": True, "model": "fixture", "answer": {"body": f"done: {message}"}, "target": target}

        with patch.object(self.runtime, "ask_operator_ai", side_effect=slow_chat):
            thread = threading.Thread(
                target=lambda: responses.append(
                    self.app.dispatch(
                        "POST",
                        "/api/chat",
                        json.dumps({"message": "hold this request", "target": "pirate.htb"}).encode("utf-8"),
                    )
                )
            )
            thread.start()
            self.assertTrue(started.wait(timeout=1))

            started_at = time.monotonic()
            for path in ("/api/work-status", "/api/execution-mode", "/api/runtime-settings"):
                response = self.app.dispatch("GET", path)
                self.assertEqual(response.status, 200)
            elapsed = time.monotonic() - started_at

            release.set()
            thread.join(timeout=2)

        self.assertLess(elapsed, 0.5)
        self.assertEqual(responses[0].status, 200)

__all__ = ["WebConsoleTestsPart8"]
