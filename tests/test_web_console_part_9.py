from __future__ import annotations

from tests.test_web_console_common import *


class WebConsoleTestsPart9(WebConsoleTestsBase):
    def test_full_control_plane_render_does_not_block_lightweight_endpoints(self) -> None:
        started = threading.Event()
        release = threading.Event()
        responses = []

        def slow_control_plane(**kwargs):
            started.set()
            release.wait(timeout=2)
            return {"mode": "real", "runtime": {}}

        with patch.object(self.app, "_control_plane_payload", side_effect=slow_control_plane):
            thread = threading.Thread(
                target=lambda: responses.append(self.app.dispatch("GET", "/api/control-plane"))
            )
            thread.start()
            self.assertTrue(started.wait(timeout=1))

            started_at = time.monotonic()
            for path in (
                "/api/work-status",
                "/api/execution-mode",
                "/api/runtime-settings",
                "/api/operator-intent",
                "/api/credentials",
                "/api/integrations/caido?check_health=1",
            ):
                response = self.app.dispatch("GET", path)
                self.assertEqual(response.status, 200)
            elapsed = time.monotonic() - started_at

            release.set()
            thread.join(timeout=2)

        self.assertLess(elapsed, 0.5)
        self.assertEqual(responses[0].status, 200)

    def test_continuous_tick_does_not_block_population_endpoints(self) -> None:
        started = threading.Event()
        release = threading.Event()

        class _Report:
            summary = "slow tick"
            completed_runs = []

        def slow_tick(max_executions: int = 1):
            started.set()
            release.wait(timeout=2)
            return _Report()

        self.runtime.update_execution_mode("continuous", interval_seconds=7)
        with patch.object(self.runtime, "run_tick", side_effect=slow_tick):
            thread = threading.Thread(target=self.app.continuous_tick_once)
            thread.start()
            self.assertTrue(started.wait(timeout=1))

            started_at = time.monotonic()
            for path in ("/api/control-plane", "/api/scope", "/api/models", "/api/storage-status"):
                response = self.app.dispatch("GET", path)
                self.assertEqual(response.status, 200)
            elapsed = time.monotonic() - started_at

            skipped = self.app.continuous_tick_once()
            release.set()
            thread.join(timeout=2)

        self.assertLess(elapsed, 0.5)
        self.assertFalse(skipped["ran"])
        self.assertTrue(skipped["busy"])

    def test_aborted_browser_response_writes_are_ignored(self) -> None:
        handler = object.__new__(_WebConsoleRequestHandler)
        response = WebResponse(
            status=200,
            body=b"{}",
            content_type="application/json; charset=utf-8",
            headers={"Cache-Control": "no-store"},
        )
        calls = []

        def broken_send_response(status):
            calls.append(status)
            raise BrokenPipeError("browser went away")

        handler.send_response = broken_send_response
        handler.send_header = lambda *args: None
        handler.end_headers = lambda: None
        handler.wfile = io.BytesIO()

        handler._write_response(response)
        self.assertEqual(calls, [200])

    def test_operator_status_chat_uses_deterministic_state_guard(self) -> None:
        with patch.object(
            self.runtime.ollama,
            "generate",
            return_value=OllamaResponse(
                model="deepseek-r1:8b",
                text="- No flag evidence exists yet.\n- Run bounded TCP service discovery next.",
            ),
        ) as generate:
            response = self.app.dispatch(
                "POST",
                "/api/chat",
                json.dumps({"message": "current status and flags", "target": "pirate.htb"}).encode("utf-8"),
            )

        payload = json.loads(response.body)
        answer = payload["result"]["chat"]["answer"]["body"]

        self.assertEqual(response.status, 200)
        self.assertEqual(payload["result"]["chat"]["model"], "deepseek-r1:8b")
        self.assertEqual(payload["result"]["chat"]["route_model"], "deepseek-r1:8b")
        self.assertIn("**Facts**", answer)
        self.assertIn("**AI Review**", answer)
        self.assertIn("No stored evidence contains", answer)
        generate.assert_called_once()

    def test_operator_ip_question_and_correction_update_target_state(self) -> None:
        target = self.runtime.store.get_target_by_handle("pirate.htb")
        self.assertIsNotNone(target)
        assert target is not None
        self.runtime.register_target(
            handle="pirate.htb",
            profile=ScopeProfile.HACK_THE_BOX,
            assets=[{"asset": PIRATE_IP, "asset_type": "ip"}],
            emit_event=False,
        )
        self.runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=target.id,
                type=EvidenceType.TOOL_OUTPUT,
                title="TCP service discovery",
                summary="Observed services on " + PIRATE_IP + ".",
                source_ref="fixture://old-service",
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.8,
                freshness=0.9,
                metadata={
                    "kind": "tcp_service_discovery",
                    "open_services": [{"host": PIRATE_IP, "port": 445, "service": "smb"}],
                },
            )
        )

        with patch.object(self.runtime.ollama, "generate") as generate:
            question_response = self.app.dispatch(
                "POST",
                "/api/chat",
                json.dumps({"message": "What IP are you using for the target?", "target": "pirate.htb"}).encode("utf-8"),
            )
            update_response = self.app.dispatch(
                "POST",
                "/api/chat",
                json.dumps({"message": "You should be using " + UPDATED_IP, "target": "pirate.htb"}).encode("utf-8"),
            )
            followup_response = self.app.dispatch(
                "POST",
                "/api/chat",
                json.dumps({"message": "What IP are you using for the target?", "target": "pirate.htb"}).encode("utf-8"),
            )

        question_answer = json.loads(question_response.body)["result"]["chat"]["answer"]["body"]
        update_answer = json.loads(update_response.body)["result"]["chat"]["answer"]["body"]
        followup_answer = json.loads(followup_response.body)["result"]["chat"]["answer"]["body"]
        refreshed = self.runtime.store.get_target_by_handle("pirate.htb")
        self.assertIsNotNone(refreshed)
        assert refreshed is not None
        ip_assets = [asset.asset for asset in self.runtime.store.list_scope_assets(refreshed.id) if asset.asset_type == "ip"]

        self.assertIn(PIRATE_IP, question_answer)
        self.assertIn("Target IP Updated", update_answer)
        self.assertEqual(refreshed.metadata["active_ip"], UPDATED_IP)
        self.assertIn(UPDATED_IP, ip_assets)
        self.assertIn(UPDATED_IP, followup_answer)
        self.assertIn("historical", followup_answer.lower())
        generate.assert_not_called()

    def test_operator_summary_uses_deterministic_renderer(self) -> None:
        target = self.runtime.register_target(
            handle="example.test",
            profile=ScopeProfile.HACKERONE,
            assets=["example.test"],
            emit_event=False,
        )
        self.runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=target.id,
                type=EvidenceType.TOOL_OUTPUT,
                title="Recon: http://example.test/",
                summary="HTTP probe returned 200 for http://example.test/.",
                source_ref="fixture://example-summary",
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.85,
                freshness=0.9,
                metadata={"kind": "recon_scan", "effective_url": "http://example.test/", "status_code": 200},
            )
        )
        with patch.object(self.runtime.ollama, "generate") as generate:
            response = self.app.dispatch(
                "POST",
                "/api/chat",
                json.dumps({"message": "summarize example.test"}).encode("utf-8"),
            )

        payload = json.loads(response.body)

        self.assertEqual(response.status, 200)
        self.assertEqual(payload["result"]["chat"]["model"], "deterministic-state")
        self.assertIn("**Facts**", payload["result"]["chat"]["answer"]["body"])
        generate.assert_not_called()

__all__ = ["WebConsoleTestsPart9"]
