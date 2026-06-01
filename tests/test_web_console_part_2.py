from __future__ import annotations

from tests.test_web_console_common import *


class WebConsoleTestsPart2(WebConsoleTestsBase):
    def test_caido_presets_are_generic_and_targets_are_runtime_scope(self) -> None:
        create_response = self.app.dispatch(
            "POST",
            "/api/targets",
            json.dumps(
                {
                    "handle": "helix.htb",
                    "display_name": "helix.htb",
                    "profile": "hack_the_box",
                    "assets": ["helix.htb", HELIX_IP],
                    "active_ip": HELIX_IP,
                    "in_scope": True,
                }
            ).encode("utf-8"),
        )
        response = self.app.dispatch("GET", "/api/control-plane")
        payload = json.loads(response.body)
        caido = payload["caido"]
        handles = {item["handle"] for item in caido["targetOptions"]}
        preset_labels = {item["label"] for item in caido["savedFilters"]}

        self.assertEqual(create_response.status, 200)
        self.assertEqual(response.status, 200)
        self.assertIn("pirate.htb", handles)
        self.assertIn("helix.htb", handles)
        self.assertIn("Error responses", preset_labels)
        self.assertIn("Auth paths", preset_labels)
        self.assertIn("Token hints", preset_labels)
        self.assertNotIn("pirate.htb scope", preset_labels)
        self.assertNotIn("helix.htb scope", preset_labels)

    def test_caido_import_creates_redacted_evidence_and_artifact(self) -> None:
        detail = {
            "ok": True,
            "request": {
                "id": "42",
                "method": "POST",
                "host": "pirate.htb",
                "port": 80,
                "path": "/login",
                "status": 200,
                "source": "INTERCEPT",
                "request_sha256": "reqhash",
                "response_sha256": "resphash",
                "request_snippet": "POST /login HTTP/1.1\nHost: pirate.htb\nAuthorization: [redacted]\n\npassword=[redacted]",
                "response_snippet": "HTTP/1.1 200 OK\nSet-Cookie: [redacted]\n\nok",
                "request_truncated": False,
                "response_truncated": False,
                "raw_bodies_stored": False,
            },
        }
        with patch.object(self.runtime.caido, "request_detail", return_value=detail):
            response = self.app.dispatch(
                "POST",
                "/api/integrations/caido/import",
                json.dumps(
                    {
                        "target": "pirate.htb",
                        "request_ids": ["42"],
                        "httpql": 'req.host.eq:"pirate.htb"',
                    }
                ).encode("utf-8"),
            )

        payload = json.loads(response.body)
        records = self.runtime.records_payload(limit=10)
        evidence = records["evidence"][0]
        artifact = records["artifacts"][0]
        artifact_body = Path(artifact["path"]).read_text(encoding="utf-8")
        serialized = json.dumps(payload) + json.dumps(records) + artifact_body

        self.assertEqual(response.status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(evidence["type"], "http_replay")
        self.assertEqual(artifact["kind"], "caido_capture")
        self.assertIn("Authorization: [redacted]", serialized)
        self.assertIn("password=[redacted]", serialized)
        self.assertNotIn("Bearer abc", serialized)
        self.assertNotIn("swordfish", serialized)
        self.assertNotIn("\"raw\":", serialized)
        self.assertFalse(evidence["metadata"]["raw_bodies_stored"])

        target = next(item for item in self.runtime.store.list_targets() if item.handle == "pirate.htb")
        assert target is not None
        self.runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=target.id,
                type=EvidenceType.HTTP_REPLAY,
                title="Recon",
                summary="Generic replay evidence that is not a Caido capture.",
                source_ref="manual://recon",
                verification_status=VerificationStatus.PARTIAL,
                metadata={"method": "http_replay", "host": "pirate.htb", "path": "Recon"},
            )
        )
        control_plane = json.loads(self.app.dispatch("GET", "/api/control-plane").body)

        self.assertEqual(control_plane["caido"]["requests"], [])
        self.assertEqual(len(control_plane["caido"]["importedCaptures"]), 1)
        self.assertEqual(control_plane["caido"]["importedCaptures"][0]["caidoRequestId"], "42")
        self.assertEqual(control_plane["caido"]["importedCaptures"][0]["path"], "/login")

    def test_caido_replay_send_gates_confirmation_scope_and_batches(self) -> None:
        valid_raw = "GET / HTTP/1.1\nHost: pirate.htb\nConnection: close\n\n"
        out_of_scope_raw = "GET / HTTP/1.1\nHost: evil.example\nConnection: close\n\n"
        batch_raw = (
            "GET /one HTTP/1.1\nHost: pirate.htb\nConnection: close\n\n"
            "GET /two HTTP/1.1\nHost: pirate.htb\nConnection: close\n\n"
        )

        missing = self.app.dispatch(
            "POST",
            "/api/integrations/caido/replay/send",
            json.dumps({"target": "pirate.htb", "raw_request": valid_raw, "session_id": "1"}).encode("utf-8"),
        )
        out_of_scope = self.app.dispatch(
            "POST",
            "/api/integrations/caido/replay/send",
            json.dumps(
                {
                    "target": "pirate.htb",
                    "raw_request": out_of_scope_raw,
                    "session_id": "1",
                    "confirmation": hashlib.sha256(out_of_scope_raw.strip("\n").encode("utf-8")).hexdigest(),
                }
            ).encode("utf-8"),
        )
        malformed = self.app.dispatch(
            "POST",
            "/api/integrations/caido/replay/send",
            json.dumps({"target": "pirate.htb", "raw_request": "not an http request", "confirmation": "x"}).encode("utf-8"),
        )
        batch = self.app.dispatch(
            "POST",
            "/api/integrations/caido/replay/send",
            json.dumps(
                {
                    "target": "pirate.htb",
                    "raw_request": batch_raw,
                    "session_id": "1",
                    "confirmation": hashlib.sha256(batch_raw.strip("\n").encode("utf-8")).hexdigest(),
                }
            ).encode("utf-8"),
        )

        parsed = self.runtime.caido.parse_raw_request(valid_raw)
        with patch.object(
            self.runtime.caido,
            "send_replay",
            return_value={
                "ok": True,
                "parsed": parsed.as_payload(),
                "task": {"id": "8", "replay_entry_id": "2"},
            },
        ) as send_replay:
            sent = self.app.dispatch(
                "POST",
                "/api/integrations/caido/replay/send",
                json.dumps(
                    {
                        "target": "pirate.htb",
                        "raw_request": valid_raw,
                        "session_id": "1",
                        "confirmation": parsed.raw_sha256,
                    }
                ).encode("utf-8"),
            )

        self.assertEqual(missing.status, 400)
        self.assertIn("confirmation", json.loads(missing.body)["error"])
        self.assertEqual(out_of_scope.status, 400)
        self.assertIn("not in target scope", json.loads(out_of_scope.body)["error"])
        self.assertEqual(malformed.status, 400)
        self.assertIn("request line", json.loads(malformed.body)["error"])
        self.assertEqual(batch.status, 400)
        self.assertIn("one HTTP request", json.loads(batch.body)["error"])
        self.assertEqual(sent.status, 200)
        send_replay.assert_called_once()
        audit = self.runtime.audit_payload(limit=5)
        self.assertEqual(audit["recent_events"][0]["type"], "caido_replay_sent")
        self.assertEqual(audit["recent_events"][0]["metadata"]["raw_sha256"], parsed.raw_sha256)
        self.assertFalse(audit["recent_events"][0]["metadata"]["raw_persisted"])

    def test_target_guidance_can_be_updated_from_web_console(self) -> None:
        update_response = self.app.dispatch(
            "POST",
            "/api/findings-context/guidance",
            json.dumps(
                {
                    "target": "pirate.htb",
                    "guidance": "# Pirate Guidance\n\n- Prefer careful AD enumeration.\n",
                }
            ).encode("utf-8"),
        )
        read_response = self.app.dispatch("GET", "/api/findings-context?target=pirate.htb&include_guidance=1")

        update = json.loads(update_response.body)
        read = json.loads(read_response.body)

        self.assertEqual(update_response.status, 200)
        self.assertTrue(update["ok"])
        self.assertEqual(update["action"], "update-target-guidance")
        self.assertIn("Prefer careful AD enumeration", read["workspace"]["guidance"])

    def test_tick_action_and_task_detail_work(self) -> None:
        tick_response = self.app.dispatch(
            "POST",
            "/api/actions/tick",
            json.dumps({"max_executions": 1}).encode("utf-8"),
        )
        tick_payload = json.loads(tick_response.body)

        self.assertEqual(tick_response.status, 200)
        self.assertTrue(tick_payload["ok"])
        self.assertIn("work_status", tick_payload)
        self.assertNotIn("dashboard", tick_payload)
        self.assertNotIn("control_plane", tick_payload)

        task_id = self.runtime.store.list_tasks(limit=1)[0].id
        detail_response = self.app.dispatch("GET", f"/api/tasks/{task_id}")
        detail_payload = json.loads(detail_response.body)

        self.assertEqual(detail_response.status, 200)
        self.assertEqual(detail_payload["task"]["id"], task_id)
        self.assertIn("runs", detail_payload)
        self.assertIn("checkpoints", detail_payload)

    def test_static_index_and_health_are_available(self) -> None:
        index_response = self.app.dispatch("GET", "/")
        health_response = self.app.dispatch("GET", "/api/health")

        self.assertEqual(index_response.status, 200)
        self.assertIn(b"Primordial Control Plane", index_response.body)

        health = json.loads(health_response.body)
        self.assertEqual(health_response.status, 200)
        self.assertEqual(health["status"], "ok")

__all__ = ["WebConsoleTestsPart2"]
