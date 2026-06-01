from __future__ import annotations

from tests.test_web_console_common import *


class WebConsoleTestsPart6(WebConsoleTestsBase):
    def test_target_registration_endpoint_updates_scope(self) -> None:
        response = self.app.dispatch(
            "POST",
            "/api/targets",
            json.dumps(
                {
                    "handle": "pirate.htb",
                    "display_name": "Pirate HTB",
                    "profile": "hack_the_box",
                    "assets": ["pirate.htb", PIRATE_IP],
                    "active_ip": PIRATE_IP,
                    "in_scope": True,
                    "metadata": {"target_kind": "htb_lab"},
                }
            ).encode("utf-8"),
        )
        payload = json.loads(response.body)

        self.assertEqual(response.status, 200)
        self.assertEqual(payload["result"]["target"]["handle"], "pirate.htb")
        self.assertEqual(payload["result"]["target"]["metadata"]["active_ip"], PIRATE_IP)
        self.assertEqual(payload["result"]["target"]["metadata"]["target_kind"], "htb_lab")
        self.assertIn("scope", payload)
        self.assertIn("scopePayload", payload)
        self.assertIn("scopeProfiles", payload)
        self.assertNotIn("control_plane", payload)
        scope = json.loads(self.app.dispatch("GET", "/api/scope").body)
        self.assertTrue(any(item["target"]["handle"] == "pirate.htb" for item in scope["targets"]))

    def test_target_registration_auto_adds_active_ip_asset(self) -> None:
        response = self.app.dispatch(
            "POST",
            "/api/targets",
            json.dumps(
                {
                    "handle": "helix.htb",
                    "display_name": "helix.htb",
                    "profile": "hack_the_box",
                    "assets": ["helix.htb"],
                    "active_ip": HELIX_IP,
                    "in_scope": True,
                }
            ).encode("utf-8"),
        )
        payload = json.loads(response.body)
        target = self.runtime.store.get_target_by_handle("helix.htb", ScopeProfile.HACK_THE_BOX)

        self.assertEqual(response.status, 200)
        self.assertEqual(payload["result"]["target"]["handle"], "helix.htb")
        self.assertEqual(payload["result"]["target"]["metadata"]["active_ip"], HELIX_IP)
        self.assertIsNotNone(target)
        assert target is not None
        assets = {item.asset for item in self.runtime.store.list_scope_assets(target.id)}
        self.assertIn("helix.htb", assets)
        self.assertIn(HELIX_IP, assets)

    def test_target_registration_can_replace_scope_assets_when_active_ip_changes(self) -> None:
        first = self.app.dispatch(
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
                    "replace_scope_assets": True,
                }
            ).encode("utf-8"),
        )
        second = self.app.dispatch(
            "POST",
            "/api/targets",
            json.dumps(
                {
                    "handle": "helix.htb",
                    "display_name": "helix.htb",
                    "profile": "hack_the_box",
                    "assets": ["helix.htb"],
                    "active_ip": REPLACEMENT_IP,
                    "in_scope": True,
                    "replace_scope_assets": True,
                }
            ).encode("utf-8"),
        )
        target = self.runtime.store.get_target_by_handle("helix.htb", ScopeProfile.HACK_THE_BOX)

        self.assertEqual(first.status, 200)
        self.assertEqual(second.status, 200)
        self.assertIsNotNone(target)
        assert target is not None
        assets = {item.asset for item in self.runtime.store.list_scope_assets(target.id)}
        self.assertEqual(assets, {"helix.htb", REPLACEMENT_IP})
        self.assertEqual(target.metadata["active_ip"], REPLACEMENT_IP)
        self.assertEqual(target.metadata["active_ip_generation"], 2)
        notes = self.runtime.store.list_notes(target_id=target.id, limit=10)
        self.assertTrue(any(note.metadata.get("previous_ip") == HELIX_IP for note in notes))

    def test_target_registration_rejects_invalid_active_ip(self) -> None:
        response = self.app.dispatch(
            "POST",
            "/api/targets",
            json.dumps(
                {
                    "handle": "pirate.htb",
                    "profile": "hack_the_box",
                    "assets": ["pirate.htb"],
                    "active_ip": "not-an-ip",
                }
            ).encode("utf-8"),
        )
        payload = json.loads(response.body)

        self.assertEqual(response.status, 400)
        self.assertIn("invalid IP address", payload["error"])

    def test_scope_profile_presets_can_be_managed_and_resolved(self) -> None:
        saved = self.runtime.upsert_scope_profile(
            profile_id="htb_windows_ad",
            label="HTB Windows AD",
            base_profile="hack_the_box",
            description="Windows AD lab preset.",
        )

        ids = {item["id"] for item in saved["profiles"]}
        self.assertIn("hack_the_box", ids)
        self.assertIn("hackerone", ids)
        self.assertIn("htb_windows_ad", ids)
        self.assertEqual(saved["saved"], "htb_windows_ad")
        self.assertEqual(self.runtime.resolve_scope_profile("htb_windows_ad"), ScopeProfile.HACK_THE_BOX)

        imported = self.runtime.import_scope_payload(
            {
                "profile": "htb_windows_ad",
                "targets": [{"handle": "custom.htb", "assets": ["custom.htb"]}],
            },
            source_name="custom-profile-test",
        )
        self.assertEqual(imported["profile"], ScopeProfile.HACK_THE_BOX.value)

        response = self.app.dispatch(
            "POST",
            "/api/targets",
            json.dumps(
                {
                    "handle": "preset.htb",
                    "profile": "htb_windows_ad",
                    "assets": ["preset.htb"],
                    "in_scope": True,
                }
            ).encode("utf-8"),
        )
        payload = json.loads(response.body)
        self.assertEqual(response.status, 200)
        self.assertEqual(payload["result"]["target"]["profile"], ScopeProfile.HACK_THE_BOX.value)

        deleted = self.runtime.delete_scope_profile("htb_windows_ad")
        self.assertTrue(deleted["removed"])
        self.assertNotIn("htb_windows_ad", {item["id"] for item in deleted["profiles"]})
        with self.assertRaises(ValueError):
            self.runtime.delete_scope_profile("hack_the_box")

    def test_scope_import_endpoint_adds_multiple_targets(self) -> None:
        response = self.app.dispatch(
            "POST",
            "/api/scope/import",
            json.dumps(
                {
                    "profile": "hack_the_box",
                    "source": "web-test.json",
                    "scope": {
                        "targets": [
                            {"handle": "alpha.htb", "assets": ["alpha.htb", ALPHA_IP]},
                            {"handle": "beta.htb", "assets": [{"asset": "https://beta.htb", "asset_type": "webapp"}]},
                        ]
                    },
                }
            ).encode("utf-8"),
        )
        payload = json.loads(response.body)

        self.assertEqual(response.status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["action"], "import-scope")
        self.assertEqual(payload["result"]["targets_imported"], 2)
        self.assertEqual(payload["result"]["assets_imported"], 3)
        scope = json.loads(self.app.dispatch("GET", "/api/scope").body)
        handles = {item["target"]["handle"] for item in scope["targets"]}
        self.assertIn("alpha.htb", handles)
        self.assertIn("beta.htb", handles)

    def test_target_removal_endpoint_updates_scope(self) -> None:
        response = self.app.dispatch("DELETE", "/api/targets/pirate.htb?profile=hack_the_box")
        payload = json.loads(response.body)

        self.assertEqual(response.status, 200)
        self.assertTrue(payload["result"]["removed"])
        scope = json.loads(self.app.dispatch("GET", "/api/scope").body)
        self.assertEqual(scope["targets"], [])

    def test_target_removal_blocks_linked_runtime_records(self) -> None:
        target = self.runtime.store.get_target_by_handle("pirate.htb", ScopeProfile.HACK_THE_BOX)
        self.assertIsNotNone(target)
        self.runtime.store.insert_evidence(
            EvidenceRecord(
                id="evidence_delete_guard",
                target_id=target.id,
                type=EvidenceType.SCANNER_OUTPUT,
                title="Preserved runtime evidence",
                summary="Runtime evidence must not be deleted by target cleanup.",
                source_ref="test",
                verification_status=VerificationStatus.PARTIAL,
            )
        )

        response = self.app.dispatch("DELETE", "/api/targets/pirate.htb?profile=hack_the_box")
        payload = json.loads(response.body)

        self.assertEqual(response.status, 409)
        self.assertFalse(payload["ok"])
        self.assertTrue(payload["result"]["blocked"])
        self.assertEqual(payload["result"]["runtime_record_counts"]["evidence"], 1)
        self.assertIsNotNone(self.runtime.store.get_target_by_handle("pirate.htb", ScopeProfile.HACK_THE_BOX))
        self.assertTrue(self.runtime.store.target_has_evidence(target.id))

    def test_database_trigger_blocks_direct_runtime_deletes(self) -> None:
        target = self.runtime.store.get_target_by_handle("pirate.htb", ScopeProfile.HACK_THE_BOX)
        self.assertIsNotNone(target)

        with self.assertRaises(Exception):
            with self.runtime.store.connect() as connection:
                connection.execute("DELETE FROM targets WHERE id = %s", (target.id,))
                connection.commit()

        self.assertIsNotNone(self.runtime.store.get_target_by_handle("pirate.htb", ScopeProfile.HACK_THE_BOX))

__all__ = ["WebConsoleTestsPart6"]
