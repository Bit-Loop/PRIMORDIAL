from __future__ import annotations

from tests.test_web_console_common import *


class WebConsoleTestsPart7(WebConsoleTestsBase):
    def test_credentials_and_records_endpoints_are_practical(self) -> None:
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
        caido_response = self.app.dispatch(
            "POST",
            "/api/credentials/caido",
            json.dumps(
                {
                    "graphql_url": "http://127.0.0.1:8650/graphql",
                    "api_token": "caido-secret-token",
                }
            ).encode("utf-8"),
        )
        credentials_response = self.app.dispatch("GET", "/api/credentials")
        records_response = self.app.dispatch("GET", "/api/records?limit=5")

        self.assertEqual(notion_response.status, 200)
        self.assertEqual(discord_response.status, 200)
        self.assertEqual(caido_response.status, 200)
        self.assertEqual(credentials_response.status, 200)
        self.assertEqual(records_response.status, 200)

        credentials = json.loads(credentials_response.body)
        serialized = json.dumps(credentials)
        self.assertNotIn("secret_notion_token", serialized)
        self.assertNotIn("discord.com/api/webhooks/123/token", serialized)
        self.assertNotIn("caido-secret-token", serialized)
        self.assertTrue(credentials["services"]["notion"]["api_key"]["configured"])
        self.assertTrue(credentials["services"]["discord"]["webhook_url"]["configured"])
        self.assertTrue(credentials["services"]["caido"]["api_token"]["configured"])

        records = json.loads(records_response.body)
        self.assertIn("evidence", records)
        self.assertIn("primitives", records)

    def test_discord_credential_save_rejects_non_webhook_urls(self) -> None:
        channel_response = self.app.dispatch(
            "POST",
            "/api/credentials/discord",
            json.dumps({"webhook_url": "https://discord.com/channels/1/2"}).encode("utf-8"),
        )
        malformed_response = self.app.dispatch(
            "POST",
            "/api/credentials/discord",
            json.dumps({"webhook_url": "http://discord.com/api/webhooks/123/token"}).encode("utf-8"),
        )

        self.assertEqual(channel_response.status, 400)
        self.assertEqual(malformed_response.status, 400)
        self.assertIn("/api/webhooks", json.loads(channel_response.body)["error"])
        self.assertIn("HTTPS", json.loads(malformed_response.body)["error"])

    def test_discord_405_marks_webhook_configuration_invalid(self) -> None:
        self.runtime.set_discord_credentials(webhook_url="https://discord.com/api/webhooks/123/token")
        first = NotificationRecord(channel=NotificationChannel.DISCORD, event_type="approval_needed", summary="one")
        second = NotificationRecord(channel=NotificationChannel.DISCORD, event_type="finding_candidate", summary="two")
        self.runtime.store.insert_notification(first)
        self.runtime.store.insert_notification(second)

        def method_not_allowed(req, timeout):
            raise __import__("urllib.error").error.HTTPError(
                req.full_url,
                405,
                "Method Not Allowed",
                {},
                io.BytesIO(b"method not allowed"),
            )

        with patch("primordial.adapters.discord.request.urlopen", side_effect=method_not_allowed):
            delivered = self.runtime.discord.deliver_pending(limit=10)

        self.assertEqual(delivered, 0)
        notifications = {item.id: item for item in self.runtime.store.list_notifications(limit=10)}
        self.assertEqual(notifications[first.id].status, NotificationStatus.FAILED)
        self.assertEqual(notifications[second.id].status, NotificationStatus.FAILED)
        events = self.runtime.store.list_events(limit=10)
        self.assertTrue(any("invalid webhook configuration" in event.summary for event in events))

    def test_discord_transient_failure_keeps_notification_pending_until_retry_limit(self) -> None:
        self.runtime.set_discord_credentials(webhook_url="https://discord.com/api/webhooks/123/token")
        notification = NotificationRecord(
            channel=NotificationChannel.DISCORD,
            event_type="approval_needed",
            summary="retry me",
        )
        self.runtime.store.insert_notification(notification)

        with patch("primordial.adapters.discord.request.urlopen", side_effect=OSError("temporary network failure")):
            delivered = self.runtime.discord.deliver_pending(limit=10)

        self.assertEqual(delivered, 0)
        refreshed = {item.id: item for item in self.runtime.store.list_notifications(limit=10)}[notification.id]
        self.assertEqual(refreshed.status, NotificationStatus.PENDING)
        self.assertEqual(refreshed.metadata["delivery_attempts"], 1)
        self.assertTrue(refreshed.metadata["retryable_delivery_error"])
        deliveries = self.runtime.store.list_discord_deliveries(limit=10)
        self.assertEqual(deliveries[0].status, NotificationStatus.PENDING)

__all__ = ["WebConsoleTestsPart7"]
