from __future__ import annotations

import json
from urllib import error, request
from urllib.parse import urlsplit

from primordial.core.credentials import CredentialStore
from primordial.core.events.bus import EventBus, RuntimeSignal
from primordial.core.domain.enums import EventType, NotificationStatus
from primordial.core.domain.models import DiscordDelivery, EventRecord
from primordial.core.sensitive_text import redact_sensitive_text
from primordial.core.storage.runtime import RuntimeStore


class DiscordWebhookConfigurationError(ValueError):
    pass


def validate_discord_webhook_url(webhook_url: str) -> str:
    value = str(webhook_url or "").strip()
    if not value:
        return ""
    parsed = urlsplit(value)
    host = parsed.netloc.lower()
    if parsed.scheme != "https":
        raise DiscordWebhookConfigurationError("Discord webhook URL must use HTTPS")
    allowed_hosts = {"discord.com", "discordapp.com", "canary.discord.com", "ptb.discord.com"}
    if host not in allowed_hosts:
        raise DiscordWebhookConfigurationError("Discord webhook URL must use a Discord domain")
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 4 or parts[0] != "api" or parts[1] != "webhooks" or not parts[2] or not parts[3]:
        raise DiscordWebhookConfigurationError("Discord webhook URL must look like https://discord.com/api/webhooks/{id}/{token}")
    return value


class DiscordNotificationService:
    MAX_DELIVERY_ATTEMPTS = 3

    def __init__(
        self,
        store: RuntimeStore,
        credentials: CredentialStore,
        event_bus: EventBus | None = None,
    ) -> None:
        self.store = store
        self.credentials = credentials
        self.event_bus = event_bus

    def deliver_pending(self, limit: int = 10) -> int:
        notifications = self.store.list_notifications(status=NotificationStatus.PENDING, limit=limit)
        delivered = 0
        for notification in notifications:
            webhook_url = self.credentials.get("discord", "webhook_url")
            if not webhook_url:
                self._record_failure(
                    notification,
                    "DISCORD_WEBHOOK_URL is required for Discord delivery",
                    retryable=False,
                )
                continue

            try:
                safe_summary = self._safe_notification_summary(notification.summary)
                external_ref = self._send_webhook(webhook_url, safe_summary)
            except DiscordWebhookConfigurationError as exc:
                self._record_failure(notification, str(exc), invalid_configuration=True)
                self._fail_pending_invalid_webhook(str(exc), exclude_id=notification.id)
                break
            except (OSError, error.URLError, error.HTTPError, ValueError) as exc:
                self._record_failure(notification, str(exc), retryable=True)
                continue

            notification.status = NotificationStatus.DELIVERED
            notification.metadata["delivery_attempts"] = int(notification.metadata.get("delivery_attempts", 0) or 0) + 1
            notification.metadata.pop("last_delivery_error", None)
            self.store.insert_notification(notification)
            delivery = DiscordDelivery(
                notification_id=notification.id,
                status=NotificationStatus.DELIVERED,
                external_ref=external_ref,
                attempts=int(notification.metadata.get("delivery_attempts", 1) or 1),
                metadata={"summary": safe_summary, "summary_redacted": safe_summary != notification.summary},
            )
            self.store.insert_discord_delivery(delivery)
            self.store.insert_event(
                EventRecord(
                    type=EventType.NOTIFICATION_DELIVERED,
                    summary=safe_summary,
                    target_id=notification.target_id,
                    task_id=notification.task_id,
                    metadata={"summary_redacted": safe_summary != notification.summary},
                )
            )
            if self.event_bus is not None:
                self.event_bus.emit(
                    RuntimeSignal.NOTIFICATION_DELIVERED,
                    {"notification_id": notification.id, "target_id": notification.target_id},
                )
            delivered += 1
        return delivered

    def _send_webhook(self, webhook_url: str, summary: str) -> str:
        webhook_url = validate_discord_webhook_url(webhook_url)
        payload = json.dumps({"content": summary[:1900]}).encode("utf-8")
        req = request.Request(
            webhook_url,
            data=payload,
            method="POST",
            headers={"Content-Type": "application/json", "User-Agent": "Primordial/0.1"},
        )
        try:
            with request.urlopen(req, timeout=15) as response:
                response.read()
                return response.headers.get("X-Discord-Trace-Id", f"discord-http-{response.status}")
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            exc.close()
            if exc.code == 405:
                raise DiscordWebhookConfigurationError(
                    "invalid Discord webhook configuration: URL returned 405 Method Not Allowed; "
                    "save the /api/webhooks/{id}/{token} endpoint, not a channel or browser URL"
                ) from exc
            raise ValueError(f"Discord webhook returned {exc.code}: {detail}") from exc

    def _record_failure(
        self,
        notification,
        message: str,
        *,
        invalid_configuration: bool = False,
        retryable: bool = False,
    ) -> None:
        safe_message = redact_sensitive_text(message)
        safe_summary = self._safe_notification_summary(notification.summary)
        attempts = int(notification.metadata.get("delivery_attempts", 0) or 0) + 1
        terminal = invalid_configuration or not retryable or attempts >= self.MAX_DELIVERY_ATTEMPTS
        notification.status = NotificationStatus.FAILED if terminal else NotificationStatus.PENDING
        notification.metadata.update(
            {
                "delivery_attempts": attempts,
                "last_delivery_error": safe_message,
                "retryable_delivery_error": retryable and not terminal,
                "max_delivery_attempts": self.MAX_DELIVERY_ATTEMPTS,
            }
        )
        self.store.insert_notification(notification)
        self.store.insert_discord_delivery(
            DiscordDelivery(
                notification_id=notification.id,
                status=notification.status,
                attempts=attempts,
                last_error=safe_message,
                metadata={
                    "summary": safe_summary,
                    "summary_redacted": safe_summary != notification.summary,
                    "invalid_webhook_configuration": invalid_configuration,
                    "retryable": retryable and not terminal,
                },
            )
        )
        summary = (
            f"Discord delivery failed: invalid webhook configuration ({safe_message})"
            if invalid_configuration
            else f"Discord delivery failed: {safe_message}"
            if terminal
            else f"Discord delivery retry queued ({attempts}/{self.MAX_DELIVERY_ATTEMPTS}): {safe_message}"
        )
        self.store.insert_event(
            EventRecord(
                type=EventType.NOTIFICATION_FAILED,
                summary=summary,
                target_id=notification.target_id,
                task_id=notification.task_id,
                metadata={
                    "invalid_webhook_configuration": invalid_configuration,
                    "retryable": retryable and not terminal,
                    "attempts": attempts,
                    "max_attempts": self.MAX_DELIVERY_ATTEMPTS,
                },
            )
        )

    def _safe_notification_summary(self, summary: str) -> str:
        return redact_sensitive_text(summary)

    def _fail_pending_invalid_webhook(self, message: str, *, exclude_id: str) -> None:
        for notification in self.store.list_notifications(status=NotificationStatus.PENDING, limit=100):
            if notification.id == exclude_id:
                continue
            self._record_failure(notification, message, invalid_configuration=True)
