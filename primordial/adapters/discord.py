from __future__ import annotations

import json
from urllib import error, request

from primordial.core.credentials import CredentialStore
from primordial.core.events.bus import EventBus, RuntimeSignal
from primordial.core.domain.enums import EventType, NotificationStatus
from primordial.core.domain.models import DiscordDelivery, EventRecord
from primordial.core.storage.runtime import RuntimeStore


class DiscordNotificationService:
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
                notification.status = NotificationStatus.FAILED
                self.store.insert_notification(notification)
                self.store.insert_discord_delivery(
                    DiscordDelivery(
                        notification_id=notification.id,
                        status=NotificationStatus.FAILED,
                        attempts=1,
                        last_error="DISCORD_WEBHOOK_URL is required for Discord delivery",
                        metadata={"summary": notification.summary},
                    )
                )
                self.store.insert_event(
                    EventRecord(
                        type=EventType.NOTIFICATION_FAILED,
                        summary="Discord delivery failed: DISCORD_WEBHOOK_URL is not configured",
                        target_id=notification.target_id,
                        task_id=notification.task_id,
                    )
                )
                continue

            try:
                external_ref = self._send_webhook(webhook_url, notification.summary)
            except (OSError, error.URLError, error.HTTPError, ValueError) as exc:
                notification.status = NotificationStatus.FAILED
                self.store.insert_notification(notification)
                self.store.insert_discord_delivery(
                    DiscordDelivery(
                        notification_id=notification.id,
                        status=NotificationStatus.FAILED,
                        attempts=1,
                        last_error=str(exc),
                        metadata={"summary": notification.summary},
                    )
                )
                self.store.insert_event(
                    EventRecord(
                        type=EventType.NOTIFICATION_FAILED,
                        summary=f"Discord delivery failed: {exc}",
                        target_id=notification.target_id,
                        task_id=notification.task_id,
                    )
                )
                continue

            notification.status = NotificationStatus.DELIVERED
            self.store.insert_notification(notification)
            delivery = DiscordDelivery(
                notification_id=notification.id,
                status=NotificationStatus.DELIVERED,
                external_ref=external_ref,
                attempts=1,
                metadata={"summary": notification.summary},
            )
            self.store.insert_discord_delivery(delivery)
            self.store.insert_event(
                EventRecord(
                    type=EventType.NOTIFICATION_DELIVERED,
                    summary=notification.summary,
                    target_id=notification.target_id,
                    task_id=notification.task_id,
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
            raise ValueError(f"Discord webhook returned {exc.code}: {detail}") from exc
