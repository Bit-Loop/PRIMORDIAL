from __future__ import annotations

from primordial.app.runtime_deps import (
    CaidoIntegrationService,
    EventRecord,
    EventType,
    validate_discord_webhook_url,
)

class RuntimeCredentialsMixin:
    def credentials_payload(self) -> dict[str, object]:
        return self.credentials.status()

    def skills_payload(self, *, include_body: bool = False) -> dict[str, object]:
        return self.skills.payload(include_body=include_body)

    def set_notion_credentials(
        self,
        *,
        api_key: str | None = None,
        parent_page_id: str | None = None,
        version: str | None = None,
    ) -> dict[str, object]:
        values = {
            "api_key": api_key or "",
            "parent_page_id": parent_page_id or "",
            "version": version or "",
        }
        self.credentials.clear_service_status("notion")
        outcome = self.credentials.update_service("notion", values)
        self.store.insert_event(
            EventRecord(
                type=EventType.CREDENTIAL_UPDATED,
                summary="Notion credentials updated",
                metadata={"service": "notion", "changed": outcome["changed"]},
            )
        )
        return self.credentials_payload()

    def set_discord_credentials(self, *, webhook_url: str | None = None) -> dict[str, object]:
        validated_webhook_url = validate_discord_webhook_url(webhook_url or "")
        outcome = self.credentials.update_service("discord", {"webhook_url": validated_webhook_url})
        self.store.insert_event(
            EventRecord(
                type=EventType.CREDENTIAL_UPDATED,
                summary="Discord credentials updated",
                metadata={"service": "discord", "changed": outcome["changed"]},
            )
        )
        return self.credentials_payload()

    def set_known_credentials(
        self,
        *,
        username: str | None = None,
        password: str | None = None,
        domain: str | None = None,
    ) -> dict[str, object]:
        values = {
            "username": username or "",
            "password": password or "",
            "domain": domain or "",
        }
        outcome = self.credentials.update_service("known", values)
        self.store.insert_event(
            EventRecord(
                type=EventType.CREDENTIAL_UPDATED,
                summary="Known credentials updated",
                metadata={"service": "known", "changed": outcome["changed"]},
            )
        )
        return self.credentials_payload()

    def set_lab_credentials(
        self,
        *,
        username: str | None = None,
        password: str | None = None,
        domain: str | None = None,
    ) -> dict[str, object]:
        return self.set_known_credentials(username=username, password=password, domain=domain)

    def set_caido_credentials(
        self,
        *,
        graphql_url: str | None = None,
        api_token: str | None = None,
    ) -> dict[str, object]:
        existing_graphql_url = self.credentials.get("caido", "graphql_url")
        selected_graphql_url = CaidoIntegrationService.normalize_graphql_url(graphql_url or "")
        default_graphql_url = ""
        if api_token and not selected_graphql_url:
            if not existing_graphql_url or existing_graphql_url != CaidoIntegrationService.normalize_graphql_url(existing_graphql_url):
                default_graphql_url = CaidoIntegrationService.DEFAULT_GRAPHQL_URL
        values = {
            "graphql_url": selected_graphql_url or default_graphql_url,
            "api_token": api_token or "",
        }
        outcome = self.credentials.update_service("caido", values)
        self.store.insert_event(
            EventRecord(
                type=EventType.CREDENTIAL_UPDATED,
                summary="Caido credentials updated",
                metadata={"service": "caido", "changed": outcome["changed"]},
            )
        )
        return self.credentials_payload()

    def clear_credentials(self, service: str) -> dict[str, object]:
        if service not in {"notion", "discord", "known", "lab", "caido"}:
            raise ValueError("service must be one of: notion, discord, known, lab, caido")
        removed = self.credentials.clear_service(service)
        if service == "lab":
            removed = self.credentials.clear_service("known") or removed
        elif service == "known":
            removed = self.credentials.clear_service("lab") or removed
        self.store.insert_event(
            EventRecord(
                type=EventType.CREDENTIAL_CLEARED,
                summary=f"{('known' if service == 'lab' else service).title()} credentials cleared",
                metadata={"service": service, "removed": removed},
            )
        )
        return self.credentials_payload()
