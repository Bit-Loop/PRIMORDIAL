from __future__ import annotations

import ipaddress
import os
from urllib import parse, request

from primordial.adapters.caido_constants import DEFAULT_GRAPHQL_URL, LEGACY_DEFAULT_GRAPHQL_URLS, REQUEST_SUMMARY_FIELDS
from primordial.adapters.caido_graphql import CaidoGraphQLMixin
from primordial.adapters.caido_models import CaidoConnection, ParsedRawRequest
from primordial.adapters.caido_replay import CaidoReplayMixin
from primordial.adapters.caido_status import CaidoStatusMixin
from primordial.adapters.caido_traffic import CaidoTrafficMixin
from primordial.core.credentials import CredentialStore
from primordial.core.events.bus import EventBus


class CaidoIntegrationService(
    CaidoStatusMixin,
    CaidoGraphQLMixin,
    CaidoTrafficMixin,
    CaidoReplayMixin,
):
    DEFAULT_GRAPHQL_URL = DEFAULT_GRAPHQL_URL
    LEGACY_DEFAULT_GRAPHQL_URLS = LEGACY_DEFAULT_GRAPHQL_URLS
    REQUEST_SUMMARY_FIELDS = REQUEST_SUMMARY_FIELDS

    def __init__(
        self,
        credentials: CredentialStore,
        event_bus: EventBus | None = None,
        *,
        timeout_seconds: float = 5.0,
    ) -> None:
        self.credentials = credentials
        self.event_bus = event_bus
        self.timeout_seconds = timeout_seconds

    def _connection(self) -> CaidoConnection | None:
        graphql_url = self.credentials.get("caido", "graphql_url")
        api_token = self.credentials.get("caido", "api_token")
        if not graphql_url or not api_token:
            return None
        normalized_url = self.normalize_graphql_url(graphql_url)
        migrated_from = graphql_url if normalized_url != graphql_url else ""
        return CaidoConnection(graphql_url=normalized_url, api_token=api_token, migrated_from=migrated_from)

    @classmethod
    def normalize_graphql_url(cls, value: str) -> str:
        cleaned = str(value or "").strip()
        if cleaned in cls.LEGACY_DEFAULT_GRAPHQL_URLS:
            return cls.DEFAULT_GRAPHQL_URL
        return cleaned

    def _validate_graphql_url(self, value: str) -> str | None:
        parsed = parse.urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return "Caido GraphQL URL must be an http(s) URL."
        host = (parsed.hostname or "").lower()
        if self._remote_caido_allowed() or host in {"localhost", "127.0.0.1", "::1"}:
            return None
        try:
            if ipaddress.ip_address(host).is_private:
                return None
        except ValueError:
            pass
        return "Refusing non-local Caido URL unless PRIMORDIAL_ALLOW_REMOTE_CAIDO=1 is set."

    def _remote_caido_allowed(self) -> bool:
        return os.getenv("PRIMORDIAL_ALLOW_REMOTE_CAIDO", "").strip().lower() in {"1", "true", "yes", "on"}

    def _urlopen(self, graph_request: request.Request):
        return request.urlopen(graph_request, timeout=self.timeout_seconds)


__all__ = [
    "CaidoConnection",
    "CaidoIntegrationService",
    "ParsedRawRequest",
    "request",
]
