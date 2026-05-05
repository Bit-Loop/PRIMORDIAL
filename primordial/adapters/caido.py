from __future__ import annotations

from dataclasses import dataclass
import json
import os
from typing import Any
from urllib import error, parse, request

from primordial.core.credentials import CredentialStore
from primordial.core.domain.models import utc_now
from primordial.core.events.bus import EventBus


@dataclass(frozen=True, slots=True)
class CaidoConnection:
    graphql_url: str
    api_token: str


class CaidoIntegrationService:
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

    def status(self, *, check_health: bool = False) -> dict[str, object]:
        connection = self._connection()
        configured = connection is not None
        payload: dict[str, object] = {
            "configured": configured,
            "graphql_url": connection.graphql_url if connection else "",
            "api_token_configured": bool(connection.api_token) if connection else False,
            "httpql_reference": {
                "host_filter_example": 'req.host.eq:"pirate.htb"',
                "status_filter_example": "resp.code.gte:400",
                "token_hunt_example": 'resp.raw.cont:"api_key" OR resp.raw.cont:"secret" OR resp.raw.cont:"token"',
            },
            "checked_at": utc_now().isoformat(),
        }
        if not configured:
            payload["ok"] = False
            payload["error"] = "Caido GraphQL URL and API token are not configured."
            return payload
        validation_error = self._validate_graphql_url(connection.graphql_url)
        if validation_error:
            payload["ok"] = False
            payload["error"] = validation_error
            return payload
        payload["ok"] = True
        if check_health:
            payload.update(self.health())
        return payload

    def health(self) -> dict[str, object]:
        query = "query PrimordialCaidoHealth { __typename }"
        result = self.graphql(query)
        return {
            "ok": result["ok"],
            "status_code": result.get("status_code"),
            "error": result.get("error"),
            "graphql_typename": (result.get("data") or {}).get("__typename")
            if isinstance(result.get("data"), dict)
            else None,
        }

    def graphql(self, query: str, variables: dict[str, object] | None = None) -> dict[str, object]:
        connection = self._connection()
        if connection is None:
            return {"ok": False, "error": "Caido GraphQL URL and API token are not configured."}
        validation_error = self._validate_graphql_url(connection.graphql_url)
        if validation_error:
            return {"ok": False, "error": validation_error}
        payload = json.dumps({"query": query, "variables": variables or {}}).encode("utf-8")
        graph_request = request.Request(
            connection.graphql_url,
            data=payload,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {connection.api_token}",
                "Content-Type": "application/json",
                "User-Agent": "Primordial-Caido-Adapter/1",
            },
            method="POST",
        )
        try:
            with request.urlopen(graph_request, timeout=self.timeout_seconds) as response:
                body = response.read()
                parsed = json.loads(body.decode("utf-8")) if body else {}
                return {
                    "ok": not bool(parsed.get("errors")),
                    "status_code": response.status,
                    "data": parsed.get("data"),
                    "errors": parsed.get("errors", []),
                }
        except error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            return {"ok": False, "status_code": exc.code, "error": body or str(exc)}
        except (OSError, TimeoutError, json.JSONDecodeError) as exc:
            return {"ok": False, "error": str(exc)}

    def build_target_httpql(self, terms: list[str], *, max_terms: int = 8) -> str:
        clauses: list[str] = []
        seen: set[str] = set()
        for raw_term in terms:
            term = raw_term.strip()
            if not term or term in seen:
                continue
            seen.add(term)
            parsed = parse.urlsplit(term if "://" in term else f"//{term}")
            host = parsed.hostname or term
            if not host:
                continue
            escaped_host = self._httpql_string(host)
            if parsed.path and parsed.path not in {"", "/"}:
                clauses.append(f'(req.host.eq:"{escaped_host}" AND req.path.cont:"{self._httpql_string(parsed.path)}")')
            else:
                clauses.append(f'req.host.eq:"{escaped_host}"')
            if len(clauses) >= max_terms:
                break
        return " OR ".join(clauses)

    def _connection(self) -> CaidoConnection | None:
        graphql_url = self.credentials.get("caido", "graphql_url")
        api_token = self.credentials.get("caido", "api_token")
        if not graphql_url or not api_token:
            return None
        return CaidoConnection(graphql_url=graphql_url, api_token=api_token)

    def _validate_graphql_url(self, value: str) -> str | None:
        parsed = parse.urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return "Caido GraphQL URL must be an http(s) URL."
        host = (parsed.hostname or "").lower()
        if self._remote_caido_allowed():
            return None
        if host in {"localhost", "127.0.0.1", "::1"}:
            return None
        if host.startswith("10.") or host.startswith("192.168.") or host.startswith("172.16."):
            return None
        return "Refusing non-local Caido URL unless PRIMORDIAL_ALLOW_REMOTE_CAIDO=1 is set."

    def _remote_caido_allowed(self) -> bool:
        return os.getenv("PRIMORDIAL_ALLOW_REMOTE_CAIDO", "").strip().lower() in {"1", "true", "yes", "on"}

    def _httpql_string(self, value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"')
