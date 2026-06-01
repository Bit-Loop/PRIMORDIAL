from __future__ import annotations

import json
from urllib import error, request

from primordial.adapters.caido_redaction import (
    contains_auth_error,
    contains_auth_text,
    redact_secret,
    sanitize_graphql_errors,
)


class CaidoGraphQLMixin:
    def graphql(
        self,
        query: str,
        variables: dict[str, object] | None = None,
        *,
        operation_name: str | None = None,
    ) -> dict[str, object]:
        connection = self._connection()
        if connection is None:
            return {"ok": False, "error": "Caido GraphQL URL and API token are not configured."}
        validation_error = self._validate_graphql_url(connection.graphql_url)
        if validation_error:
            return {"ok": False, "error": validation_error}
        graph_request = self._build_graphql_request(
            connection.graphql_url,
            connection.api_token,
            query,
            variables or {},
            operation_name=operation_name,
        )
        try:
            with self._urlopen(graph_request) as response:
                body = response.read()
                parsed = json.loads(body.decode("utf-8")) if body else {}
                errors = sanitize_graphql_errors(parsed.get("errors", []), connection.api_token)
                return {
                    "ok": not bool(errors),
                    "status_code": response.status,
                    "data": parsed.get("data"),
                    "errors": errors,
                    "auth_error": contains_auth_error(errors),
                }
        except error.HTTPError as exc:
            try:
                body = exc.read().decode("utf-8", errors="replace")
            finally:
                exc.close()
            message = redact_secret(body or str(exc), connection.api_token)
            return {
                "ok": False,
                "status_code": exc.code,
                "error": message,
                "auth_error": exc.code in {401, 403} or contains_auth_text(message),
            }
        except (OSError, TimeoutError, json.JSONDecodeError) as exc:
            return {"ok": False, "error": redact_secret(str(exc), connection.api_token)}

    def _build_graphql_request(
        self,
        graphql_url: str,
        api_token: str,
        query: str,
        variables: dict[str, object],
        *,
        operation_name: str | None,
    ) -> request.Request:
        graph_payload: dict[str, object] = {"query": query, "variables": variables}
        if operation_name:
            graph_payload["operationName"] = operation_name
        return request.Request(
            graphql_url,
            data=json.dumps(graph_payload).encode("utf-8"),
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {api_token}",
                "Content-Type": "application/json",
                "User-Agent": "Primordial-Caido-Adapter/1",
            },
            method="POST",
        )
