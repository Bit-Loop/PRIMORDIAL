from __future__ import annotations

from primordial.adapters.caido_redaction import graphql_error_message
from primordial.adapters.caido_schema import empty_schema, field_arg_types, schema_payload
from primordial.core.domain.models import utc_now


class CaidoStatusMixin:
    def status(self, *, check_health: bool = False) -> dict[str, object]:
        connection = self._connection()
        configured = connection is not None
        payload: dict[str, object] = {
            "configured": configured,
            "graphql_url": connection.graphql_url if connection else "",
            "graphql_url_migrated_from": connection.migrated_from if connection else "",
            "api_token_configured": bool(connection.api_token) if connection else False,
            "httpql_reference": {
                "host_filter_example": 'req.host.eq:"target.example"',
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
        payload["checked"] = False
        if check_health:
            self._merge_health_payload(payload)
        return payload

    def health(self) -> dict[str, object]:
        result = self.graphql("query PrimordialCaidoHealth { __typename }")
        traffic_result = self._traffic_health_result() if result.get("ok") else None
        traffic_ok = bool(traffic_result.get("ok")) if isinstance(traffic_result, dict) else False
        traffic_error = graphql_error_message(traffic_result) if isinstance(traffic_result, dict) and not traffic_ok else None
        return {
            "ok": bool(result["ok"]) and traffic_ok,
            "status_code": result.get("status_code"),
            "error": result.get("error") or traffic_error,
            "auth_error": bool(result.get("auth_error")) or self._traffic_auth_error(traffic_result),
            "graphql_typename": (result.get("data") or {}).get("__typename")
            if isinstance(result.get("data"), dict)
            else None,
            "traffic_access_ok": traffic_ok,
            "traffic_error": traffic_error,
        }

    def schema_probe(self) -> dict[str, object]:
        query = """
        query PrimordialCaidoSchemaProbe {
          __schema {
            queryType { name fields { name args { name type { kind name ofType { kind name ofType { kind name } } } } } }
            mutationType { name fields { name } }
          }
        }
        """
        result = self.graphql(query, operation_name="PrimordialCaidoSchemaProbe")
        schema = result.get("data", {}).get("__schema") if isinstance(result.get("data"), dict) else None
        query_fields: set[str] = set()
        mutation_fields: set[str] = set()
        request_args: dict[str, dict[str, str]] = {}
        if isinstance(schema, dict):
            query_type = schema.get("queryType") if isinstance(schema.get("queryType"), dict) else {}
            mutation_type = schema.get("mutationType") if isinstance(schema.get("mutationType"), dict) else {}
            query_field_payloads = [item for item in query_type.get("fields", []) if isinstance(item, dict)]
            query_fields = {str(item.get("name")) for item in query_field_payloads if item.get("name")}
            mutation_fields = {
                str(item.get("name"))
                for item in mutation_type.get("fields", [])
                if isinstance(item, dict) and item.get("name")
            }
            request_args = field_arg_types(query_field_payloads, {"request", "requests", "requestsByOffset"})
        return schema_payload(
            ok=bool(result.get("ok")) and bool(query_fields or mutation_fields),
            error=result.get("error"),
            query_fields=query_fields,
            mutation_fields=mutation_fields,
            request_args=request_args,
        )

    def _merge_health_payload(self, payload: dict[str, object]) -> None:
        health = self.health()
        payload.update(health)
        payload["checked"] = True
        if health.get("ok"):
            payload["schema"] = self.schema_probe()
        else:
            payload["schema"] = empty_schema(error=str(health.get("error") or "Caido health check failed."))

    def _traffic_health_result(self) -> dict[str, object]:
        return self.graphql(
            """
            query PrimordialCaidoTrafficHealth($limit: Int!, $offset: Int!) {
              requestsByOffset(limit: $limit, offset: $offset) { count { value } }
            }
            """,
            {"limit": 1, "offset": 0},
            operation_name="PrimordialCaidoTrafficHealth",
        )

    def _traffic_auth_error(self, traffic_result: object) -> bool:
        return bool(traffic_result.get("auth_error")) if isinstance(traffic_result, dict) else False
