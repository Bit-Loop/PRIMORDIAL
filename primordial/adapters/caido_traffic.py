from __future__ import annotations

from primordial.adapters.caido_httpql import compact_search_attempts, request_search_attempts
from primordial.adapters.caido_normalization import (
    connection_count,
    normalize_request_detail,
    normalize_request_summary,
)
from primordial.adapters.caido_redaction import graphql_error_message


class CaidoTrafficMixin:
    def search_requests(self, httpql: str, *, limit: int = 50, offset: int = 0) -> dict[str, object]:
        selected_limit = max(1, min(int(limit), 200))
        selected_offset = max(0, int(offset))
        normalized_httpql = httpql.strip()
        last_result: dict[str, object] | None = None
        attempt_log: list[dict[str, object]] = []
        for attempt in request_search_attempts(
            httpql=normalized_httpql,
            limit=selected_limit,
            offset=selected_offset,
        ):
            result = self._execute_search_attempt(attempt)
            last_result = result
            attempt_log.append(self._search_attempt_log(attempt, result))
            if result.get("auth_error"):
                break
            if not result.get("ok"):
                continue
            connection = result.get("data", {}).get(attempt["field_name"]) if isinstance(result.get("data"), dict) else None
            if isinstance(connection, dict):
                return self._search_success(normalized_httpql, selected_limit, selected_offset, attempt, connection, attempt_log)
        return {
            "ok": False,
            "httpql": normalized_httpql,
            "error": graphql_error_message(last_result),
            "auth_error": bool(last_result.get("auth_error")) if isinstance(last_result, dict) else False,
            "query_field": "",
            "filter_strategy": "",
            "requests": [],
            "diagnostics": {"attempts": compact_search_attempts(attempt_log)},
        }

    def request_detail(self, request_id: str, *, snippet_chars: int = 4096) -> dict[str, object]:
        query = f"""
        query PrimordialCaidoRequestDetail($id: ID!) {{
          request(id: $id) {{
            {self.REQUEST_SUMMARY_FIELDS}
            raw
            response {{ id statusCode length roundtripTime createdAt raw }}
          }}
        }}
        """
        result = self.graphql(query, {"id": str(request_id)}, operation_name="PrimordialCaidoRequestDetail")
        if not result.get("ok"):
            return {"ok": False, "id": str(request_id), "error": graphql_error_message(result)}
        request_payload = result.get("data", {}).get("request") if isinstance(result.get("data"), dict) else None
        if not isinstance(request_payload, dict):
            return {"ok": False, "id": str(request_id), "error": "Caido request was not found."}
        return {
            "ok": True,
            "request": normalize_request_detail(request_payload, snippet_chars=snippet_chars),
        }

    def _execute_search_attempt(self, attempt: dict[str, object]) -> dict[str, object]:
        variables = attempt["variables"] if isinstance(attempt["variables"], dict) else {}
        return self.graphql(
            str(attempt["query"]),
            variables,
            operation_name="PrimordialCaidoRequestSearch",
        )

    def _search_attempt_log(self, attempt: dict[str, object], result: dict[str, object]) -> dict[str, object]:
        return {
            "query_field": str(attempt["field_name"]),
            "filter_strategy": str(attempt["filter_strategy"]),
            "ok": bool(result.get("ok")),
            "error": "" if result.get("ok") else graphql_error_message(result),
            "auth_error": bool(result.get("auth_error")),
        }

    def _search_success(
        self,
        httpql: str,
        limit: int,
        offset: int,
        attempt: dict[str, object],
        connection: dict[str, object],
        attempt_log: list[dict[str, object]],
    ) -> dict[str, object]:
        return {
            "ok": True,
            "httpql": httpql,
            "query_field": str(attempt["field_name"]),
            "filter_strategy": str(attempt["filter_strategy"]),
            "limit": limit,
            "offset": offset,
            "total": connection_count(connection),
            "requests": [normalize_request_summary(item) for item in connection.get("nodes", []) if isinstance(item, dict)],
            "diagnostics": {"attempts": compact_search_attempts(attempt_log)},
            "auth_error": False,
        }
