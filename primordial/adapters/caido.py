from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
import re
from urllib import error, parse, request

from primordial.core.credentials import CredentialStore
from primordial.core.domain.models import utc_now
from primordial.core.events.bus import EventBus


@dataclass(frozen=True, slots=True)
class CaidoConnection:
    graphql_url: str
    api_token: str
    migrated_from: str = ""


@dataclass(frozen=True, slots=True)
class ParsedRawRequest:
    method: str
    host: str
    port: int
    is_tls: bool
    sni: str | None
    path: str
    raw: str
    raw_base64: str
    raw_sha256: str
    headers: dict[str, str]

    @property
    def connection_info(self) -> dict[str, object]:
        return {
            "host": self.host,
            "port": self.port,
            "isTLS": self.is_tls,
            "SNI": self.sni or self.host,
        }

    def as_payload(self) -> dict[str, object]:
        return {
            "method": self.method,
            "host": self.host,
            "port": self.port,
            "is_tls": self.is_tls,
            "sni": self.sni,
            "path": self.path,
            "raw_sha256": self.raw_sha256,
            "headers": sorted(self.headers),
            "connection": self.connection_info,
        }


class CaidoIntegrationService:
    DEFAULT_GRAPHQL_URL = "http://127.0.0.1:8650/graphql"
    LEGACY_DEFAULT_GRAPHQL_URLS = {
        "http://127.0.0.1:8080/graphql",
        "http://localhost:8080/graphql",
    }
    REQUEST_SUMMARY_FIELDS = """
        id
        host
        port
        method
        path
        query
        isTls
        length
        createdAt
        source
        metadata { id color }
        response {
            id
            statusCode
            length
            roundtripTime
            createdAt
        }
    """
    SENSITIVE_HEADER_RE = re.compile(
        r"^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-csrf-token|csrf-token)\s*:",
        re.IGNORECASE,
    )
    SENSITIVE_PARAM_RE = re.compile(
        r"(?i)\b(password|passwd|pwd|token|access_token|refresh_token|api[_-]?key|secret)=([^&\s]+)"
    )
    REQUEST_LINE_RE = re.compile(r"^[A-Z][A-Z0-9-]{0,31}\s+\S+\s+HTTP/\d(?:\.\d)?\s*$", re.MULTILINE)

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
            health = self.health()
            payload.update(health)
            payload["checked"] = True
            if health.get("ok"):
                payload["schema"] = self.schema_probe()
            else:
                payload["schema"] = self._empty_schema(error=str(health.get("error") or "Caido health check failed."))
        return payload

    def health(self) -> dict[str, object]:
        query = "query PrimordialCaidoHealth { __typename }"
        result = self.graphql(query)
        traffic_result = None
        if result.get("ok"):
            traffic_result = self.graphql(
                """
                query PrimordialCaidoTrafficHealth($limit: Int!, $offset: Int!) {
                  requestsByOffset(limit: $limit, offset: $offset) {
                    count { value }
                  }
                }
                """,
                {"limit": 1, "offset": 0},
                operation_name="PrimordialCaidoTrafficHealth",
            )
        traffic_ok = bool(traffic_result.get("ok")) if isinstance(traffic_result, dict) else False
        traffic_error = self._graphql_error_message(traffic_result) if isinstance(traffic_result, dict) and not traffic_ok else None
        return {
            "ok": bool(result["ok"]) and traffic_ok,
            "status_code": result.get("status_code"),
            "error": result.get("error") or traffic_error,
            "auth_error": bool(result.get("auth_error")) or bool(traffic_result.get("auth_error") if isinstance(traffic_result, dict) else False),
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
            queryType {
              name
              fields {
                name
                args {
                  name
                  type {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                        ofType { kind name }
                      }
                    }
                  }
                }
              }
            }
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
            query_fields = {
                str(item.get("name"))
                for item in query_field_payloads
                if item.get("name")
            }
            mutation_fields = {
                str(item.get("name"))
                for item in mutation_type.get("fields", [])
                if isinstance(item, dict) and item.get("name")
            }
            request_args = self._field_arg_types(
                query_field_payloads,
                {"request", "requests", "requestsByOffset"},
            )
        return {
            "ok": bool(result.get("ok")) and bool(query_fields or mutation_fields),
            "error": result.get("error"),
            "capabilities": {
                "requests_by_offset": "requestsByOffset" in query_fields,
                "requests": "requests" in query_fields,
                "request_detail": "request" in query_fields,
                "create_replay_session": "createReplaySession" in mutation_fields,
                "start_replay_task": "startReplayTask" in mutation_fields,
                "replay_entry": "replayEntry" in query_fields,
            },
            "query_fields": sorted(query_fields),
            "mutation_fields": sorted(mutation_fields),
            "request_args": request_args,
        }

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
        graph_payload: dict[str, object] = {"query": query, "variables": variables or {}}
        if operation_name:
            graph_payload["operationName"] = operation_name
        payload = json.dumps(graph_payload).encode("utf-8")
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
                errors = self._sanitize_graphql_errors(parsed.get("errors", []), connection.api_token)
                auth_error = self._contains_auth_error(errors)
                return {
                    "ok": not bool(errors),
                    "status_code": response.status,
                    "data": parsed.get("data"),
                    "errors": errors,
                    "auth_error": auth_error,
                }
        except error.HTTPError as exc:
            try:
                body = exc.read().decode("utf-8", errors="replace")
            finally:
                exc.close()
            message = self._redact_secret(body or str(exc), connection.api_token)
            return {
                "ok": False,
                "status_code": exc.code,
                "error": message,
                "auth_error": exc.code in {401, 403} or self._contains_auth_text(message),
            }
        except (OSError, TimeoutError, json.JSONDecodeError) as exc:
            return {"ok": False, "error": self._redact_secret(str(exc), connection.api_token)}

    def search_requests(self, httpql: str, *, limit: int = 50, offset: int = 0) -> dict[str, object]:
        selected_limit = max(1, min(int(limit), 200))
        selected_offset = max(0, int(offset))
        normalized_httpql = httpql.strip()
        last_result: dict[str, object] | None = None
        attempt_log: list[dict[str, object]] = []
        for attempt in self._request_search_attempts(
            httpql=normalized_httpql,
            limit=selected_limit,
            offset=selected_offset,
        ):
            field_name = str(attempt["field_name"])
            filter_strategy = str(attempt["filter_strategy"])
            result = self.graphql(
                str(attempt["query"]),
                attempt["variables"] if isinstance(attempt["variables"], dict) else {},
                operation_name="PrimordialCaidoRequestSearch",
            )
            last_result = result
            attempt_log.append(
                {
                    "query_field": field_name,
                    "filter_strategy": filter_strategy,
                    "ok": bool(result.get("ok")),
                    "error": "" if result.get("ok") else self._graphql_error_message(result),
                    "auth_error": bool(result.get("auth_error")),
                }
            )
            if result.get("auth_error"):
                break
            if not result.get("ok"):
                continue
            connection = result.get("data", {}).get(field_name) if isinstance(result.get("data"), dict) else None
            if not isinstance(connection, dict):
                continue
            return {
                "ok": True,
                "httpql": normalized_httpql,
                "query_field": field_name,
                "filter_strategy": filter_strategy,
                "limit": selected_limit,
                "offset": selected_offset,
                "total": self._connection_count(connection),
                "requests": [self._normalize_request_summary(item) for item in connection.get("nodes", []) if isinstance(item, dict)],
                "diagnostics": {"attempts": self._compact_search_attempts(attempt_log)},
                "auth_error": False,
            }
        return {
            "ok": False,
            "httpql": normalized_httpql,
            "error": self._graphql_error_message(last_result),
            "auth_error": bool(last_result.get("auth_error")) if isinstance(last_result, dict) else False,
            "query_field": "",
            "filter_strategy": "",
            "requests": [],
            "diagnostics": {"attempts": self._compact_search_attempts(attempt_log)},
        }

    def request_detail(self, request_id: str, *, snippet_chars: int = 4096) -> dict[str, object]:
        query = f"""
        query PrimordialCaidoRequestDetail($id: ID!) {{
          request(id: $id) {{
            {self.REQUEST_SUMMARY_FIELDS}
            raw
            response {{
              id
              statusCode
              length
              roundtripTime
              createdAt
              raw
            }}
          }}
        }}
        """
        result = self.graphql(
            query,
            {"id": str(request_id)},
            operation_name="PrimordialCaidoRequestDetail",
        )
        if not result.get("ok"):
            return {"ok": False, "id": str(request_id), "error": self._graphql_error_message(result)}
        request_payload = result.get("data", {}).get("request") if isinstance(result.get("data"), dict) else None
        if not isinstance(request_payload, dict):
            return {"ok": False, "id": str(request_id), "error": "Caido request was not found."}
        return {
            "ok": True,
            "request": self._normalize_request_detail(request_payload, snippet_chars=snippet_chars),
        }

    def create_replay_draft(self, raw_request: str) -> dict[str, object]:
        parsed = self.parse_raw_request(raw_request)
        query = """
        mutation PrimordialCreateReplaySession($input: CreateReplaySessionInput!) {
          createReplaySession(input: $input) {
            session {
              id
              name
              activeEntry { id }
              collection { id }
              entries(first: 10) {
                edges { node { id } }
                pageInfo { hasNextPage hasPreviousPage startCursor endCursor }
              }
            }
          }
        }
        """
        variables = {
            "input": {
                "requestSource": {
                    "raw": {
                        "connectionInfo": parsed.connection_info,
                        "raw": parsed.raw_base64,
                    }
                }
            }
        }
        result = self.graphql(query, variables, operation_name="PrimordialCreateReplaySession")
        if not result.get("ok"):
            return {"ok": False, "parsed": parsed.as_payload(), "error": self._graphql_error_message(result)}
        session = result.get("data", {}).get("createReplaySession", {}).get("session") if isinstance(result.get("data"), dict) else None
        if not isinstance(session, dict):
            return {"ok": False, "parsed": parsed.as_payload(), "error": "Caido did not return a replay session."}
        return {
            "ok": True,
            "parsed": parsed.as_payload(),
            "session": self._normalize_replay_session(session),
        }

    def send_replay(self, raw_request: str, *, session_id: str) -> dict[str, object]:
        parsed = self.parse_raw_request(raw_request)
        query = """
        mutation PrimordialStartReplayTask($sessionId: ID!, $input: StartReplayTaskInput!) {
          startReplayTask(sessionId: $sessionId, input: $input) {
            error { __typename }
            task {
              id
              createdAt
              replayEntry {
                id
                error
                createdAt
                connection { host port isTLS SNI }
                request {
                  id
                  host
                  port
                  method
                  path
                  query
                  isTls
                  length
                  createdAt
                  response { id statusCode length roundtripTime createdAt }
                }
              }
            }
          }
        }
        """
        variables = {
            "sessionId": str(session_id),
            "input": {
                "connection": parsed.connection_info,
                "raw": parsed.raw_base64,
                "settings": {
                    "connectionClose": True,
                    "updateContentLength": True,
                    "placeholders": [],
                },
            },
        }
        result = self.graphql(query, variables, operation_name="PrimordialStartReplayTask")
        if not result.get("ok"):
            return {"ok": False, "parsed": parsed.as_payload(), "error": self._graphql_error_message(result)}
        payload = result.get("data", {}).get("startReplayTask") if isinstance(result.get("data"), dict) else None
        if not isinstance(payload, dict):
            return {"ok": False, "parsed": parsed.as_payload(), "error": "Caido did not return a replay task."}
        if payload.get("error"):
            return {
                "ok": False,
                "parsed": parsed.as_payload(),
                "error": self._graphql_error_message({"errors": [payload["error"]]}),
                "caido_error": payload["error"],
            }
        task = payload.get("task") if isinstance(payload.get("task"), dict) else {}
        replay_entry = task.get("replayEntry") if isinstance(task.get("replayEntry"), dict) else {}
        return {
            "ok": True,
            "parsed": parsed.as_payload(),
            "task": {
                "id": str(task.get("id") or ""),
                "created_at": task.get("createdAt"),
                "replay_entry_id": str(replay_entry.get("id") or ""),
                "replay_entry_error": replay_entry.get("error"),
                "request": self._normalize_request_summary(replay_entry.get("request"))
                if isinstance(replay_entry.get("request"), dict)
                else None,
            },
        }

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

    def parse_raw_request(self, raw_request: str, *, max_bytes: int = 262_144) -> ParsedRawRequest:
        raw = raw_request.replace("\r\n", "\n").replace("\r", "\n")
        raw = raw.strip("\n")
        if not raw:
            raise ValueError("raw request is required")
        raw_bytes = raw.encode("utf-8", errors="replace")
        if len(raw_bytes) > max_bytes:
            raise ValueError(f"raw request exceeds {max_bytes} bytes")
        if "\x00" in raw:
            raise ValueError("raw request must not contain NUL bytes")
        request_lines = self.REQUEST_LINE_RE.findall(raw)
        if len(request_lines) > 1:
            raise ValueError("raw Replay send accepts one HTTP request at a time")
        lines = raw.split("\n")
        request_line = lines[0].strip()
        parts = request_line.split()
        if len(parts) != 3 or not parts[2].upper().startswith("HTTP/"):
            raise ValueError("raw request must start with an HTTP request line")
        method = parts[0].upper()
        if not re.fullmatch(r"[A-Z][A-Z0-9-]{0,31}", method):
            raise ValueError("raw request method is malformed")
        request_target = parts[1]
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if line == "":
                break
            if ":" not in line:
                raise ValueError("raw request contains a malformed header")
            name, value = line.split(":", 1)
            header_name = name.strip().lower()
            if not header_name:
                raise ValueError("raw request contains an empty header name")
            headers[header_name] = value.strip()
        absolute = parse.urlsplit(request_target)
        host_header = headers.get("host", "")
        host_value = absolute.netloc if absolute.scheme in {"http", "https"} and absolute.netloc else host_header
        if not host_value:
            raise ValueError("raw request must include a Host header or absolute request URL")
        host, header_port = self._split_host_port(host_value)
        if not host:
            raise ValueError("raw request host is malformed")
        explicit_port = absolute.port if absolute.scheme in {"http", "https"} and absolute.port else header_port
        is_tls = absolute.scheme == "https" or explicit_port == 443
        port = explicit_port or (443 if is_tls else 80)
        if not (1 <= int(port) <= 65535):
            raise ValueError("raw request port is out of range")
        if absolute.scheme in {"http", "https"}:
            path = absolute.path or "/"
            if absolute.query:
                path = f"{path}?{absolute.query}"
        else:
            path = request_target or "/"
        return ParsedRawRequest(
            method=method,
            host=host,
            port=int(port),
            is_tls=is_tls,
            sni=host,
            path=path,
            raw=raw,
            raw_base64=base64.b64encode(raw.encode("utf-8")).decode("ascii"),
            raw_sha256=hashlib.sha256(raw.encode("utf-8")).hexdigest(),
            headers=headers,
        )

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
        if self._remote_caido_allowed():
            return None
        if host in {"localhost", "127.0.0.1", "::1"}:
            return None
        try:
            if ipaddress.ip_address(host).is_private:
                return None
        except ValueError:
            pass
        return "Refusing non-local Caido URL unless PRIMORDIAL_ALLOW_REMOTE_CAIDO=1 is set."

    def _remote_caido_allowed(self) -> bool:
        return os.getenv("PRIMORDIAL_ALLOW_REMOTE_CAIDO", "").strip().lower() in {"1", "true", "yes", "on"}

    def _httpql_string(self, value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"')

    def _graphql_string_literal(self, value: str) -> str:
        return json.dumps(value)

    def _request_search_attempts(self, *, httpql: str, limit: int, offset: int) -> list[dict[str, object]]:
        attempts: list[dict[str, object]] = []
        field_shapes = [
            ("requestsByOffset", {"limit": limit, "offset": offset}, ["limit: $limit", "offset: $offset"]),
            ("requests", {"limit": limit}, ["first: $limit"]),
        ]
        filter_shapes: list[tuple[str, str, dict[str, object], str]]
        if httpql:
            httpql_literal = self._graphql_string_literal(httpql)
            filter_shapes = [
                ("variable:HTTPQLInput.code", "$filter: HTTPQLInput!, ", {"filter": {"code": httpql}}, "filter: $filter"),
                ("inline:HTTPQLInput.code", "", {}, f"filter: {{ code: {httpql_literal} }}"),
                ("variable:HTTPQLInput.query", "$filter: HTTPQLInput!, ", {"filter": {"query": httpql}}, "filter: $filter"),
                ("inline:HTTPQLInput.query", "", {}, f"filter: {{ query: {httpql_literal} }}"),
                ("variable:String", "$filter: String!, ", {"filter": httpql}, "filter: $filter"),
                ("inline:String", "", {}, f"filter: {httpql_literal}"),
            ]
        else:
            filter_shapes = [("unfiltered", "", {}, "")]
        for field_name, base_variables, base_args in field_shapes:
            for filter_strategy, filter_var_defs, filter_variables, filter_arg in filter_shapes:
                for include_order in (True, False):
                    variables = dict(base_variables)
                    variables.update(filter_variables)
                    arg_lines = list(base_args)
                    if filter_arg:
                        arg_lines.append(filter_arg)
                    if include_order:
                        arg_lines.append("order: { by: CREATED_AT, ordering: DESC }")
                    variable_defs = "$limit: Int!"
                    if field_name == "requestsByOffset":
                        variable_defs += ", $offset: Int!"
                    if filter_var_defs:
                        variable_defs = filter_var_defs + variable_defs
                    args = "\n                    ".join(arg_lines)
                    query = f"""
                query PrimordialCaidoRequestSearch({variable_defs}) {{
                  {field_name}(
                    {args}
                  ) {{
                    count {{ value }}
                    nodes {{ {self.REQUEST_SUMMARY_FIELDS} }}
                  }}
                }}
                """
                    order_label = "+order" if include_order else ""
                    attempts.append(
                        {
                            "field_name": field_name,
                            "filter_strategy": f"{filter_strategy}{order_label}",
                            "query": query,
                            "variables": variables,
                        }
                    )
        return attempts

    def _compact_search_attempts(self, attempts: list[dict[str, object]]) -> list[dict[str, object]]:
        compacted = []
        seen_errors: set[tuple[str, str, str]] = set()
        for item in attempts:
            error_text = str(item.get("error") or "")
            key = (str(item.get("query_field") or ""), str(item.get("filter_strategy") or ""), error_text)
            if error_text and key in seen_errors:
                continue
            if error_text:
                seen_errors.add(key)
            compacted.append(
                {
                    "query_field": item.get("query_field") or "",
                    "filter_strategy": item.get("filter_strategy") or "",
                    "ok": bool(item.get("ok")),
                    "error": error_text,
                    "auth_error": bool(item.get("auth_error")),
                }
            )
        return compacted[-8:]

    def _field_arg_types(self, fields: list[dict[str, object]], selected_names: set[str]) -> dict[str, dict[str, str]]:
        selected: dict[str, dict[str, str]] = {}
        for field in fields:
            name = str(field.get("name") or "")
            if name not in selected_names:
                continue
            args: dict[str, str] = {}
            for arg in field.get("args", []) if isinstance(field.get("args"), list) else []:
                if not isinstance(arg, dict):
                    continue
                arg_name = str(arg.get("name") or "")
                if not arg_name:
                    continue
                args[arg_name] = self._graphql_type_name(arg.get("type"))
            selected[name] = args
        return selected

    def _graphql_type_name(self, value: object) -> str:
        if not isinstance(value, dict):
            return ""
        kind = str(value.get("kind") or "")
        name = str(value.get("name") or "")
        if kind == "NON_NULL":
            inner = self._graphql_type_name(value.get("ofType"))
            return f"{inner}!" if inner else "!"
        if kind == "LIST":
            inner = self._graphql_type_name(value.get("ofType"))
            return f"[{inner}]" if inner else "[]"
        return name or kind

    def _normalize_request_summary(self, payload: dict[str, object] | None) -> dict[str, object]:
        payload = payload or {}
        response_payload = payload.get("response") if isinstance(payload.get("response"), dict) else {}
        query = str(payload.get("query") or "")
        path = str(payload.get("path") or "/")
        return {
            "id": str(payload.get("id") or ""),
            "method": str(payload.get("method") or ""),
            "host": str(payload.get("host") or ""),
            "port": payload.get("port"),
            "path": f"{path}?{query}" if query and "?" not in path else path,
            "query": query,
            "is_tls": bool(payload.get("isTls")),
            "length": int(payload.get("length") or 0),
            "created_at": payload.get("createdAt"),
            "source": str(payload.get("source") or ""),
            "status": int(response_payload.get("statusCode") or 0) if isinstance(response_payload, dict) else 0,
            "response_id": str(response_payload.get("id") or "") if isinstance(response_payload, dict) else "",
            "response_length": int(response_payload.get("length") or 0) if isinstance(response_payload, dict) else 0,
            "roundtrip_time_ms": int(response_payload.get("roundtripTime") or 0) if isinstance(response_payload, dict) else 0,
        }

    def _normalize_request_detail(self, payload: dict[str, object], *, snippet_chars: int) -> dict[str, object]:
        summary = self._normalize_request_summary(payload)
        response_payload = payload.get("response") if isinstance(payload.get("response"), dict) else {}
        request_raw = self._blob_to_text(payload.get("raw"))
        response_raw = self._blob_to_text(response_payload.get("raw") if isinstance(response_payload, dict) else None)
        request_snippet = self._redacted_snippet(request_raw, snippet_chars)
        response_snippet = self._redacted_snippet(response_raw, snippet_chars)
        summary.update(
            {
                "request_sha256": hashlib.sha256(request_raw.encode("utf-8", errors="replace")).hexdigest()
                if request_raw
                else "",
                "response_sha256": hashlib.sha256(response_raw.encode("utf-8", errors="replace")).hexdigest()
                if response_raw
                else "",
                "request_snippet": request_snippet["text"],
                "response_snippet": response_snippet["text"],
                "request_truncated": request_snippet["truncated"],
                "response_truncated": response_snippet["truncated"],
                "raw_bodies_stored": False,
            }
        )
        return summary

    def _normalize_replay_session(self, payload: dict[str, object]) -> dict[str, object]:
        active = payload.get("activeEntry") if isinstance(payload.get("activeEntry"), dict) else {}
        collection = payload.get("collection") if isinstance(payload.get("collection"), dict) else {}
        entry_ids: list[str] = []
        entries = payload.get("entries") if isinstance(payload.get("entries"), dict) else {}
        for edge in entries.get("edges", []) if isinstance(entries, dict) else []:
            node = edge.get("node") if isinstance(edge, dict) and isinstance(edge.get("node"), dict) else {}
            if node.get("id"):
                entry_ids.append(str(node["id"]))
        return {
            "id": str(payload.get("id") or ""),
            "name": str(payload.get("name") or ""),
            "active_entry_id": str(active.get("id") or ""),
            "collection_id": str(collection.get("id") or ""),
            "entry_ids": entry_ids,
        }

    def _connection_count(self, payload: dict[str, object]) -> int:
        count = payload.get("count") if isinstance(payload.get("count"), dict) else {}
        try:
            return int(count.get("value") or 0)
        except (TypeError, ValueError):
            return 0

    def _blob_to_text(self, value: object) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        text = str(value)
        compact = text.strip()
        if not compact:
            return ""
        try:
            decoded = base64.b64decode(compact, validate=True)
        except (ValueError, base64.binascii.Error):
            return text
        try:
            return decoded.decode("utf-8", errors="replace")
        except UnicodeDecodeError:
            return decoded.decode("latin-1", errors="replace")

    def _redacted_snippet(self, value: str, max_chars: int) -> dict[str, object]:
        redacted_lines = []
        for line in value.splitlines():
            if self.SENSITIVE_HEADER_RE.match(line):
                name = line.split(":", 1)[0]
                redacted_lines.append(f"{name}: [redacted]")
            else:
                redacted_lines.append(self.SENSITIVE_PARAM_RE.sub(r"\1=[redacted]", line))
        redacted = "\n".join(redacted_lines)
        selected_max = max(256, int(max_chars))
        truncated = len(redacted) > selected_max
        return {
            "text": redacted[:selected_max],
            "truncated": truncated,
        }

    def _split_host_port(self, value: str) -> tuple[str, int | None]:
        cleaned = value.strip()
        if not cleaned:
            return "", None
        parsed = parse.urlsplit(f"//{cleaned}")
        host = parsed.hostname or cleaned
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("raw request host port is malformed") from exc
        return host.strip("[]").lower(), port

    def _sanitize_graphql_errors(self, errors: object, secret: str) -> list[object]:
        if not isinstance(errors, list):
            return []
        return [self._sanitize_json(item, secret) for item in errors]

    def _empty_schema(self, *, error: str = "") -> dict[str, object]:
        return {
            "ok": False,
            "error": error,
            "capabilities": {
                "requests_by_offset": False,
                "requests": False,
                "request_detail": False,
                "create_replay_session": False,
                "start_replay_task": False,
                "replay_entry": False,
            },
            "query_fields": [],
            "mutation_fields": [],
            "request_args": {},
        }

    def _contains_auth_error(self, errors: list[object]) -> bool:
        return any(self._contains_auth_text(json.dumps(item, sort_keys=True)) for item in errors)

    def _contains_auth_text(self, value: str) -> bool:
        lowered = value.lower()
        return (
            "unauthorized" in lowered
            or "forbidden" in lowered
            or "invalid token" in lowered
            or "invalid_token" in lowered
            or '"authorization"' in lowered
        )

    def _sanitize_json(self, value: object, secret: str) -> object:
        if isinstance(value, dict):
            return {str(key): self._sanitize_json(item, secret) for key, item in value.items()}
        if isinstance(value, list):
            return [self._sanitize_json(item, secret) for item in value]
        if isinstance(value, str):
            return self._redact_secret(value, secret)
        return value

    def _redact_secret(self, value: str, secret: str) -> str:
        if secret:
            value = value.replace(secret, "[redacted]")
        return value

    def _graphql_error_message(self, result: dict[str, object] | None) -> str:
        if not result:
            return "Caido GraphQL request failed."
        if result.get("error"):
            return str(result["error"])
        errors = result.get("errors")
        if isinstance(errors, list) and errors:
            first = errors[0]
            if isinstance(first, dict):
                caido = first.get("extensions", {}).get("CAIDO") if isinstance(first.get("extensions"), dict) else None
                if isinstance(caido, dict):
                    reason = str(caido.get("reason") or "").strip()
                    code = str(caido.get("code") or "").strip()
                    if reason or code:
                        category = code.lower() if code else "graphql"
                        return f"Caido {category} error: {reason or code}"
                return str(first.get("message") or first.get("code") or first.get("__typename") or first)
            return str(first)
        return "Caido GraphQL request failed."
