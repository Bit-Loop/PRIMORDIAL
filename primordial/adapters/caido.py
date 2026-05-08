from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
import re
from typing import Any
from urllib import error, parse, request

from primordial.core.credentials import CredentialStore
from primordial.core.domain.models import utc_now
from primordial.core.events.bus import EventBus


@dataclass(frozen=True, slots=True)
class CaidoConnection:
    graphql_url: str
    api_token: str


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
            "api_token_configured": bool(connection.api_token) if connection else False,
            "httpql_reference": {
                "host_filter_example": 'req.host.eq:"target.htb"',
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
            payload["schema"] = self.schema_probe()
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

    def schema_probe(self) -> dict[str, object]:
        query = """
        query PrimordialCaidoSchemaProbe {
          __schema {
            queryType { name fields { name } }
            mutationType { name fields { name } }
          }
        }
        """
        result = self.graphql(query, operation_name="PrimordialCaidoSchemaProbe")
        schema = result.get("data", {}).get("__schema") if isinstance(result.get("data"), dict) else None
        query_fields: set[str] = set()
        mutation_fields: set[str] = set()
        if isinstance(schema, dict):
            query_type = schema.get("queryType") if isinstance(schema.get("queryType"), dict) else {}
            mutation_type = schema.get("mutationType") if isinstance(schema.get("mutationType"), dict) else {}
            query_fields = {
                str(item.get("name"))
                for item in query_type.get("fields", [])
                if isinstance(item, dict) and item.get("name")
            }
            mutation_fields = {
                str(item.get("name"))
                for item in mutation_type.get("fields", [])
                if isinstance(item, dict) and item.get("name")
            }
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
                return {
                    "ok": not bool(errors),
                    "status_code": response.status,
                    "data": parsed.get("data"),
                    "errors": errors,
                }
        except error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            return {"ok": False, "status_code": exc.code, "error": self._redact_secret(body or str(exc), connection.api_token)}
        except (OSError, TimeoutError, json.JSONDecodeError) as exc:
            return {"ok": False, "error": self._redact_secret(str(exc), connection.api_token)}

    def search_requests(self, httpql: str, *, limit: int = 50, offset: int = 0) -> dict[str, object]:
        selected_limit = max(1, min(int(limit), 200))
        selected_offset = max(0, int(offset))
        normalized_httpql = httpql.strip()
        variables: dict[str, object] = {
            "filter": normalized_httpql or None,
            "limit": selected_limit,
            "offset": selected_offset,
        }
        attempts = [
            (
                "requestsByOffset",
                f"""
                query PrimordialCaidoRequestSearch($filter: HTTPQL, $limit: Int!, $offset: Int!) {{
                  requestsByOffset(
                    limit: $limit
                    offset: $offset
                    filter: $filter
                    order: {{ by: CREATED_AT, ordering: DESC }}
                  ) {{
                    count {{ value }}
                    nodes {{ {self.REQUEST_SUMMARY_FIELDS} }}
                  }}
                }}
                """,
                "PrimordialCaidoRequestSearch",
            ),
            (
                "requestsByOffset",
                f"""
                query PrimordialCaidoRequestSearch($filter: HTTPQL, $limit: Int!, $offset: Int!) {{
                  requestsByOffset(limit: $limit, offset: $offset, filter: $filter) {{
                    count {{ value }}
                    nodes {{ {self.REQUEST_SUMMARY_FIELDS} }}
                  }}
                }}
                """,
                "PrimordialCaidoRequestSearch",
            ),
            (
                "requests",
                f"""
                query PrimordialCaidoRequestSearch($filter: HTTPQL, $limit: Int!) {{
                  requests(first: $limit, filter: $filter, order: {{ by: CREATED_AT, ordering: DESC }}) {{
                    count {{ value }}
                    nodes {{ {self.REQUEST_SUMMARY_FIELDS} }}
                  }}
                }}
                """,
                "PrimordialCaidoRequestSearch",
            ),
            (
                "requests",
                f"""
                query PrimordialCaidoRequestSearch($filter: HTTPQL, $limit: Int!) {{
                  requests(first: $limit, filter: $filter) {{
                    count {{ value }}
                    nodes {{ {self.REQUEST_SUMMARY_FIELDS} }}
                  }}
                }}
                """,
                "PrimordialCaidoRequestSearch",
            ),
        ]
        last_result: dict[str, object] | None = None
        for field_name, query, operation_name in attempts:
            attempt_variables = dict(variables)
            if field_name == "requests":
                attempt_variables.pop("offset", None)
            result = self.graphql(query, attempt_variables, operation_name=operation_name)
            last_result = result
            if not result.get("ok"):
                continue
            connection = result.get("data", {}).get(field_name) if isinstance(result.get("data"), dict) else None
            if not isinstance(connection, dict):
                continue
            return {
                "ok": True,
                "httpql": normalized_httpql,
                "query_field": field_name,
                "limit": selected_limit,
                "offset": selected_offset,
                "total": self._connection_count(connection),
                "requests": [self._normalize_request_summary(item) for item in connection.get("nodes", []) if isinstance(item, dict)],
            }
        return {
            "ok": False,
            "httpql": normalized_httpql,
            "error": self._graphql_error_message(last_result),
            "requests": [],
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
                return str(first.get("message") or first.get("code") or first.get("__typename") or first)
            return str(first)
        return "Caido GraphQL request failed."
