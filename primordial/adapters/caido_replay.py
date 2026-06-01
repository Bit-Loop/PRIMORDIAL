from __future__ import annotations

from primordial.adapters.caido_httpql import build_target_httpql
from primordial.adapters.caido_models import ParsedRawRequest
from primordial.adapters.caido_normalization import normalize_replay_session, normalize_request_summary
from primordial.adapters.caido_parsing import parse_raw_request
from primordial.adapters.caido_redaction import graphql_error_message


class CaidoReplayMixin:
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
            return {"ok": False, "parsed": parsed.as_payload(), "error": graphql_error_message(result)}
        session = result.get("data", {}).get("createReplaySession", {}).get("session") if isinstance(result.get("data"), dict) else None
        if not isinstance(session, dict):
            return {"ok": False, "parsed": parsed.as_payload(), "error": "Caido did not return a replay session."}
        return {
            "ok": True,
            "parsed": parsed.as_payload(),
            "session": normalize_replay_session(session),
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
        result = self.graphql(query, self._send_replay_variables(parsed, session_id), operation_name="PrimordialStartReplayTask")
        if not result.get("ok"):
            return {"ok": False, "parsed": parsed.as_payload(), "error": graphql_error_message(result)}
        payload = result.get("data", {}).get("startReplayTask") if isinstance(result.get("data"), dict) else None
        if not isinstance(payload, dict):
            return {"ok": False, "parsed": parsed.as_payload(), "error": "Caido did not return a replay task."}
        if payload.get("error"):
            return self._send_replay_error(parsed, payload)
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
                "request": normalize_request_summary(replay_entry.get("request"))
                if isinstance(replay_entry.get("request"), dict)
                else None,
            },
        }

    def build_target_httpql(self, terms: list[str], *, max_terms: int = 8) -> str:
        return build_target_httpql(terms, max_terms=max_terms)

    def parse_raw_request(self, raw_request: str, *, max_bytes: int = 262_144) -> ParsedRawRequest:
        return parse_raw_request(raw_request, max_bytes=max_bytes)

    def _send_replay_variables(self, parsed: ParsedRawRequest, session_id: str) -> dict[str, object]:
        return {
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

    def _send_replay_error(self, parsed: ParsedRawRequest, payload: dict[str, object]) -> dict[str, object]:
        return {
            "ok": False,
            "parsed": parsed.as_payload(),
            "error": graphql_error_message({"errors": [payload["error"]]}),
            "caido_error": payload["error"],
        }
