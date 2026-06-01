from __future__ import annotations

from primordial.app.runtime_deps import (
    caido_capture_evidence,
    caido_detail_error,
    caido_import_event,
    caido_import_response,
    caido_import_row,
    caido_request_payload,
    caido_scope_error,
    CaidoIntegrationService,
    EventRecord,
    EventType,
    selected_caido_request_ids,
)

class RuntimeCaidoMixin:
    def caido_status_payload(self, *, check_health: bool = False) -> dict[str, object]:
        if not self.credentials.get("caido", "graphql_url") or not self.credentials.get("caido", "api_token"):
            return CaidoIntegrationService(self.credentials, self.event_bus).status(check_health=False)
        return self.caido.status(check_health=check_health)

    def caido_httpql_presets(self, target: str | None = None) -> dict[str, object]:
        target_record = self._resolve_target_reference(target) if target else None
        targets = [target_record] if target_record else self.store.list_targets()
        target_rows = []
        presets = []
        for item in targets:
            if item is None:
                continue
            terms = self._caido_scope_terms(item)
            httpql = self.caido.build_target_httpql(terms)
            target_rows.append(
                {
                    "id": item.id,
                    "handle": item.handle,
                    "display_name": item.display_name,
                    "in_scope": item.in_scope,
                    "httpql": httpql,
                    "terms": terms,
                }
            )
        presets.extend(
            [
                {"id": "errors", "label": "Error responses", "httpql": "resp.code.gte:400"},
                {"id": "auth", "label": "Auth paths", "httpql": 'req.path.cont:"login" OR req.path.cont:"admin"'},
                {
                    "id": "tokens",
                    "label": "Token hints",
                    "httpql": 'resp.raw.cont:"api_key" OR resp.raw.cont:"secret" OR resp.raw.cont:"token"',
                },
            ]
        )
        return {"targets": target_rows, "presets": presets}

    def caido_search_requests(
        self,
        *,
        target: str | None = None,
        httpql: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, object]:
        target_record = self._resolve_target_reference(target) if target else self._resolve_target_reference(None)
        if target and target_record is None:
            raise ValueError("target not found")
        effective_httpql = (httpql or "").strip()
        if not effective_httpql:
            if target_record is not None:
                effective_httpql = self.caido.build_target_httpql(self._caido_scope_terms(target_record))
            else:
                terms: list[str] = []
                for item in self.store.list_targets():
                    terms.extend(self._caido_scope_terms(item))
                effective_httpql = self.caido.build_target_httpql(terms)
        result = self.caido.search_requests(effective_httpql, limit=limit, offset=offset)
        result["target"] = target_record.as_payload() if target_record else None
        result["presets"] = self.caido_httpql_presets()
        return result

    def caido_request_detail(self, request_id: str) -> dict[str, object]:
        return self.caido.request_detail(request_id)

    def caido_import_requests(
        self,
        *,
        target: str,
        request_ids: list[str],
        httpql: str = "",
    ) -> dict[str, object]:
        target_record = self._resolve_target_reference(target)
        if target_record is None:
            raise ValueError("target not found")
        if not target_record.in_scope:
            raise ValueError("target is not in scope")
        selected_ids = selected_caido_request_ids(request_ids)
        imported = []
        errors = []
        for request_id in selected_ids:
            detail = self.caido.request_detail(request_id)
            if not detail.get("ok"):
                errors.append(caido_detail_error(request_id, detail))
                continue
            request_payload = caido_request_payload(detail)
            host = str(request_payload.get("host") or "")
            if not self._caido_host_in_scope(target_record, host):
                errors.append(caido_scope_error(request_id, host))
                continue
            artifact = self._write_caido_capture_artifact(target_record, request_payload, httpql=httpql)
            self.store.insert_artifact(artifact)
            evidence = caido_capture_evidence(
                target=target_record,
                request_id=request_id,
                request_payload=request_payload,
                artifact=artifact,
                httpql=httpql,
            )
            self.store.insert_evidence(evidence)
            imported.append(caido_import_row(request_id, evidence, artifact))
        if imported:
            self.store.insert_event(caido_import_event(target_record, imported, httpql))
        return caido_import_response(
            target=target_record,
            imported=imported,
            errors=errors,
            records=self.records_payload(limit=50, target_id=target_record.id),
        )

    def caido_replay_draft(self, *, target: str, raw_request: str) -> dict[str, object]:
        target_record = self._resolve_target_reference(target)
        if target_record is None:
            raise ValueError("target not found")
        if not target_record.in_scope:
            raise ValueError("target is not in scope")
        parsed = self.caido.parse_raw_request(raw_request)
        if not self._caido_host_in_scope(target_record, parsed.host):
            raise ValueError(f"raw request host is not in target scope: {parsed.host}")
        draft = self.caido.create_replay_draft(raw_request)
        draft["target"] = target_record.as_payload()
        return draft

    def caido_replay_send(
        self,
        *,
        target: str,
        raw_request: str,
        confirmation: str | None = None,
        session_id: str | None = None,
    ) -> dict[str, object]:
        target_record = self._resolve_target_reference(target)
        if target_record is None:
            raise ValueError("target not found")
        if not target_record.in_scope:
            raise ValueError("target is not in scope")
        parsed = self.caido.parse_raw_request(raw_request)
        if not self._caido_host_in_scope(target_record, parsed.host):
            raise ValueError(f"raw request host is not in target scope: {parsed.host}")
        if str(confirmation or "").strip() != parsed.raw_sha256:
            raise ValueError("same-session replay confirmation is required")
        selected_session_id = str(session_id or "").strip()
        draft: dict[str, object] | None = None
        if not selected_session_id:
            draft = self.caido.create_replay_draft(raw_request)
            if not draft.get("ok"):
                return {"ok": False, "target": target_record.as_payload(), "parsed": parsed.as_payload(), "error": draft.get("error")}
            session = draft.get("session") if isinstance(draft.get("session"), dict) else {}
            selected_session_id = str(session.get("id") or "")
        if not selected_session_id:
            raise ValueError("caido replay session_id is required")
        result = self.caido.send_replay(raw_request, session_id=selected_session_id)
        result["target"] = target_record.as_payload()
        result["session_id"] = selected_session_id
        if draft is not None:
            result["draft"] = draft.get("session")
        if result.get("ok"):
            task = result.get("task") if isinstance(result.get("task"), dict) else {}
            self.store.insert_event(
                EventRecord(
                    type=EventType.CAIDO_REPLAY_SENT,
                    summary=f"Caido Replay sent one request to {parsed.host}",
                    target_id=target_record.id,
                    metadata={
                        "raw_sha256": parsed.raw_sha256,
                        "method": parsed.method,
                        "host": parsed.host,
                        "port": parsed.port,
                        "path": parsed.path,
                        "is_tls": parsed.is_tls,
                        "caido_session_id": selected_session_id,
                        "caido_task_id": task.get("id") or "",
                        "caido_replay_entry_id": task.get("replay_entry_id") or "",
                        "raw_persisted": False,
                        "same_session_confirmation": True,
                    },
                )
            )
        return result
