from __future__ import annotations

from primordial.app.runtime_deps import (
    ipaddress,
    json,
    json_ready,
    re,
    Target,
)

class RuntimeOperatorContextMixin:
    def _resolve_operator_chat_target(self, target: str | None, question: str) -> Target | None:
        target_record = self._resolve_target_reference(target)
        if target_record is not None:
            return target_record
        lowered = question.lower()
        for candidate in self.store.list_targets():
            identifiers = [candidate.handle, candidate.display_name, str(candidate.metadata.get("active_ip") or "")]
            identifiers.extend(asset.asset for asset in self.store.list_scope_assets(candidate.id))
            for identifier in identifiers:
                normalized = str(identifier or "").strip().lower()
                if not normalized:
                    continue
                if re.search(rf"(?<![a-z0-9_.:-]){re.escape(normalized)}(?![a-z0-9_.:-])", lowered):
                    return candidate
        return None

    def _operator_state_update_or_direct_answer(self, question: str, target: Target | None) -> str | None:
        lowered = question.lower()
        ips = self._extract_ip_addresses(question)
        is_ip_question = "ip" in lowered and any(term in lowered for term in ("using", "target", "what", "which", "current"))
        is_ip_update = bool(ips) and any(
            term in lowered
            for term in (
                "should be using",
                "use ",
                "using ",
                "target is",
                "ip is",
                "set ip",
                "change ip",
                "update ip",
            )
        )
        if is_ip_update:
            if not target:
                return (
                    "**Target IP Update Blocked**\n"
                    "- I found an IP correction, but no target was selected. Re-send it with `--target <handle>` "
                    "or select a target in the GUI/web app."
                )
            return self._apply_operator_active_ip(target, ips[-1])
        if is_ip_question:
            return self._target_ip_answer(target)
        return None

    def _extract_ip_addresses(self, value: str) -> list[str]:
        ips: list[str] = []
        for match in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", value):
            try:
                parsed = ipaddress.ip_address(match)
            except ValueError:
                continue
            if parsed.version == 4 and match not in ips:
                ips.append(match)
        return ips

    def _validated_optional_ip(self, value: str | None) -> str:
        candidate = str(value or "").strip()
        if not candidate:
            return ""
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError as exc:
            raise ValueError(f"invalid IP address: {candidate}") from exc

    def _apply_operator_active_ip(self, target: Target, ip: str) -> str:
        previous_ip = str(target.metadata.get("active_ip") or "").strip()
        refreshed_target = self.set_target_active_ip(target, ip, source="operator_chat")
        assets = self.store.list_scope_assets(refreshed_target.id)
        ip_assets = [asset.asset for asset in assets if asset.asset_type == "ip"]
        old_line = f"\n- Previous active IP: `{previous_ip}`" if previous_ip and previous_ip != ip else ""
        return (
            "**Target IP Updated**\n"
            f"- Target: `{target.handle}`\n"
            f"- Active operator-confirmed IP: `{ip}`\n"
            f"- Configured IP scope assets: {', '.join(f'`{item}`' for item in ip_assets) or 'none'}"
            f"{old_line}\n"
            "- Prior evidence that references older IPs is historical until recon/service discovery reruns for this active IP."
        )

    def _target_ip_answer(self, target: Target | None) -> str:
        if not target:
            return (
                "**Target IP**\n"
                "- No target is selected. Ask with a registered target handle, for example `--target <handle>`, "
                "or select a target in the GUI/web app."
            )
        assets = self.store.list_scope_assets(target.id)
        active_ip = str(target.metadata.get("active_ip") or "").strip()
        ip_assets = [asset.asset for asset in assets if asset.asset_type == "ip"]
        host_assets = [asset.asset for asset in assets if asset.asset_type in {"hostname", "webapp"}]
        historical_ips = self._historical_evidence_ips(target.id)
        lines = [
            "**Target IP**",
            f"- Target: `{target.handle}`",
            f"- Active operator-confirmed IP: `{active_ip}`" if active_ip else "- Active operator-confirmed IP: not set",
            f"- Configured IP scope assets: {', '.join(f'`{item}`' for item in ip_assets) or 'none'}",
            f"- Host/web assets: {', '.join(f'`{item}`' for item in host_assets) or 'none'}",
        ]
        if historical_ips:
            lines.append(
                f"- Historical evidence references: {', '.join(f'`{item}`' for item in historical_ips[:8])}"
            )
        if active_ip and historical_ips and any(item != active_ip for item in historical_ips):
            lines.append("- Any non-active historical IPs should be treated as stale until refreshed recon completes.")
        return "\n".join(lines)

    def _historical_evidence_ips(self, target_id: str) -> list[str]:
        seen: list[str] = []
        for item in self.store.list_evidence(target_id=target_id, limit=100):
            for ip in self._extract_ip_addresses(json.dumps(item.as_payload())):
                if ip not in seen:
                    seen.append(ip)
        return seen

    def _build_operator_prompt(self, question: str, target_id: str | None) -> str:
        target = self.store.get_target(target_id) if target_id else None
        rag_context_pack = self._rag_context_pack_payload(question, target_id)
        rag_context = rag_context_pack.get("chunks", []) if isinstance(rag_context_pack.get("chunks"), list) else []
        snapshot = {
            "operator_question": question,
            "active_session": (
                self.store.get_active_session().as_payload()
                if self.store.get_active_session()
                else None
            ),
            "current_target": target.as_payload() if target else None,
            "dashboard_counts": self.store.count_all(),
            "scope": self.scope_payload(),
            "recent_tasks": [item.as_payload() for item in self.store.list_tasks(target_id=target_id, limit=10)],
            "recent_evidence": [
                item.as_payload() for item in self.store.list_evidence(target_id=target_id, limit=10)
            ],
            "recent_notes": [item.as_payload() for item in self.store.list_notes(target_id=target_id, limit=8)],
            "recent_interests": [
                item.as_payload() for item in self.store.list_interests(target_id=target_id, limit=8)
            ],
            "recent_findings": [
                item.as_payload() for item in self.store.list_findings(target_id=target_id, limit=6)
            ],
            "recent_events": [item.as_payload() for item in self.store.list_events(limit=12)],
            "recent_operator_messages": [
                item.as_payload()
                for item in reversed(self.store.list_operator_messages(target_id=target_id, limit=8))
                if item.role != "assistant" or not self._operator_answer_violates_contract(item.body)
            ],
            "credentials_status": self.credentials_payload(),
            "available_skills": self.skills_payload(include_body=False),
            "permanent_findings_context": (
                self.findings_context.payload_for_target(target, include_guidance=True)
                if target
                else None
            ),
            "rag_context": rag_context,
            "rag_context_pack": rag_context_pack,
        }
        rendered = json.dumps(json_ready(snapshot), indent=2, sort_keys=True)
        if len(rendered) > 24000:
            rendered = rendered[:24000] + "\n...TRUNCATED_TO_KEEP_OPERATOR_CHAT_BOUNDED..."
        digest = self._build_operator_state_digest(target_id)
        return (
            "Answer the operator question using this bounded Primordial runtime snapshot.\n"
            "Do not assume hidden state outside this snapshot.\n\n"
            "Required answer contract:\n"
            "- Use concise markdown with these headings when relevant: Facts, Blockers, Next Actions.\n"
            "- Every factual claim must be supported by a record in the snapshot.\n"
            "- RAG context is advisory source material, not target evidence, approval, scope, or execution authority.\n"
            "- If you use RAG, cite rag:<chunk_id>; never present rag:<chunk_id> as evidence:<id>.\n"
            "- If user/root flags are not present in evidence, say they have not been obtained.\n"
            "- If current production primitives are insufficient, say exactly which primitive or operator input is missing.\n"
            "- Do not say evidence is implied; use the exact evidence, task, note, or primitive names supplied.\n\n"
            "Deterministic state digest:\n"
            f"{digest}\n\n"
            "Loaded runtime skills:\n"
            f"{self.skills.context_digest() or 'none'}\n\n"
            "Permanent findings context digest:\n"
            f"{self.findings_context.context_digest(target) or 'none'}\n\n"
            "Full structured snapshot:\n"
            f"{rendered}"
        )

    def _build_operator_state_digest(self, target_id: str | None) -> str:
        target = self.store.get_target(target_id) if target_id else None
        lines = []
        if target:
            lines.append(f"Target: {target.display_name} handle={target.handle} profile={target.profile.value}")
            if target.metadata.get("active_ip"):
                lines.append(
                    f"Active IP: {target.metadata.get('active_ip')} generation={target.metadata.get('active_ip_generation')}"
                )
            methodology_state = self._live_methodology_state_payload(target)
            if isinstance(methodology_state, dict) and methodology_state:
                lines.append(
                    "Methodology state: "
                    f"phase={methodology_state.get('phase')} "
                    f"subphase={methodology_state.get('subphase')} "
                    f"completion={methodology_state.get('completion')}"
                )
                if methodology_state.get("no_progress_reason"):
                    lines.append(f"No-progress reason: {methodology_state.get('no_progress_reason')}")
                if methodology_state.get("next_unblock_action"):
                    lines.append(f"Next unblock action: {methodology_state.get('next_unblock_action')}")
        active_generation = self._target_active_generation(target)
        tasks = self.store.list_tasks(target_id=target_id, limit=12)
        raw_evidence = self.store.list_evidence(target_id=target_id, limit=30)
        raw_notes = self.store.list_notes(target_id=target_id, limit=20)
        raw_interests = self.store.list_interests(target_id=target_id, limit=20)
        raw_findings = self.store.list_findings(target_id=target_id, limit=12)
        evidence = [item for item in raw_evidence if self._record_matches_active_generation(item, active_generation)][:12]
        notes = [item for item in raw_notes if self._record_matches_active_generation(item, active_generation)][:8]
        interests = [item for item in raw_interests if self._record_matches_active_generation(item, active_generation)][:8]
        findings = [item for item in raw_findings if self._record_matches_active_generation(item, active_generation)][:8]
        primitives = self.store.list_primitives()
        lines.append("Recent tasks:")
        lines.extend(f"- {task.kind.value} status={task.status.value} model={task.provider_model}" for task in tasks)
        if active_generation is not None:
            stale_evidence_count = len(raw_evidence) - len([item for item in raw_evidence if self._record_matches_active_generation(item, active_generation)])
            stale_interest_count = len(raw_interests) - len(
                [item for item in raw_interests if self._record_matches_active_generation(item, active_generation)]
            )
            lines.append(
                f"Historical records excluded from current reasoning: evidence={stale_evidence_count}, interests={stale_interest_count}"
            )
        lines.append("Current-generation evidence:")
        lines.extend(f"- {item.id}: {item.title} :: {item.summary}" for item in evidence)
        lines.append("Current-generation notes:")
        lines.extend(f"- {item.title}: {item.body[:500]}" for item in notes)
        lines.append("Current-generation interests:")
        lines.extend(f"- {item.title}: {item.summary}" for item in interests)
        if findings:
            lines.append("Current-generation findings:")
            lines.extend(f"- {finding.title}: {finding.summary}" for finding in findings)
        else:
            lines.append("Current-generation findings: none")
        flag_hits = [
            item.id
            for item in evidence
            if any(token in json.dumps(item.as_payload()).lower() for token in ("user.txt", "root.txt", "flag{", "htb{"))
        ]
        lines.append(f"Flag evidence IDs: {', '.join(flag_hits) if flag_hits else 'none'}")
        primitive_names = ", ".join(sorted(primitive.name for primitive in primitives))
        lines.append(f"Registered primitives: {primitive_names}")
        return "\n".join(lines)

    def _live_methodology_state_payload(self, target: Target | None) -> dict[str, object]:
        if target is None:
            return {}
        try:
            state = self.workflow.preview_target_state(target)
        except Exception:  # noqa: BLE001 - status surfaces must degrade safely
            cached = target.metadata.get("methodology_state", {})
            return cached if isinstance(cached, dict) else {}
        payload = state.as_payload()
        payload["planner_version"] = 2
        return payload

    def _target_active_generation(self, target: Target | None) -> str | None:
        if target is None or target.metadata.get("active_ip_generation") is None:
            return None
        return str(target.metadata["active_ip_generation"])

    def _record_matches_active_generation(self, record: object, active_generation: str | None) -> bool:
        if active_generation is None:
            return True
        metadata = getattr(record, "metadata", {})
        if not isinstance(metadata, dict):
            return False
        return str(metadata.get("active_ip_generation", "")) == active_generation
