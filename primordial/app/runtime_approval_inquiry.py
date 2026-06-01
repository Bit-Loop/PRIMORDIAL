from __future__ import annotations

from primordial.app.runtime_deps import (
    EventRecord,
    EventType,
    EvidenceRecord,
    json,
    json_ready,
    OperatorMessage,
    re,
    Target,
    Task,
)

class RuntimeApprovalInquiryMixin:
    def ask_approval_inquiry(self, task_id: str, message: str) -> dict[str, object]:
        question = message.strip()
        if not question:
            raise ValueError("message is required")
        task = self.store.get_task(task_id)
        if task is None:
            raise ValueError(f"task not found: {task_id}")
        target = self.store.get_target(task.target_id) if task.target_id else None
        operator_message = OperatorMessage(
            role="operator",
            body=question,
            target_id=target.id if target else None,
            metadata={
                "approval_task_id": task.id,
                "approval_inquiry": True,
            },
        )
        self.store.insert_operator_message(operator_message)
        self._write_operator_chat_log(operator_message)
        self.store.insert_event(
            EventRecord(
                type=EventType.OPERATOR_MESSAGE,
                summary="Approval inquiry recorded",
                target_id=operator_message.target_id,
                task_id=task.id,
                metadata={"message_id": operator_message.id, "approval_task_id": task.id},
            )
        )

        evidence_refs = self._approval_evidence_refs(task)
        evidence_records = [record for ref in evidence_refs if (record := self.store.get_evidence(ref)) is not None]
        answer = self._deterministic_approval_inquiry_answer(
            question,
            task=task,
            target=target,
            evidence_refs=evidence_refs,
            evidence_records=evidence_records,
        )
        assistant_message = OperatorMessage(
            role="assistant",
            body=answer,
            target_id=target.id if target else None,
            model="deterministic-approval",
            metadata={
                "approval_task_id": task.id,
                "approval_inquiry": True,
                "evidence_refs": evidence_refs,
            },
        )
        self.store.insert_operator_message(assistant_message)
        self._write_operator_chat_log(assistant_message)
        self.store.insert_event(
            EventRecord(
                type=EventType.OPERATOR_AI_RESPONSE,
                summary="Approval inquiry answered",
                target_id=assistant_message.target_id,
                task_id=task.id,
                metadata={
                    "message_id": assistant_message.id,
                    "model": "deterministic-approval",
                    "approval_task_id": task.id,
                    "evidence_refs": evidence_refs,
                },
            )
        )
        return {
            "ok": True,
            "model": "deterministic-approval",
            "question": operator_message.as_payload(),
            "answer": assistant_message.as_payload(),
            "task": task.as_payload(),
            "target": target.as_payload() if target else None,
            "evidence_refs": evidence_refs,
            "evidence": [record.as_payload() for record in evidence_records],
        }

    def _approval_evidence_refs(self, task: Task) -> list[str]:
        refs: list[str] = []

        def add(value: object) -> None:
            if isinstance(value, str):
                if value.startswith("evidence_") and value not in refs:
                    refs.append(value)
                return
            if isinstance(value, list | tuple | set):
                for item in value:
                    add(item)
                return
            if isinstance(value, dict):
                for key, item in value.items():
                    if "evidence" in str(key).lower():
                        add(item)
                    elif isinstance(item, dict | list | tuple | set):
                        add(item)

        add(task.evidence_refs)
        add(task.metadata)
        return refs

    def _deterministic_approval_inquiry_answer(
        self,
        question: str,
        *,
        task: Task,
        target: Target | None,
        evidence_refs: list[str],
        evidence_records: list[EvidenceRecord],
    ) -> str:
        lowered = question.lower()
        target_label = target.handle if target else "global"
        primitive = task.metadata.get("primitive_hint") or task.metadata.get("primitive") or task.kind.value
        intent = self.active_operator_intent().id
        active_generation = self._target_active_generation(target)
        current_records = [
            item for item in evidence_records if self._record_matches_active_generation(item, active_generation)
        ]
        stale_records = [item for item in evidence_records if item not in current_records]

        lines: list[str] = []
        if any(term in lowered for term in ("exact request", "show me", "request", "what is this")):
            lines.extend(
                [
                    "**Approval Request**",
                    f"- Task: `{task.id}`",
                    f"- Title: {task.title}",
                    f"- Kind: `{task.kind.value}`",
                    f"- Target: `{target_label}`",
                    f"- Primitive/request hint: `{primitive}`",
                    f"- Status: `{task.status.value}`; approval required: `{task.requires_approval}`",
                    f"- Risk: `{task.risk_tier.value}`; priority: `{task.priority}`",
                    f"- Active Operator Intent: `{intent}`",
                    f"- Summary: {task.summary}",
                    f"- Required capabilities: {', '.join(task.required_capabilities) if task.required_capabilities else 'none declared'}",
                    f"- Attached evidence refs: {', '.join(f'`{ref}`' for ref in evidence_refs) if evidence_refs else 'none'}",
                    f"- Inspect raw task: `/api/inspect/task/{task.id}`",
                ]
            )
            if task.metadata:
                lines.append(f"- Metadata keys: {', '.join(sorted(str(key) for key in task.metadata.keys()))}")
        elif any(term in lowered for term in ("evidence", "backs", "proof", "why", "support")):
            lines.extend(
                [
                    "**Evidence Check**",
                    f"- Task: `{task.id}`",
                    f"- Attached evidence refs: {', '.join(f'`{ref}`' for ref in evidence_refs) if evidence_refs else 'none'}",
                    f"- Current-generation attached evidence: {len(current_records)}",
                    f"- Stale-generation attached evidence: {len(stale_records)}",
                ]
            )
            if not evidence_refs:
                lines.append("- No evidence refs are attached to this approval request. Treat it as unsupported until the planner supplies current evidence.")
            missing = [ref for ref in evidence_refs if self.store.get_evidence(ref) is None]
            if missing:
                lines.append("- Missing evidence records: " + ", ".join(f"`{ref}`" for ref in missing))
            for item in current_records[:8]:
                lines.append(
                    f"- CURRENT `{item.id}` {item.title}: {item.summary} "
                    f"(confidence={item.confidence:.2f}, freshness={item.freshness:.2f})"
                )
            for item in stale_records[:5]:
                generation = item.metadata.get("active_ip_generation", "unknown")
                lines.append(f"- STALE `{item.id}` generation={generation} {item.title}: {item.summary}")
        else:
            lines.extend(
                [
                    "**Approval Inquiry**",
                    f"- Task `{task.id}` is waiting on `{task.kind.value}` for `{target_label}`.",
                    f"- Ask `show me the exact request` for the request packet.",
                    f"- Ask `what evidence backs this?` for attached evidence and current/stale generation status.",
                    "- Inquiry messages do not approve, deny, or modify the task.",
                ]
            )
        return "\n".join(lines)

    def export_operator_chat_logs(self) -> int:
        exported = 0
        for message in self.store.list_operator_messages(limit=10000):
            if self._write_operator_chat_log(message):
                exported += 1
        return exported

    def _write_operator_chat_log(self, message: OperatorMessage) -> bool:
        target = self.store.get_target(message.target_id) if message.target_id else None
        target_fragment = self._safe_log_fragment(target.handle if target else "global")
        day_dir = self.config.chat_logs_dir / message.created_at.strftime("%Y-%m-%d")
        day_dir.mkdir(parents=True, exist_ok=True)
        timestamp = message.created_at.strftime("%Y%m%dT%H%M%S%fZ")
        path = day_dir / f"{timestamp}_{message.id}_{message.role}_{target_fragment}.json"
        if path.exists():
            return False
        payload = {
            "id": message.id,
            "created_at": message.created_at.isoformat(),
            "role": message.role,
            "model": message.model,
            "target": target.as_payload() if target else None,
            "body": message.body,
            "metadata": json_ready(message.metadata),
        }
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return True

    def _safe_log_fragment(self, value: str) -> str:
        fragment = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
        return fragment.strip("._-")[:80] or "global"
