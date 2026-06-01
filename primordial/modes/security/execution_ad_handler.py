from __future__ import annotations

from primordial.modes.security.execution_common import *


class PrimitiveAdHandlerMixin:
    def _handle_ad_enumeration(self, task: Task, context: ContextSlice) -> TaskExecutionResult:
        result = TaskExecutionResult(summary="AD enumeration completed")
        target = self.store.get_target(task.target_id)
        if not target:
            result.success = False
            result.error = "target not found"
            return result

        assets = self._target_scope_assets(target)
        host = self._preferred_network_host(assets)
        if not host:
            result.success = False
            result.error = "no host or IP asset is available for AD enumeration"
            return result

        command_results = self._run_ad_enumeration_commands(host)
        if not command_results:
            result.success = False
            result.error = "no AD enumeration commands could be executed"
            return result

        parsed = self._parse_ad_enumeration(command_results)
        artifact = self._write_artifact(
            task,
            target.id,
            f"ad-enumeration-{self._safe_artifact_fragment(host)}",
            {
                "target": target.as_payload(),
                "host": host,
                "command_results": command_results,
                "parsed": parsed,
            },
        )
        result.artifacts.append(artifact)
        evidence = EvidenceRecord(
            target_id=target.id,
            task_id=task.id,
            type=EvidenceType.TOOL_OUTPUT,
            title=f"AD enumeration: {target.handle}",
            summary=self._summarize_ad_enumeration(host, parsed),
            source_ref=artifact.id,
            verification_status=VerificationStatus.VERIFIED,
            confidence=0.78,
            freshness=0.96,
            artifact_path=artifact.path,
            metadata={
                "kind": "ad_enumeration",
                "host": host,
                "ldap_rootdse": parsed["ldap_rootdse"],
                "smb_shares": parsed["smb_shares"],
                "rpc_users": parsed["rpc_users"],
                "rpc_groups": parsed["rpc_groups"],
                "executed_tools": [item["tool"] for item in command_results if item.get("executed")],
            },
        )
        result.evidence.append(evidence)
        result.notes.append(
            Note(
                target_id=target.id,
                task_id=task.id,
                title="Anonymous AD enumeration summary",
                body=self._build_ad_enumeration_note(host, parsed, command_results),
                confidence=0.76,
                freshness=0.92,
                metadata={"phase": task.phase.value, "host": host},
            )
        )
        if parsed["smb_shares"] or parsed["rpc_users"] or parsed["ldap_rootdse"]:
            result.interests.append(
                Interest(
                    target_id=target.id,
                    title="AD inventory follow-up candidates",
                    summary=(
                        "Anonymous AD-facing enumeration produced structured inventory. "
                        "Review shares, domain metadata, and discovered principals before any credentialed or exploitative step."
                    ),
                    evidence_refs=[evidence.id],
                    status=InterestStatus.OPEN,
                    confidence=0.74,
                    metadata={
                        "origin_task": task.id,
                        "class": "ad_inventory",
                        "host": host,
                        "share_count": len(parsed["smb_shares"]),
                        "rpc_user_count": len(parsed["rpc_users"]),
                    },
                )
            )
        result.events.append(
            EventRecord(
                type=EventType.TASK_SUCCEEDED,
                summary=f"AD enumeration completed for {target.handle}",
                target_id=target.id,
                task_id=task.id,
                metadata={
                    "host": host,
                    "share_count": len(parsed["smb_shares"]),
                    "rpc_user_count": len(parsed["rpc_users"]),
                },
            )
        )
        return result
