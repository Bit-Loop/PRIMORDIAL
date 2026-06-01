from __future__ import annotations

from primordial.modes.security.execution_common import *


class PrimitiveCredentialHandlerMixin:
    def _handle_credentialed_access_check(self, task: Task, context: ContextSlice) -> TaskExecutionResult:
        blocked = self._require_intent(task)
        if blocked is not None:
            return blocked
        result = TaskExecutionResult(summary="credentialed access check completed")
        target = self.store.get_target(task.target_id)
        if not target:
            result.success = False
            result.error = "target not found"
            return result

        username = self.credentials.get("known", "username")
        password = self.credentials.get("known", "password")
        domain = self.credentials.get("known", "domain")
        if not username or not password:
            result.success = False
            result.error = "known username and password are required for credentialed access checks"
            return result

        assets = self._target_scope_assets(target)
        host = self._preferred_network_host(assets)
        if not host:
            result.success = False
            result.error = "no host or IP asset is available for credentialed access checks"
            return result
        surface = task.metadata.get("credentialed_access_surface", {})
        if isinstance(surface, dict) and surface.get("eligible") is False:
            result.success = False
            result.error = str(surface.get("blocked_reason") or "credentialed access surface is not eligible")
            return result

        command_results, auth_results, flag_hits = self._run_credentialed_access_commands(
            task,
            target.id,
            host,
            username,
            password,
            domain,
            protocols=self._credentialed_access_protocols(task),
        )
        artifact = self._write_artifact(
            task,
            target.id,
            f"credentialed-access-{self._safe_artifact_fragment(host)}",
            {
                "target": target.as_payload(),
                "host": host,
                "username": username,
                "domain": domain,
                "auth_results": auth_results,
                "flag_hits": flag_hits,
                "command_results": command_results,
                "guardrails": {
                    "password_redacted": True,
                    "uses_configured_known_credentials": True,
                    "winrm_password_arg_tools_require_env_opt_in": True,
                },
            },
        )
        result.artifacts.append(artifact)
        verified_access = any(item.get("valid") for item in auth_results)
        evidence = EvidenceRecord(
            target_id=target.id,
            task_id=task.id,
            type=EvidenceType.TOOL_OUTPUT,
            title=f"Credentialed access check: {target.handle}",
            summary=self._summarize_credentialed_access(auth_results, flag_hits),
            source_ref=artifact.id,
            verification_status=VerificationStatus.VERIFIED if verified_access else VerificationStatus.REJECTED,
            confidence=0.86 if verified_access else 0.7,
            freshness=0.9,
            artifact_path=artifact.path,
            metadata={
                "kind": "credentialed_access_check",
                "host": host,
                "username": username,
                "domain": domain,
                "auth_results": auth_results,
                "flag_hits": flag_hits,
                "credential_namespace": "known",
                "protocols": sorted(self._credentialed_access_protocols(task)),
            },
        )
        result.evidence.append(evidence)
        result.notes.append(
            Note(
                target_id=target.id,
                task_id=task.id,
                title="Credentialed access check summary",
                body=self._build_credentialed_access_note(host, username, domain, auth_results, flag_hits, command_results),
                confidence=0.82 if verified_access else 0.68,
                freshness=0.88,
                metadata={"phase": task.phase.value, "flag_count": len(flag_hits)},
            )
        )
        if verified_access:
            result.interests.append(
                Interest(
                    target_id=target.id,
                    title="Credentialed foothold available",
                    summary="Configured known credentials authenticated successfully. Post-foothold verification and gated LPE review are now eligible.",
                    evidence_refs=[evidence.id],
                    status=InterestStatus.VERIFIED,
                    confidence=0.84,
                    metadata={"origin_task": task.id, "class": "credentialed_access", "flag_count": len(flag_hits)},
                )
            )
        result.events.append(
            EventRecord(
                type=EventType.TASK_SUCCEEDED,
                summary=f"Credentialed access check completed for {target.handle}",
                target_id=target.id,
                task_id=task.id,
                metadata={"valid_access": verified_access, "flag_count": len(flag_hits)},
            )
        )
        return result
