from __future__ import annotations

from primordial.modes.security.execution_common import *


class PrimitiveKerberosHandlerMixin:
    def _handle_kerberos_user_discovery(self, task: Task, context: ContextSlice) -> TaskExecutionResult:
        blocked = self._require_intent(task)
        if blocked is not None:
            return blocked
        result = TaskExecutionResult(summary="Kerberos user discovery completed")
        target = self.store.get_target(task.target_id)
        if not target:
            result.success = False
            result.error = "target not found"
            return result

        host = self._preferred_network_host(self._target_scope_assets(target))
        if not host:
            result.success = False
            result.error = "no host or IP asset is available for Kerberos user discovery"
            return result

        base_dn = self._default_naming_context(target.id)
        domain = self._domain_from_base_dn(base_dn) or self._domain_from_target(target.handle)
        command_results = self._run_kerberos_user_discovery_commands(host, base_dn)
        parsed = self._parse_kerberos_user_discovery(command_results, domain)
        evidence = self._append_kerberos_user_evidence(task, target, result, host, domain, base_dn, command_results, parsed)
        self._append_kerberos_user_followups(task, target, result, evidence, host, parsed)
        return result

    def _handle_kerberos_attack_check(self, task: Task, context: ContextSlice) -> TaskExecutionResult:
        blocked = self._require_intent(task)
        if blocked is not None:
            return blocked
        result = TaskExecutionResult(summary="Kerberos attack-path checks completed")
        target = self.store.get_target(task.target_id)
        if not target:
            result.success = False
            result.error = "target not found"
            return result

        inputs = self._kerberos_attack_inputs(task, target, result)
        if inputs is None:
            return result
        host, users, spn_candidates, domain, requested_checks = inputs
        command_results = self._run_kerberos_attack_check_commands(task, target.id, host, domain, users, requested_checks)
        asrep_hashes = self._parse_asrep_hashes(command_results)
        retained_spn_candidates = spn_candidates if "kerberoast" in requested_checks else []
        evidence = self._append_kerberos_attack_evidence(
            task,
            target,
            result,
            host,
            domain,
            users,
            retained_spn_candidates,
            requested_checks,
            command_results,
            asrep_hashes,
        )
        self._append_kerberos_attack_followups(task, target, result, evidence, asrep_hashes, retained_spn_candidates)
        return result

    def _append_kerberos_user_evidence(
        self,
        task: Task,
        target,
        result: TaskExecutionResult,
        host: str,
        domain: str,
        base_dn: str,
        command_results: list[dict[str, object]],
        parsed: dict[str, object],
    ) -> EvidenceRecord:
        artifact = self._write_artifact(
            task,
            target.id,
            f"kerberos-user-discovery-{self._safe_artifact_fragment(host)}",
            {"target": target.as_payload(), "host": host, "domain": domain, "base_dn": base_dn, "command_results": command_results, "parsed": parsed},
        )
        result.artifacts.append(artifact)
        evidence = EvidenceRecord(
            target_id=target.id,
            task_id=task.id,
            type=EvidenceType.TOOL_OUTPUT,
            title=f"Kerberos user discovery: {target.handle}",
            summary=self._summarize_kerberos_user_discovery(host, parsed),
            source_ref=artifact.id,
            verification_status=VerificationStatus.VERIFIED if parsed["users"] else VerificationStatus.PARTIAL,
            confidence=0.78 if parsed["users"] else 0.62,
            freshness=0.95,
            artifact_path=artifact.path,
            metadata={
                "kind": "kerberos_user_discovery",
                "host": host,
                "domain": domain,
                "base_dn": base_dn,
                "users": parsed["users"],
                "spn_candidates": parsed["spn_candidates"],
                "executed_tools": [item["tool"] for item in command_results if item.get("executed")],
            },
        )
        result.evidence.append(evidence)
        result.notes.append(
            Note(
                target_id=target.id,
                task_id=task.id,
                title="Kerberos user discovery summary",
                body=self._build_kerberos_user_discovery_note(host, domain, parsed, command_results),
                confidence=0.76 if parsed["users"] else 0.62,
                freshness=0.92,
                metadata={"phase": task.phase.value, "host": host, "user_count": len(parsed["users"])},
            )
        )
        return evidence

    def _append_kerberos_user_followups(
        self,
        task: Task,
        target,
        result: TaskExecutionResult,
        evidence: EvidenceRecord,
        host: str,
        parsed: dict[str, object],
    ) -> None:
        if parsed["users"] or parsed["spn_candidates"]:
            result.interests.append(
                Interest(
                    target_id=target.id,
                    title="Kerberos principal follow-up candidates",
                    summary=(
                        "Kerberos/LDAP user discovery produced principals or SPN-bearing accounts. "
                        "AS-REP and Kerberoast checks remain bounded verification steps; no cracking was performed."
                    ),
                    evidence_refs=[evidence.id],
                    status=InterestStatus.OPEN,
                    confidence=0.76,
                    metadata={
                        "origin_task": task.id,
                        "class": "kerberos_principals",
                        "user_count": len(parsed["users"]),
                        "spn_candidate_count": len(parsed["spn_candidates"]),
                    },
                )
            )
        result.events.append(
            EventRecord(
                type=EventType.TASK_SUCCEEDED,
                summary=f"Kerberos user discovery found {len(parsed['users'])} user principal(s)",
                target_id=target.id,
                task_id=task.id,
                metadata={"user_count": len(parsed["users"]), "spn_candidate_count": len(parsed["spn_candidates"])},
            )
        )

    def _kerberos_attack_inputs(
        self,
        task: Task,
        target,
        result: TaskExecutionResult,
    ) -> tuple[str, list[str], list[dict[str, object]], str, set[str]] | None:
        host = self._preferred_network_host(self._target_scope_assets(target))
        users = self._discovered_kerberos_users(target.id)
        spn_candidates = self._discovered_spn_candidates(target.id)
        domain = self._kerberos_domain(target.id, target.handle)
        requested_checks = self._requested_kerberos_checks(task)
        if not host:
            result.success = False
            result.error = "Kerberos attack checks require a host"
            return None
        if "asrep_roast" in requested_checks and not users:
            result.success = False
            result.error = "AS-REP roast checks require discovered user principals"
            return None
        if "kerberoast" in requested_checks and not spn_candidates:
            result.success = False
            result.error = "Kerberoast checks require discovered SPN candidates"
            return None
        return host, users, spn_candidates, domain, requested_checks

    def _append_kerberos_attack_evidence(
        self,
        task: Task,
        target,
        result: TaskExecutionResult,
        host: str,
        domain: str,
        users: list[str],
        retained_spn_candidates: list[dict[str, object]],
        requested_checks: set[str],
        command_results: list[dict[str, object]],
        asrep_hashes: list[dict[str, object]],
    ) -> EvidenceRecord:
        artifact = self._write_artifact(
            task,
            target.id,
            f"kerberos-attack-check-{self._safe_artifact_fragment(host)}",
            self._kerberos_attack_artifact_payload(target, host, domain, users, retained_spn_candidates, requested_checks, command_results, asrep_hashes),
        )
        result.artifacts.append(artifact)
        evidence = EvidenceRecord(
            target_id=target.id,
            task_id=task.id,
            type=EvidenceType.TOOL_OUTPUT,
            title=f"Kerberos attack-path check: {target.handle}",
            summary=self._summarize_kerberos_attack_check(asrep_hashes, retained_spn_candidates, command_results),
            source_ref=artifact.id,
            verification_status=VerificationStatus.PARTIAL if asrep_hashes or retained_spn_candidates else VerificationStatus.REJECTED,
            confidence=0.78 if asrep_hashes or retained_spn_candidates else 0.62,
            freshness=0.9,
            artifact_path=artifact.path,
            metadata=self._kerberos_attack_metadata(host, domain, users, retained_spn_candidates, requested_checks, asrep_hashes),
        )
        result.evidence.append(evidence)
        result.notes.append(
            Note(
                target_id=target.id,
                task_id=task.id,
                title="Kerberos attack-path check summary",
                body=self._build_kerberos_attack_check_note(domain, users, asrep_hashes, retained_spn_candidates, command_results),
                confidence=0.76,
                freshness=0.88,
                metadata={"phase": task.phase.value, "asrep_hash_count": len(asrep_hashes)},
            )
        )
        return evidence

    def _kerberos_attack_artifact_payload(self, target, host: str, domain: str, users: list[str], retained_spn_candidates: list[dict[str, object]], requested_checks: set[str], command_results: list[dict[str, object]], asrep_hashes: list[dict[str, object]]) -> dict[str, object]:
        return {
            "target": target.as_payload(),
            "host": host,
            "domain": domain,
            "user_count": len(users),
            "requested_checks": sorted(requested_checks),
            "spn_candidates": retained_spn_candidates,
            "asrep_hashes": asrep_hashes,
            "command_results": command_results,
            "guardrails": {"cracks_hashes": False, "executes_pocs": False, "bounded_user_count": len(users)},
        }

    def _kerberos_attack_metadata(self, host: str, domain: str, users: list[str], retained_spn_candidates: list[dict[str, object]], requested_checks: set[str], asrep_hashes: list[dict[str, object]]) -> dict[str, object]:
        return {
            "kind": "kerberos_attack_check",
            "host": host,
            "domain": domain,
            "requested_checks": sorted(requested_checks),
            "user_count": len(users),
            "asrep_hash_count": len(asrep_hashes),
            "spn_candidates": retained_spn_candidates,
            "cracks_hashes": False,
            "executes_pocs": False,
        }

    def _append_kerberos_attack_followups(
        self,
        task: Task,
        target,
        result: TaskExecutionResult,
        evidence: EvidenceRecord,
        asrep_hashes: list[dict[str, object]],
        retained_spn_candidates: list[dict[str, object]],
    ) -> None:
        if asrep_hashes or retained_spn_candidates:
            result.interests.append(
                Interest(
                    target_id=target.id,
                    title="Kerberos attack-path verification candidates",
                    summary=(
                        "Bounded Kerberos checks produced AS-REP material or SPN candidates. "
                        "Hash cracking and exploit execution are not performed by this primitive."
                    ),
                    evidence_refs=[evidence.id],
                    status=InterestStatus.OPEN,
                    confidence=0.78,
                    metadata={
                        "origin_task": task.id,
                        "class": "kerberos_attack_check",
                        "asrep_hash_count": len(asrep_hashes),
                        "spn_candidate_count": len(retained_spn_candidates),
                    },
                )
            )
        result.events.append(
            EventRecord(
                type=EventType.TASK_SUCCEEDED,
                summary=f"Kerberos attack checks completed with {len(asrep_hashes)} AS-REP hash candidate(s)",
                target_id=target.id,
                task_id=task.id,
                metadata={"asrep_hash_count": len(asrep_hashes), "spn_candidate_count": len(retained_spn_candidates)},
            )
        )
