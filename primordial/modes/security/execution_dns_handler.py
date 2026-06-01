from __future__ import annotations

from primordial.modes.security.execution_common import *


class PrimitiveDnsHandlerMixin:
    def _handle_dns_enumeration(self, task: Task, context: ContextSlice) -> TaskExecutionResult:
        result = TaskExecutionResult(summary="DNS enumeration completed")
        target = self.store.get_target(task.target_id)
        if not target:
            result.success = False
            result.error = "target not found"
            return result

        assets = self._target_scope_assets(target)
        dns_server = self._preferred_network_host(assets)
        domain = self._target_domain_guess(target, assets)
        if not dns_server or not domain:
            result.success = False
            result.error = "DNS enumeration requires a DNS server host and domain name"
            return result

        command_results = self._run_dns_enumeration_commands(dns_server, domain)
        parsed = self._parse_dns_enumeration(command_results)
        dns_records: list[dict[str, str]] = parsed["records"] if isinstance(parsed["records"], list) else []
        # Extract DC hostnames from LDAP SRV records as a fallback for AD enumeration
        # when DC01.domain A-record lookup fails or no hostname is pre-configured.
        dc_hostnames = self._extract_dc_hostnames_from_srv(dns_records, domain)
        artifact = self._write_artifact(
            task,
            target.id,
            f"dns-enumeration-{self._safe_artifact_fragment(domain)}",
            {
                "target": target.as_payload(),
                "dns_server": dns_server,
                "domain": domain,
                "command_results": command_results,
                "parsed": parsed,
            },
        )
        result.artifacts.append(artifact)
        evidence = EvidenceRecord(
            target_id=target.id,
            task_id=task.id,
            type=EvidenceType.TOOL_OUTPUT,
            title=f"DNS enumeration: {domain}",
            summary=self._summarize_dns_enumeration(dns_server, domain, parsed),
            source_ref=artifact.id,
            verification_status=VerificationStatus.VERIFIED,
            confidence=0.82,
            freshness=0.96,
            artifact_path=artifact.path,
            metadata={
                "kind": "dns_enumeration",
                "dns_server": dns_server,
                "domain": domain,
                "records": dns_records,
                "zone_transfer_success": parsed["zone_transfer_success"],
                "executed_tools": [item["tool"] for item in command_results if item.get("executed")],
                "dc_hostnames": dc_hostnames,
            },
        )
        result.evidence.append(evidence)
        result.notes.append(
            Note(
                target_id=target.id,
                task_id=task.id,
                title="DNS enumeration summary",
                body=self._build_dns_enumeration_note(dns_server, domain, parsed, command_results),
                confidence=0.78,
                freshness=0.92,
                metadata={"phase": task.phase.value, "domain": domain, "dns_server": dns_server},
            )
        )
        if dns_records:
            result.interests.append(
                Interest(
                    target_id=target.id,
                    title="DNS-derived host and service candidates",
                    summary="DNS enumeration produced records that may identify additional hostnames or service names for follow-up recon.",
                    evidence_refs=[evidence.id],
                    status=InterestStatus.OPEN,
                    confidence=0.76,
                    metadata={
                        "origin_task": task.id,
                        "class": "dns_inventory",
                        "record_count": len(dns_records),
                        "zone_transfer_success": parsed["zone_transfer_success"],
                        "dc_hostnames": dc_hostnames,
                    },
                )
            )
        result.events.append(
            EventRecord(
                type=EventType.TASK_SUCCEEDED,
                summary=f"DNS enumeration completed for {domain}",
                target_id=target.id,
                task_id=task.id,
                metadata={"record_count": len(dns_records)},
            )
        )
        return result
