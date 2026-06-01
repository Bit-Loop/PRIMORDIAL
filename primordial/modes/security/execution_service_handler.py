from __future__ import annotations

from primordial.modes.security.execution_common import *


class PrimitiveServiceHandlerMixin:
    def _handle_service_discovery(self, task: Task, context: ContextSlice) -> TaskExecutionResult:
        result = TaskExecutionResult(summary="service discovery completed")
        target = self.store.get_target(task.target_id)
        if not target:
            result.success = False
            result.error = "target not found"
            return result

        assets = self._target_scope_assets(target)
        hosts = self._service_discovery_hosts(assets)
        if not hosts:
            result.success = False
            result.error = "no host or IP assets are available for TCP service discovery"
            return result

        ports = self._service_discovery_ports(target.metadata)
        scan = self._scan_tcp_services(hosts, ports, timeout_seconds=self._manifest_timeout(task, 90))
        open_services = scan["open_services"]
        artifact = self._write_artifact(
            task,
            target.id,
            f"service-discovery-{self._safe_artifact_fragment(target.handle)}",
            {
                "target": target.as_payload(),
                "hosts": hosts,
                "ports": ports,
                "open_services": open_services,
                "closed_count": scan["closed_count"],
                "errors": scan["errors"],
                "scanner": scan.get("scanner", "unknown"),
                "command_results": scan.get("command_results", []),
            },
        )
        result.artifacts.append(artifact)

        evidence = EvidenceRecord(
            target_id=target.id,
            task_id=task.id,
            type=EvidenceType.TOOL_OUTPUT,
            title=f"TCP service discovery: {target.handle}",
            summary=self._summarize_open_services(open_services, host_count=len(hosts), port_count=len(ports)),
            source_ref=artifact.id,
            verification_status=VerificationStatus.VERIFIED,
            confidence=0.86 if open_services else 0.72,
            freshness=0.98,
            artifact_path=artifact.path,
            metadata={
                "kind": "tcp_service_discovery",
                "hosts": hosts,
                "ports": ports,
                "open_services": open_services,
                "closed_count": scan["closed_count"],
                "errors": scan["errors"],
                "scanner": scan.get("scanner", "unknown"),
                "command_results": scan.get("command_results", []),
            },
        )
        result.evidence.append(evidence)
        result.notes.append(
            Note(
                target_id=target.id,
                task_id=task.id,
                title="TCP service inventory",
                body=self._build_service_inventory_note(open_services, scan["closed_count"], scan["errors"]),
                confidence=0.82 if open_services else 0.7,
                freshness=0.96,
                metadata={"phase": task.phase.value, "open_service_count": len(open_services)},
            )
        )

        high_signal_services = [
            service for service in open_services if int(service.get("port", 0)) in REMOTE_ADMIN_PORTS
        ]
        if high_signal_services:
            result.interests.append(
                Interest(
                    target_id=target.id,
                    title="High-signal exposed service review",
                    summary=(
                        "Remote access, file-sharing, or database services were observed. "
                        "This is service inventory only; exploitation requires explicit bounded verification tasks."
                    ),
                    evidence_refs=[evidence.id],
                    status=InterestStatus.OPEN,
                    confidence=0.78,
                    metadata={"origin_task": task.id, "class": "service_inventory", "services": high_signal_services},
                )
            )
        if open_services:
            ports = sorted({int(service.get("port", 0)) for service in open_services if service.get("port")})
            severity = FindingSeverity.LOW if high_signal_services else FindingSeverity.INFO
            result.findings.append(
                Finding(
                    target_id=target.id,
                    title="Open TCP services observed",
                    summary=(
                        f"Service discovery observed {len(open_services)} open TCP service(s) "
                        f"across {len(hosts)} host candidate(s)."
                    ),
                    severity=severity,
                    evidence_refs=[evidence.id],
                    confidence=0.82,
                    verification_status=VerificationStatus.VERIFIED,
                    metadata={
                        "source": task.kind.value,
                        "auto_generated": True,
                        "ports": ports,
                        "open_service_count": len(open_services),
                        "high_signal_services": high_signal_services,
                    },
                )
            )

        result.events.append(
            EventRecord(
                type=EventType.TASK_SUCCEEDED,
                summary=f"Service discovery found {len(open_services)} open service(s) for {target.handle}",
                target_id=target.id,
                task_id=task.id,
                metadata={"open_service_count": len(open_services)},
            )
        )
        return result
