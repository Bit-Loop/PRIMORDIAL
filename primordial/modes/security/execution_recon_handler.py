from __future__ import annotations

from primordial.modes.security.execution_common import *


class PrimitiveReconHandlerMixin:
    def _handle_recon_scan(self, task: Task, context: ContextSlice) -> TaskExecutionResult:
        result = TaskExecutionResult(summary="recon scan completed")
        target = self.store.get_target(task.target_id)
        if not target:
            result.success = False
            result.error = "target not found"
            return result

        assets = self._target_scope_assets(target)
        plans = self._build_probe_plans(assets)
        successful_probes: list[dict[str, object]] = []
        errors: list[dict[str, str]] = []
        auth_surfaces: set[str] = set()
        discovered_paths: set[str] = set()
        discovered_parameters: set[str] = set()

        for plan in plans:
            probe = self._probe_url(
                url=plan["url"],
                host_header=plan.get("host_header"),
                asset_label=plan["asset_label"],
            )
            if probe.get("error"):
                errors.append(
                    {
                        "asset": str(plan["asset_label"]),
                        "url": str(plan["url"]),
                        "error": str(probe["error"]),
                    }
                )
                continue
            content_paths = [entry["path"] for entry in probe["discovery_results"] if entry.get("status")]
            auth_candidates = self._extract_auth_surfaces(
                probe["page_links"] + probe["scripts"] + probe["forms"] + content_paths
            )
            auth_surfaces.update(auth_candidates)
            discovered_paths.update(self._normalize_paths(probe["page_links"] + probe["forms"] + content_paths))
            discovered_parameters.update(self._extract_query_parameter_names(probe["page_links"]))
            successful_probes.append(probe)

            artifact_payload = {
                "asset": plan["asset_label"],
                "requested_url": probe["requested_url"],
                "effective_url": probe["effective_url"],
                "status_code": probe["status_code"],
                "content_type": probe["content_type"],
                "title": probe["title"],
                "server": probe["headers"].get("server"),
                "headers": probe["headers"],
                "page_links": probe["page_links"],
                "scripts": probe["scripts"],
                "forms": probe["forms"],
                "resolved_ips": probe["resolved_ips"],
                "discovery_results": probe["discovery_results"],
                "ssl_verification_disabled": probe["ssl_verification_disabled"],
            }
            artifact = self._write_artifact(
                task,
                target.id,
                self._artifact_prefix_for_probe(str(plan["asset_label"]), str(plan["url"])),
                artifact_payload,
            )
            result.artifacts.append(artifact)
            result.evidence.append(
                EvidenceRecord(
                    target_id=target.id,
                    task_id=task.id,
                    type=EvidenceType.TOOL_OUTPUT,
                    title=f"Recon: {probe['effective_url']}",
                    summary=self._summarize_probe(probe),
                    source_ref=artifact.id,
                    verification_status=VerificationStatus.VERIFIED,
                    confidence=0.9,
                    freshness=0.98,
                    artifact_path=artifact.path,
                    metadata={
                        "requested_url": probe["requested_url"],
                        "effective_url": probe["effective_url"],
                        "status_code": probe["status_code"],
                        "content_type": probe["content_type"],
                        "title": probe["title"],
                        "paths": content_paths,
                        "parameters": self._extract_query_parameter_names(probe["page_links"]),
                        "auth_surfaces": sorted(auth_candidates),
                        "scripts": probe["scripts"][:self.config.max_evidence_items],
                        "forms": probe["forms"][:self.config.max_evidence_items],
                        "resolved_ips": probe["resolved_ips"],
                        "headers": probe["headers"],
                    },
                )
            )

        if not successful_probes:
            failure_artifact = self._write_artifact(
                task,
                target.id,
                "recon-failures",
                {"target": target.handle, "errors": errors},
            )
            result.artifacts.append(failure_artifact)
            result.success = False
            result.error = "no reachable HTTP surface was observed for the target"
            result.events.append(
                EventRecord(
                    type=EventType.TASK_FAILED,
                    summary=f"Recon failed to reach {target.handle}",
                    target_id=target.id,
                    task_id=task.id,
                    metadata={"errors": errors},
                )
            )
            return result

        result.summary = f"recon scan completed with {len(successful_probes)} reachable endpoint(s)"
        result.notes.append(
            Note(
                target_id=target.id,
                task_id=task.id,
                title="Recon summary",
                body=self._build_recon_summary(successful_probes, auth_surfaces, discovered_paths, discovered_parameters),
                confidence=0.85,
                freshness=0.98,
                metadata={"phase": task.phase.value, "reachable_endpoints": len(successful_probes)},
            )
        )
        if auth_surfaces:
            result.interests.append(
                Interest(
                    target_id=target.id,
                    title="Observed auth/session surface inventory",
                    summary="Recon observed auth-adjacent routes or forms. This is evidence-backed surface inventory, not a vulnerability claim.",
                    evidence_refs=[item.id for item in result.evidence],
                    status=InterestStatus.OPEN,
                    confidence=0.82,
                    metadata={"origin_task": task.id, "class": "auth", "paths": sorted(auth_surfaces)},
                )
            )
        interesting_paths = sorted(
            path for path in discovered_paths if any(keyword in path.lower() for keyword in AUTH_KEYWORDS)
        )
        if successful_probes:
            statuses = sorted({int(probe["status_code"]) for probe in successful_probes})
            severity = FindingSeverity.MEDIUM if auth_surfaces or interesting_paths else FindingSeverity.LOW
            result.findings.append(
                Finding(
                    target_id=target.id,
                    title="Reachable HTTP surface observed",
                    summary=(
                        f"Recon reached {len(successful_probes)} HTTP endpoint(s) for {target.handle}. "
                        f"Observed status code(s): {', '.join(str(status) for status in statuses)}."
                    ),
                    severity=severity,
                    evidence_refs=[item.id for item in result.evidence],
                    confidence=0.78 if severity == FindingSeverity.MEDIUM else 0.72,
                    verification_status=VerificationStatus.VERIFIED,
                    metadata={
                        "source": task.kind.value,
                        "auto_generated": True,
                        "reachable_endpoints": len(successful_probes),
                        "status_codes": statuses,
                        "auth_surfaces": sorted(auth_surfaces),
                        "interesting_paths": interesting_paths[: self.config.max_evidence_items],
                    },
                )
            )
        result.handoffs.append(
            TaskHandoff(
                task_id=task.id,
                source_agent=task.role,
                destination_agent=AgentRole.ANALYSIS_WORKER,
                reason="Recon produced evidence-backed HTTP surface inventory.",
                expected_output_type="surface_analysis",
                evidence_refs=[item.id for item in result.evidence],
                hypothesis="Cluster reachable surfaces, redirects, parameters, and auth-adjacent pages before proposing any verification work.",
                budget="local-fast",
            )
        )
        result.events.append(
            EventRecord(
                type=EventType.TASK_SUCCEEDED,
                summary=f"Recon captured {len(successful_probes)} reachable endpoint(s) for {target.handle}",
                target_id=target.id,
                task_id=task.id,
            )
        )
        return result
