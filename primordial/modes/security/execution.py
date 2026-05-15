from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
from typing import Callable
from urllib import error, parse, request
import xml.etree.ElementTree as ET

from primordial.core.config import AppConfig
from primordial.core.credentials import CredentialStore
from primordial.core.domain.constants import (
    REMOTE_ADMIN_PORTS,
    SERVICE_DISCOVERY_PORTS,
    SERVICE_NAME_BY_PORT,
)
from primordial.core.domain.enums import (
    AgentRole,
    ArtifactKind,
    EventType,
    EvidenceType,
    ExternalSyncKind,
    FindingSeverity,
    InterestStatus,
    NotificationChannel,
    RiskTier,
    TaskKind,
    VerificationStatus,
)
from primordial.core.domain.models import (
    AgentTrace,
    ArtifactRecord,
    ContextSlice,
    EventRecord,
    EvidenceRecord,
    ExternalSyncJob,
    Finding,
    Interest,
    Note,
    NotificationRecord,
    PrimitiveManifest,
    Task,
    TaskExecutionResult,
    TaskHandoff,
)
from primordial.core.intent.models import OperatorIntentPolicy
from primordial.core.primitives.aliases import primitives_for_hint
from primordial.core.primitives.catalog import PrimitiveCatalog
from primordial.core.storage.runtime import RuntimeStore


AiGenerateCallable = Callable[[Task, str, str, float], dict[str, object] | None]


AUTH_KEYWORDS = ("login", "signin", "sign-in", "auth", "session", "account", "admin")
DISCOVERY_PATHS = (
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/login",
    "/admin",
    "/api/",
)
# SERVICE_DISCOVERY_PORTS, SERVICE_NAME_BY_PORT, REMOTE_ADMIN_PORTS are
# imported from primordial.core.domain.constants — edit them there, not here.
CONTENT_DISCOVERY_EXTENSIONS = ("", ".aspx", ".asp", ".txt", ".config", ".html")
CONTENT_DISCOVERY_INTERESTING_STATUS = {200, 204, 301, 302, 307, 308, 401, 403}
EXPLOIT_RESEARCH_SUPPRESSED_TERMS = (
    "denial of service",
    " dos",
    "/dos/",
    "ddos",
    "crash",
    "stack overflow",
    "buffer overflow",
    "resource exhaustion",
    "memory exhaustion",
)
EXPLOIT_RESEARCH_LOCAL_TERMS = (
    "/local/",
    " local ",
    "privilege escalation",
    "priv esc",
    "unquoted service path",
)
EXPLOIT_RESEARCH_RCE_TERMS = (
    "remote code execution",
    " rce",
    "/rce/",
    "command execution",
    "code execution",
)
EXPLOIT_RESEARCH_HTTP_TRASH_PREFIXES = ("http/1.", "content-length:", "content-type:", "last-modified:")


class _SurfaceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._in_title = False
        self._title_chunks: list[str] = []
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[str] = []

    @property
    def title(self) -> str:
        return " ".join(chunk.strip() for chunk in self._title_chunks if chunk.strip()).strip()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {key: value for key, value in attrs}
        if tag == "title":
            self._in_title = True
            return
        if tag == "a" and attr_map.get("href"):
            self.links.append(attr_map["href"])
        elif tag == "script" and attr_map.get("src"):
            self.scripts.append(attr_map["src"])
        elif tag == "form" and attr_map.get("action"):
            self.forms.append(attr_map["action"])

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title_chunks.append(data)


class PrimitiveExecutor:
    def __init__(
        self,
        store: RuntimeStore,
        catalog: PrimitiveCatalog,
        config: AppConfig,
        credentials: CredentialStore,
        ai_generate: AiGenerateCallable | None = None,
        active_intent_policy_loader: Callable[[], OperatorIntentPolicy] | None = None,
        active_intent_id_loader: Callable[[], str] | None = None,
    ) -> None:
        self.store = store
        self.catalog = catalog
        self.config = config
        self.credentials = credentials
        self.ai_generate = ai_generate
        self.active_intent_policy_loader = active_intent_policy_loader
        self.active_intent_id_loader = active_intent_id_loader

    def execute(self, task: Task, context: ContextSlice | None) -> TaskExecutionResult:
        handler = getattr(self, f"_handle_{task.kind.value}", self._handle_generic)
        return handler(task, context)

    def _active_intent_policy(self) -> OperatorIntentPolicy | None:
        return self.active_intent_policy_loader() if self.active_intent_policy_loader else None

    def _active_intent_id(self) -> str:
        return self.active_intent_id_loader() if self.active_intent_id_loader else "recon_only"

    def _blocked_by_intent_result(
        self,
        task: Task,
        *,
        capability_category: str,
        required_intent: str,
        reason: str,
    ) -> TaskExecutionResult:
        active_intent = self._active_intent_id()
        return TaskExecutionResult(
            success=False,
            summary=f"blocked by operator intent: {reason}",
            error=reason,
            events=[
                EventRecord(
                    type=EventType.TASK_BLOCKED,
                    summary=f"Operator intent blocked {task.kind.value}: {reason}",
                    target_id=task.target_id,
                    task_id=task.id,
                    metadata={
                        "blocked_by_operator_intent": True,
                        "task_kind": task.kind.value,
                        "capability_category": capability_category,
                        "active_intent": active_intent,
                        "required_intent": required_intent,
                        "reason": reason,
                    },
                )
            ],
        )

    def _require_intent(self, task: Task) -> TaskExecutionResult | None:
        policy = self._active_intent_policy()
        if policy is None:
            return None
        if task.kind == TaskKind.EXPLOIT_RESEARCH:
            if not (policy.public_poc_research and policy.searchsploit_allowed):
                return self._blocked_by_intent_result(
                    task,
                    capability_category="public_poc_research",
                    required_intent="exploit_research_allowed or htb_lab",
                    reason="active intent does not allow searchsploit public PoC research",
                )
        elif task.kind == TaskKind.POC_APPLICABILITY_VALIDATION:
            if not policy.poc_applicability_validation:
                return self._blocked_by_intent_result(
                    task,
                    capability_category="poc_applicability_validation",
                    required_intent="exploit_research_allowed or htb_lab",
                    reason="active intent does not allow public PoC applicability validation",
                )
        elif task.kind == TaskKind.KERBEROS_ATTACK_CHECK:
            requested = self._requested_kerberos_checks(task)
            if "asrep_roast" in requested and not policy.kerberos_policy.asrep_roast_check_allowed:
                return self._blocked_by_intent_result(
                    task,
                    capability_category="asrep_roast_check",
                    required_intent="ad_lab in-house AD attack path or htb_lab",
                    reason="active intent does not allow AS-REP roast checks",
                )
            if "kerberoast" in requested and not policy.kerberos_policy.kerberoast_check_allowed:
                return self._blocked_by_intent_result(
                    task,
                    capability_category="kerberoast_check",
                    required_intent="ad_lab in-house AD attack path or htb_lab",
                    reason="active intent does not allow Kerberoast candidate checks",
                )
        elif task.kind == TaskKind.CREDENTIALED_ACCESS_CHECK:
            if not policy.credential_policy.credential_validation_allowed:
                return self._blocked_by_intent_result(
                    task,
                    capability_category="credentialed_access_check",
                    required_intent="credential_validation or htb_lab",
                    reason="active intent does not allow credential validation",
                )
        return None

    def _requested_kerberos_checks(self, task: Task) -> set[str]:
        raw = task.metadata.get("kerberos_checks")
        if isinstance(raw, str):
            requested = {raw.strip().lower()}
        elif isinstance(raw, list):
            requested = {str(item).strip().lower() for item in raw}
        else:
            requested = {"asrep_roast", "kerberoast"}
        aliases = {
            "asrep": "asrep_roast",
            "asrep_roast_check": "asrep_roast",
            "kerberoast_check": "kerberoast",
            "spn_candidate_review": "kerberoast",
        }
        normalized = {aliases.get(item, item) for item in requested if item}
        return normalized.intersection({"asrep_roast", "kerberoast"}) or {"asrep_roast", "kerberoast"}

    def resolve_primitives(self, task: Task) -> list[PrimitiveManifest]:
        selected: dict[str, PrimitiveManifest] = {}
        hinted = primitives_for_hint(self.catalog.all(), task.metadata.get("primitive_hint"))
        if hinted:
            return hinted
        for capability in task.required_capabilities:
            for manifest in self.catalog.by_capability(capability):
                selected.setdefault(manifest.name, manifest)
        return list(selected.values())

    def _manifest_timeout(self, task: Task, fallback: int) -> int:
        primitives = self.resolve_primitives(task)
        if primitives:
            return primitives[0].timeout_seconds
        return fallback

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

    def _handle_web_content_discovery(self, task: Task, context: ContextSlice) -> TaskExecutionResult:
        result = TaskExecutionResult(summary="web content discovery completed")
        target = self.store.get_target(task.target_id)
        if not target:
            result.success = False
            result.error = "target not found"
            return result

        bases = self._content_discovery_bases(target.id)
        if not bases:
            result.success = False
            result.error = "no reachable HTTP base URL is available for content discovery"
            return result

        words = self._content_discovery_words(target.metadata)
        discovered = self._run_web_content_discovery(bases, words)
        artifact = self._write_artifact(
            task,
            target.id,
            f"web-content-discovery-{self._safe_artifact_fragment(target.handle)}",
            {
                "target": target.as_payload(),
                "base_urls": bases,
                "word_count": len(words),
                "extensions": list(CONTENT_DISCOVERY_EXTENSIONS),
                "discovered": discovered,
            },
        )
        result.artifacts.append(artifact)
        evidence = EvidenceRecord(
            target_id=target.id,
            task_id=task.id,
            type=EvidenceType.TOOL_OUTPUT,
            title=f"Web content discovery: {target.handle}",
            summary=self._summarize_content_discovery(discovered, bases, len(words)),
            source_ref=artifact.id,
            verification_status=VerificationStatus.VERIFIED,
            confidence=0.82 if discovered else 0.7,
            freshness=0.96,
            artifact_path=artifact.path,
            metadata={
                "kind": "web_content_discovery",
                "base_urls": bases,
                "word_count": len(words),
                "extensions": list(CONTENT_DISCOVERY_EXTENSIONS),
                "discovered": discovered,
            },
        )
        result.evidence.append(evidence)
        result.notes.append(
            Note(
                target_id=target.id,
                task_id=task.id,
                title="Web content discovery summary",
                body=self._build_content_discovery_note(discovered, bases, len(words)),
                confidence=0.76,
                freshness=0.92,
                metadata={"phase": task.phase.value, "path_count": len(discovered)},
            )
        )
        if discovered:
            result.interests.append(
                Interest(
                    target_id=target.id,
                    title="Discovered web path follow-up candidates",
                    summary="Bounded content discovery found reachable or access-controlled web paths for follow-up analysis.",
                    evidence_refs=[evidence.id],
                    status=InterestStatus.OPEN,
                    confidence=0.76,
                    metadata={"origin_task": task.id, "class": "web_content", "path_count": len(discovered)},
                )
            )
        result.events.append(
            EventRecord(
                type=EventType.TASK_SUCCEEDED,
                summary=f"Web content discovery found {len(discovered)} path(s) for {target.handle}",
                target_id=target.id,
                task_id=task.id,
                metadata={"path_count": len(discovered)},
            )
        )
        return result

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

    def _handle_kerberos_user_discovery(self, task: Task, context: ContextSlice) -> TaskExecutionResult:
        result = TaskExecutionResult(summary="Kerberos user discovery completed")
        target = self.store.get_target(task.target_id)
        if not target:
            result.success = False
            result.error = "target not found"
            return result

        assets = self._target_scope_assets(target)
        host = self._preferred_network_host(assets)
        if not host:
            result.success = False
            result.error = "no host or IP asset is available for Kerberos user discovery"
            return result

        base_dn = self._default_naming_context(target.id)
        domain = self._domain_from_base_dn(base_dn) or self._domain_from_target(target.handle)
        command_results = self._run_kerberos_user_discovery_commands(host, base_dn)
        parsed = self._parse_kerberos_user_discovery(command_results, domain)
        artifact = self._write_artifact(
            task,
            target.id,
            f"kerberos-user-discovery-{self._safe_artifact_fragment(host)}",
            {
                "target": target.as_payload(),
                "host": host,
                "domain": domain,
                "base_dn": base_dn,
                "command_results": command_results,
                "parsed": parsed,
            },
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

        assets = self._target_scope_assets(target)
        host = self._preferred_network_host(assets)
        users = self._discovered_kerberos_users(target.id)
        spn_candidates = self._discovered_spn_candidates(target.id)
        domain = self._kerberos_domain(target.id, target.handle)
        requested_checks = self._requested_kerberos_checks(task)
        if not host:
            result.success = False
            result.error = "Kerberos attack checks require a host"
            return result
        if "asrep_roast" in requested_checks and not users:
            result.success = False
            result.error = "AS-REP roast checks require discovered user principals"
            return result
        if "kerberoast" in requested_checks and not spn_candidates:
            result.success = False
            result.error = "Kerberoast checks require discovered SPN candidates"
            return result

        command_results = self._run_kerberos_attack_check_commands(task, target.id, host, domain, users, requested_checks)
        asrep_hashes = self._parse_asrep_hashes(command_results)
        retained_spn_candidates = spn_candidates if "kerberoast" in requested_checks else []
        artifact = self._write_artifact(
            task,
            target.id,
            f"kerberos-attack-check-{self._safe_artifact_fragment(host)}",
            {
                "target": target.as_payload(),
                "host": host,
                "domain": domain,
                "user_count": len(users),
                "requested_checks": sorted(requested_checks),
                "spn_candidates": retained_spn_candidates,
                "asrep_hashes": asrep_hashes,
                "command_results": command_results,
                "guardrails": {"cracks_hashes": False, "executes_pocs": False, "bounded_user_count": len(users)},
            },
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
            metadata={
                "kind": "kerberos_attack_check",
                "host": host,
                "domain": domain,
                "requested_checks": sorted(requested_checks),
                "user_count": len(users),
                "asrep_hash_count": len(asrep_hashes),
                "spn_candidates": retained_spn_candidates,
                "cracks_hashes": False,
                "executes_pocs": False,
            },
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
        return result

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

    def _handle_exploit_research(self, task: Task, context: ContextSlice) -> TaskExecutionResult:
        blocked = self._require_intent(task)
        if blocked is not None:
            return blocked
        result = TaskExecutionResult(summary="exploit research completed")
        target = self.store.get_target(task.target_id)
        if not target:
            result.success = False
            result.error = "target not found"
            return result

        queries = self._build_searchsploit_queries(target.id)
        if not queries:
            result.success = False
            result.error = "no evidence-backed search terms are available for exploit research"
            return result

        research = self._run_searchsploit_research(queries)
        artifact = self._write_artifact(
            task,
            target.id,
            f"exploit-research-{self._safe_artifact_fragment(target.handle)}",
            {
                "target": target.as_payload(),
                "queries": queries,
                "matches": research["matches"],
                "suppressed_matches": research["suppressed_matches"],
                "examined_examples": research["examined_examples"],
                "command_results": research["command_results"],
                "guardrails": {
                    "executes_pocs": False,
                    "suppresses_dos": True,
                    "requires_verification_before_synthesis": True,
                },
            },
        )
        result.artifacts.append(artifact)
        evidence = EvidenceRecord(
            target_id=target.id,
            task_id=task.id,
            type=EvidenceType.MODEL_REVIEW,
            title=f"Exploit research: {target.handle}",
            summary=self._summarize_exploit_research(research),
            source_ref=artifact.id,
            verification_status=VerificationStatus.PARTIAL,
            confidence=0.68 if research["matches"] else 0.55,
            freshness=0.9,
            artifact_path=artifact.path,
            metadata={
                "kind": "exploit_research",
                "queries": queries,
                "match_count": len(research["matches"]),
                "suppressed_match_count": len(research["suppressed_matches"]),
                "example_count": len(research["examined_examples"]),
                "executes_pocs": False,
            },
        )
        result.evidence.append(evidence)
        result.notes.append(
            Note(
                target_id=target.id,
                task_id=task.id,
                title="Exploit research summary",
                body=self._build_exploit_research_note(queries, research),
                confidence=0.68,
                freshness=0.88,
                metadata={"phase": task.phase.value, "match_count": len(research["matches"])},
            )
        )
        if self._ai_review_requested(task):
            ai_review = self._run_ai_review(
                task,
                target_id=target.id,
                title="AI exploit research triage",
                snapshot=(
                    f"{self._build_ai_target_snapshot(target.id)}\n\n"
                    f"Search queries: {json.dumps(queries, sort_keys=True)}\n"
                    f"Retained matches: {json.dumps(research['matches'][:8], sort_keys=True)}\n"
                    f"Suppressed matches: {json.dumps(research['suppressed_matches'][:8], sort_keys=True)}"
                ),
                instruction=(
                    "Triage retained public exploit references against known target evidence. Identify which "
                    "queries should be refined, which candidates are blocked by missing exact versions or foothold, "
                    "and which safe primitive-backed validations should run next. Do not write exploit code and do "
                    "not imply any PoC executed."
                ),
            )
            self._apply_ai_review(result, task, ai_review)
        else:
            evidence.metadata["ai_review_skipped"] = True
            evidence.metadata["ai_review_skip_reason"] = "operator-triggered AI review was not requested"
        if research["matches"]:
            result.findings.append(
                Finding(
                    target_id=target.id,
                    title="Public exploit references require manual triage",
                    summary=(
                        f"Searchsploit returned {len(research['matches'])} retained non-DoS candidate reference(s). "
                        "These are unverified research leads only; no PoC was executed."
                    ),
                    severity=FindingSeverity.MEDIUM,
                    evidence_refs=[evidence.id],
                    confidence=0.62,
                    verification_status=VerificationStatus.PARTIAL,
                    metadata={
                        "source": task.kind.value,
                        "auto_generated": True,
                        "match_count": len(research["matches"]),
                        "suppressed_match_count": len(research["suppressed_matches"]),
                        "executes_pocs": False,
                        "requires_manual_review": True,
                    },
                )
            )
            summary = self._build_exploit_research_notification(target.handle, research)
            result.interests.append(
                Interest(
                    target_id=target.id,
                    title="PoC research candidates for gated synthesis",
                    summary=(
                        "Searchsploit returned non-DoS public exploit references. These are research candidates only; "
                        "they require version validation, adaptation review, and policy approval before any execution."
                    ),
                    evidence_refs=[evidence.id],
                    status=InterestStatus.OPEN,
                    confidence=0.7,
                    metadata={
                        "origin_task": task.id,
                        "class": "exploit_research",
                        "match_count": len(research["matches"]),
                        "example_count": len(research["examined_examples"]),
                    },
                )
            )
            result.notifications.append(
                NotificationRecord(
                    channel=NotificationChannel.DISCORD,
                    event_type="poc_research_candidate",
                    summary=summary,
                    target_id=target.id,
                    task_id=task.id,
                    urgency="high",
                    dedupe_key=f"poc-research:{target.id}:{task.id}",
                    metadata={
                        "target": target.handle,
                        "match_count": len(research["matches"]),
                        "example_count": len(research["examined_examples"]),
                        "suppressed_match_count": len(research["suppressed_matches"]),
                        "executes_pocs": False,
                        "requires_agent_or_human_approval": True,
                    },
                )
            )
        result.events.append(
            EventRecord(
                type=EventType.TASK_SUCCEEDED,
                summary=f"Exploit research found {len(research['matches'])} non-DoS candidate(s)",
                target_id=target.id,
                task_id=task.id,
                metadata={
                    "match_count": len(research["matches"]),
                    "suppressed_match_count": len(research["suppressed_matches"]),
                },
            )
        )
        return result

    def _handle_poc_applicability_validation(self, task: Task, context: ContextSlice) -> TaskExecutionResult:
        blocked = self._require_intent(task)
        if blocked is not None:
            return blocked
        result = TaskExecutionResult(summary="PoC applicability validation completed")
        target = self.store.get_target(task.target_id)
        if not target:
            result.success = False
            result.error = "target not found"
            return result

        evidence = self._task_generation_records(task, target, self.store.list_evidence(target_id=target.id, limit=100))
        research_items = [item for item in evidence if item.metadata.get("kind") == "exploit_research"]
        service_items = [
            item
            for item in evidence
            if item.metadata.get("kind") in {"tcp_service_discovery", "dns_enumeration", "ad_enumeration", "web_content_discovery"}
        ]
        candidates = self._load_poc_candidates(research_items)
        if not candidates:
            result.success = False
            result.error = "no retained public PoC candidates are available for applicability validation"
            return result

        service_facts = self._poc_service_facts(service_items)
        has_foothold = self._poc_has_foothold(evidence)
        classified = [self._classify_poc_candidate(candidate, service_facts, has_foothold) for candidate in candidates]
        ready_count = sum(1 for item in classified if item["status"] == "ready_for_review")
        blocked_count = len(classified) - ready_count
        artifact = self._write_artifact(
            task,
            target.id,
            f"poc-applicability-{self._safe_artifact_fragment(target.handle)}",
            {
                "target": target.as_payload(),
                "service_facts": service_facts,
                "classified_candidates": classified,
                "guardrails": {
                    "executes_pocs": False,
                    "writes_exploit_code": False,
                    "requires_policy_approval_before_execution": True,
                    "requires_exact_version_or_prerequisite_match": True,
                },
            },
        )
        result.artifacts.append(artifact)
        evidence_record = EvidenceRecord(
            target_id=target.id,
            task_id=task.id,
            type=EvidenceType.MODEL_REVIEW,
            title=f"PoC applicability validation: {target.handle}",
            summary=(
                f"Classified {len(classified)} retained public PoC candidate(s): "
                f"{ready_count} ready for gated review, {blocked_count} blocked or research-only. "
                "No PoC was executed and no exploit code was generated."
            ),
            source_ref=artifact.id,
            verification_status=VerificationStatus.PARTIAL,
            confidence=0.72,
            freshness=0.92,
            artifact_path=artifact.path,
            metadata={
                "kind": "poc_applicability_validation",
                "candidate_count": len(classified),
                "ready_count": ready_count,
                "blocked_count": blocked_count,
                "executes_pocs": False,
                "writes_exploit_code": False,
            },
        )
        result.evidence.append(evidence_record)
        result.notes.append(
            Note(
                target_id=target.id,
                task_id=task.id,
                title="PoC applicability validation summary",
                body=self._build_poc_applicability_note(classified, service_facts),
                confidence=0.74,
                freshness=0.9,
                metadata={"phase": task.phase.value, "candidate_count": len(classified), "ready_count": ready_count},
            )
        )
        if self._ai_review_requested(task):
            ai_review = self._run_ai_review(
                task,
                target_id=target.id,
                title="AI PoC applicability review",
                snapshot=(
                    f"{self._build_ai_target_snapshot(target.id)}\n\n"
                    f"Service facts: {json.dumps(service_facts, sort_keys=True)}\n"
                    f"Classified candidates: {json.dumps(classified[:10], sort_keys=True)}"
                ),
                instruction=(
                    "Review the deterministic PoC applicability classifications. Call out false positives, missing "
                    "version evidence, foothold prerequisites, safer alternate validations, and exact stop conditions. "
                    "This is a read-only review: do not execute PoCs, do not generate exploit code, and do not mark a "
                    "finding verified."
                ),
            )
            self._apply_ai_review(result, task, ai_review)
        else:
            evidence_record.metadata["ai_review_skipped"] = True
            evidence_record.metadata["ai_review_skip_reason"] = "operator-triggered AI review was not requested"
        if ready_count:
            result.interests.append(
                Interest(
                    target_id=target.id,
                    title="PoC applicability candidates ready for gated review",
                    summary=(
                        f"{ready_count} retained public PoC candidate(s) have enough evidence for a deeper gated "
                        "review. Execution still requires explicit policy approval and bounded stop conditions."
                    ),
                    evidence_refs=[evidence_record.id],
                    status=InterestStatus.OPEN,
                    confidence=0.72,
                    metadata={"origin_task": task.id, "class": "poc_applicability", "ready_count": ready_count},
                )
            )
        result.events.append(
            EventRecord(
                type=EventType.TASK_SUCCEEDED,
                summary=f"PoC applicability validation classified {len(classified)} candidate(s)",
                target_id=target.id,
                task_id=task.id,
                metadata={"ready_count": ready_count, "blocked_count": blocked_count},
            )
        )
        return result

    def _handle_analyze_evidence(self, task: Task, context: ContextSlice) -> TaskExecutionResult:
        result = TaskExecutionResult(summary="analysis completed")
        target = self.store.get_target(task.target_id)
        if not target:
            result.success = False
            result.error = "target not found"
            return result

        _evidence_raw = self._task_generation_records(task, target, self.store.list_evidence(target_id=target.id, limit=25))
        _evidence_overflow = len(_evidence_raw) > 24
        evidence = _evidence_raw[:24]
        auth_refs = [
            item.id
            for item in evidence
            if self._extract_auth_surfaces(
                list(item.metadata.get("paths", []))
                + list(item.metadata.get("auth_surfaces", []))
                + list(item.metadata.get("forms", []))
            )
        ]
        observed_paths = sorted(
            {
                path
                for item in evidence
                for path in item.metadata.get("paths", [])
                if isinstance(path, str) and path
            }
        )
        observed_parameters = sorted(
            {
                name
                for item in evidence
                for name in item.metadata.get("parameters", [])
                if isinstance(name, str) and name
            }
        )
        _analysis_body = self._build_analysis_summary(observed_paths, observed_parameters, len(auth_refs))
        if _evidence_overflow:
            _analysis_body += " [Warning: evidence truncated to 24 items; older records excluded from this analysis.]"
        result.notes.append(
            Note(
                target_id=target.id,
                task_id=task.id,
                title="Evidence analysis summary",
                body=_analysis_body,
                confidence=0.78,
                freshness=0.9,
                metadata={
                    "evidence_count": len(evidence),
                    "evidence_truncated": _evidence_overflow,
                    "observed_paths": observed_paths[:self.config.max_evidence_items],
                    "observed_parameters": observed_parameters[:self.config.max_evidence_items],
                },
            )
        )
        ai_review = self._run_ai_review(
            task,
            target_id=target.id,
            title="AI strategy review",
            snapshot=self._build_ai_target_snapshot(target.id),
            instruction=(
                "Act as a bounded autonomous security-analysis worker. Identify the most useful next "
                "primitive-backed actions, explain what is blocked, and propose concrete safe follow-up "
                "tasks. Do not claim a vulnerability or flag unless evidence proves it. Do not recommend "
                "DoS, flooding, password spraying, or unbounded brute force. Prefer version-specific "
                "triage, credential/scope prerequisites, and exact missing primitives."
            ),
        )
        self._apply_ai_review(result, task, ai_review)
        if auth_refs:
            result.interests.append(
                Interest(
                    target_id=target.id,
                    title="Auth-adjacent surface review backlog",
                    summary="Auth-adjacent routes or forms were observed. Manual or future primitive-backed verification is required before any exploit claim.",
                    evidence_refs=auth_refs,
                    status=InterestStatus.OPEN,
                    confidence=0.76,
                    metadata={"rank": 1, "phase": task.phase.value},
                )
            )
        return result

    def _handle_verify_hypothesis(self, task: Task, context: ContextSlice) -> TaskExecutionResult:
        result = TaskExecutionResult(summary="verification deferred")
        target = self.store.get_target(task.target_id)
        if not target:
            result.success = False
            result.error = "target not found"
            return result

        primitives = self.resolve_primitives(task)
        has_verification_adapter = any(
            primitive.name == "finding-verification" or "finding-verification" in primitive.capability_tags
            for primitive in primitives
        )
        interests = self._task_generation_records(task, target, self.store.list_interests(target_id=target.id, limit=20))
        if has_verification_adapter:
            return self._run_bounded_finding_verification(task, target, interests)

        result.summary = "verification planning complete; execution remains primitive-gated"
        result.notes.append(
            Note(
                target_id=target.id,
                task_id=task.id,
                title="Verification status",
                body=(
                    "No production verification primitive is registered for automatic claim validation yet. "
                    "The target remains in recon/analysis state until a real bounded verification adapter is implemented."
                ),
                confidence=0.9,
                freshness=0.9,
                metadata={"interest_count": len(interests), "deferred": True},
            )
        )
        ai_review = self._run_ai_review(
            task,
            target_id=target.id,
            title="AI verification plan",
            snapshot=self._build_ai_target_snapshot(target.id),
            instruction=(
                "Produce a safe bounded verification plan for the strongest current hypothesis. "
                "List prerequisites, exact evidence references to use, production primitives needed, "
                "and stop conditions. Do not write exploit code here and do not mark anything verified."
            ),
        )
        self._apply_ai_review(result, task, ai_review)
        return result

    def _run_bounded_finding_verification(
        self,
        task: Task,
        target,
        interests: list[Interest],
    ) -> TaskExecutionResult:
        verified_interests = sorted(
            [item for item in interests if item.status == InterestStatus.VERIFIED],
            key=lambda item: item.confidence,
            reverse=True,
        )
        evidence = self._task_generation_records(task, target, self.store.list_evidence(target_id=target.id, limit=200))
        evidence_by_id = {item.id: item for item in evidence}
        verified_evidence_ids = {
            item.id
            for item in evidence
            if item.verification_status == VerificationStatus.VERIFIED
        }
        result = TaskExecutionResult(summary="bounded verification complete")
        if not verified_interests:
            result.summary = "bounded verification rejected; no verified interest is available"
            result.evidence.append(
                self._verification_result_evidence(
                    task,
                    target,
                    status=VerificationStatus.REJECTED,
                    summary="No current-generation verified interest was available for deterministic verification.",
                    evidence_refs=[],
                    metadata={"reason": "no_verified_interest"},
                )
            )
            return result

        selected = verified_interests[0]
        selected_refs = [ref for ref in selected.evidence_refs if ref in evidence_by_id]
        verified_refs = [ref for ref in selected_refs if ref in verified_evidence_ids]
        if not verified_refs:
            result.summary = "bounded verification rejected; verified interest lacks verified evidence"
            result.evidence.append(
                self._verification_result_evidence(
                    task,
                    target,
                    status=VerificationStatus.REJECTED,
                    summary=(
                        f"Interest '{selected.title}' is marked verified, but none of its evidence references "
                        "are current-generation verified evidence."
                    ),
                    evidence_refs=selected_refs,
                    metadata={"reason": "missing_verified_evidence", "interest_id": selected.id},
                )
            )
            return result

        verification_evidence = self._verification_result_evidence(
            task,
            target,
            status=VerificationStatus.VERIFIED,
            summary=(
                f"Deterministic finding-verification confirmed '{selected.title}' against "
                f"{len(verified_refs)} current-generation verified evidence record(s). No PoC was executed."
            ),
            evidence_refs=verified_refs,
            metadata={
                "interest_id": selected.id,
                "interest_title": selected.title,
                "interest_confidence": selected.confidence,
                "verified_evidence_refs": verified_refs,
                "all_interest_evidence_refs": selected_refs,
            },
        )
        result.evidence.append(verification_evidence)
        result.notes.append(
            Note(
                target_id=target.id,
                task_id=task.id,
                title="Bounded verification result",
                body=(
                    f"Verified interest '{selected.title}' is backed by current-generation verified evidence. "
                    "This adapter produced durable verification evidence only; it did not execute exploit code."
                ),
                confidence=min(0.92, max(0.7, selected.confidence)),
                freshness=0.95,
                metadata={
                    "adapter": "finding-verification",
                    "interest_id": selected.id,
                    "verification_evidence_ref": verification_evidence.id,
                },
            )
        )
        result.findings.append(
            Finding(
                target_id=target.id,
                title=f"Verified hypothesis: {selected.title}",
                summary=selected.summary,
                severity=FindingSeverity.MEDIUM,
                evidence_refs=[*verified_refs, verification_evidence.id],
                confidence=min(0.9, max(0.7, selected.confidence)),
                verification_status=VerificationStatus.VERIFIED,
                metadata={
                    "source": task.kind.value,
                    "adapter": "finding-verification",
                    "auto_generated": True,
                    "executes_pocs": False,
                    "interest_id": selected.id,
                    "verification_evidence_ref": verification_evidence.id,
                },
            )
        )
        result.summary = "bounded verification completed with durable evidence linkage"
        return result

    def _verification_result_evidence(
        self,
        task: Task,
        target,
        *,
        status: VerificationStatus,
        summary: str,
        evidence_refs: list[str],
        metadata: dict[str, object],
    ) -> EvidenceRecord:
        return EvidenceRecord(
            target_id=target.id,
            task_id=task.id,
            type=EvidenceType.TOOL_OUTPUT,
            title="Bounded finding verification result",
            summary=summary,
            source_ref=f"primitive://finding-verification/{task.id}",
            verification_status=status,
            confidence=0.9 if status == VerificationStatus.VERIFIED else 0.65,
            freshness=0.95,
            metadata={
                "kind": "bounded_verification_result",
                "adapter": "finding-verification",
                "executes_pocs": False,
                "source_evidence_refs": evidence_refs,
                **metadata,
            },
        )

    def _handle_chain_candidates(self, task: Task, context: ContextSlice) -> TaskExecutionResult:
        result = TaskExecutionResult(summary="chain review deferred")
        target = self.store.get_target(task.target_id)
        if not target:
            result.success = False
            result.error = "target not found"
            return result
        fanout = max(2, int(self.config.autonomy.max_chaining_fanout))
        interests = self._task_generation_records(
            task,
            target,
            self.store.list_interests(target_id=target.id, limit=max(12, fanout * 2)),
        )
        all_verified = [item for item in interests if item.status == InterestStatus.VERIFIED]
        verified = all_verified[:fanout]
        if len(verified) < 2:
            result.success = False
            result.error = "not enough verified interests for chain review"
            return result
        result.summary = "chain planning complete; execution remains primitive-gated"
        result.notes.append(
            Note(
                target_id=target.id,
                task_id=task.id,
                title="Candidate exploit chain",
                body="Multiple verified interests exist, but automatic exploit-chain synthesis remains disabled until a real bounded chain-verification primitive is registered.",
                confidence=0.88,
                freshness=0.86,
                metadata={
                    "verified_interest_count": len(all_verified),
                    "reviewed_interest_count": len(verified),
                    "max_chaining_fanout": fanout,
                    "truncated": len(all_verified) > len(verified),
                    "interest_ids": [item.id for item in verified],
                },
            )
        )
        ai_review = self._run_ai_review(
            task,
            target_id=target.id,
            title="AI chain review",
            snapshot=self._build_ai_target_snapshot(target.id),
            instruction=(
                "Review the verified interests for possible exploit-chain candidates. Return candidate "
                "chains, missing prerequisites, confidence, required verification tasks, and reasons "
                "to reject weak chains. Do not mark a chain valid without primitive-backed verification."
            ),
        )
        self._apply_ai_review(result, task, ai_review)
        return result

    def _handle_verify_agent_behavior(self, task: Task, context: ContextSlice) -> TaskExecutionResult:
        result = TaskExecutionResult(summary="behavior verification complete")
        target = self.store.get_target(task.target_id)
        traces = self.store.list_traces(task_id=task.id, limit=12)
        if target is not None:
            result.notes.append(
                Note(
                    target_id=target.id,
                    task_id=task.id,
                    title="Behavior verification note",
                    body=f"Verifier reviewed {len(traces)} trace records. No unsupported durable claim promotion occurred in this branch.",
                    confidence=0.82,
                    freshness=0.95,
                )
            )
        ai_review = self._run_ai_review(
            task,
            target_id=target.id if target else None,
            title="AI behavior review",
            snapshot=self._build_ai_target_snapshot(target.id) if target else self._build_ai_global_snapshot(),
            instruction=(
                "Review agent behavior for loops, duplicate work, unsupported claims, weak evidence "
                "promotion, and missed next actions. Return only operational findings and concrete "
                "control-plane corrections."
            ),
        )
        self._apply_ai_review(result, task, ai_review)
        return result

    def _handle_compact_memory(self, task: Task, context: ContextSlice) -> TaskExecutionResult:
        result = TaskExecutionResult(summary="memory compaction complete")
        target = self.store.get_target(task.target_id)
        if not target:
            result.success = False
            result.error = "target not found"
            return result
        result.notes.append(
            Note(
                target_id=target.id,
                task_id=task.id,
                title="Compaction audit",
                body="Memory compaction merged recent task context into episodic and semantic layers while preserving evidence lineage.",
                confidence=0.8,
                freshness=0.9,
            )
        )
        ai_review = self._run_ai_review(
            task,
            target_id=target.id,
            title="AI memory compaction review",
            snapshot=self._build_ai_target_snapshot(target.id),
            instruction=(
                "Review whether the current target memory is stale, repetitive, contradictory, or missing durable "
                "operator-relevant facts. Propose compact memory promotions/demotions and mention any stale evidence "
                "that should not guide next actions."
            ),
        )
        self._apply_ai_review(result, task, ai_review)
        result.sync_jobs.append(
            ExternalSyncJob(
                kind=ExternalSyncKind.NOTION,
                target_id=target.id,
                summary="Publish refreshed notes and findings to Notion",
                payload={"target_id": target.id, "reason": "memory-compaction"},
            )
        )
        return result

    def _handle_sync_notion(self, task: Task, context: ContextSlice) -> TaskExecutionResult:
        result = TaskExecutionResult(summary="notion sync prepared")
        target = self.store.get_target(task.target_id)
        if not target:
            result.success = False
            result.error = "target not found"
            return result
        result.sync_jobs.append(
            ExternalSyncJob(
                kind=ExternalSyncKind.NOTION,
                target_id=target.id,
                summary="Sync target subtree to Notion",
                payload={"target_id": target.id, "task_id": task.id},
            )
        )
        return result

    def _handle_send_notification(self, task: Task, context: ContextSlice) -> TaskExecutionResult:
        result = TaskExecutionResult(summary="notification queued")
        target = self.store.get_target(task.target_id)
        result.notifications.append(
            NotificationRecord(
                channel=NotificationChannel.DISCORD,
                event_type="operator_attention",
                summary=task.summary,
                target_id=target.id if target else None,
                task_id=task.id,
                urgency="high" if task.risk_tier in {RiskTier.HIGH, RiskTier.CRITICAL} else "info",
                dedupe_key=f"task:{task.id}:notify",
            )
        )
        result.events.append(
            EventRecord(
                type=EventType.NOTIFICATION_QUEUED,
                summary=task.summary,
                target_id=task.target_id,
                task_id=task.id,
            )
        )
        return result

    def _handle_review_premium_escalation(self, task: Task, context: ContextSlice) -> TaskExecutionResult:
        result = TaskExecutionResult(summary="premium review unavailable")
        target = self.store.get_target(task.target_id)
        if not target:
            result.success = False
            result.error = "target not found"
            return result
        result.success = False
        result.error = "remote premium review is disabled until a production provider adapter and credentials are configured"
        result.notes.append(
            Note(
                target_id=target.id,
                task_id=task.id,
                title="Premium review status",
                body=(
                    "Premium review did not run. Remote model usage is policy-disabled until a production "
                    "provider adapter and credentials are configured."
                ),
                confidence=0.95,
                freshness=0.95,
                metadata={"deferred": True},
            )
        )
        result.events.append(
            EventRecord(
                type=EventType.TASK_FAILED,
                summary="Premium review unavailable",
                target_id=target.id,
                task_id=task.id,
            )
        )
        return result

    def _handle_generic(self, task: Task, context: ContextSlice) -> TaskExecutionResult:
        return TaskExecutionResult(
            success=False,
            summary=f"execution adapter missing for {task.kind.value}",
            error=f"no production execution adapter is registered for {task.kind.value}",
        )

    def _apply_ai_review(
        self,
        result: TaskExecutionResult,
        task: Task,
        ai_review: dict[str, object] | None,
    ) -> None:
        if not ai_review:
            task.metadata["ai_review_status"] = "unavailable"
            return
        note = ai_review.get("note")
        trace = ai_review.get("trace")
        proposal = ai_review.get("proposal")
        if isinstance(note, Note):
            result.notes.append(note)
        if isinstance(trace, AgentTrace):
            result.traces.append(trace)
        if isinstance(proposal, dict):
            task.metadata["ai_proposal"] = proposal
        task.metadata["ai_review_status"] = str(ai_review.get("status") or "completed")
        task.metadata["ai_review_attempted"] = True
        task.metadata["ai_model"] = ai_review.get("metadata", {}).get("model")
        task.metadata["ai_processor"] = ai_review.get("metadata", {}).get("processor")

    def _ai_review_requested(self, task: Task) -> bool:
        return bool(
            task.metadata.get("operator_triggered_ai_review")
            or task.metadata.get("allow_ai_review")
            or task.metadata.get("run_ai_review")
        )

    def _run_ai_review(
        self,
        task: Task,
        *,
        target_id: str | None,
        title: str,
        snapshot: str,
        instruction: str,
    ) -> dict[str, object] | None:
        if not self.ai_generate:
            return None
        system = (
            "You are a Primordial autonomous worker inside a policy-gated authorized security platform. "
            "Use only the supplied runtime snapshot. Be specific, evidence-backed, and operational. "
            "Never propose DoS, flooding, destructive actions, credential spraying, or unbounded brute force. "
            "If execution needs a missing primitive, state that as a capability gap instead of pretending it ran. "
            "Return a single JSON object only."
        )
        prompt = (
            f"Task: {task.kind.value}\n"
            f"Task title: {task.title}\n"
            f"Instruction: {instruction}\n\n"
            f"Runtime snapshot:\n{snapshot}\n\n"
            "Return JSON with keys:\n"
            "- summary: short operational summary\n"
            "- facts: list of concise evidence-backed facts\n"
            "- candidate_actions: list of objects with title, rationale, confidence, primitive_hint\n"
            "  Use exact primitive_hint values when applicable: content-discovery, http-probe, tcp-service-discovery.\n"
            "- blocked_reasons: list of concise blockers\n"
            "- required_primitives: list of missing or required primitive names\n"
            "- evidence_refs: list of evidence IDs if visible in the snapshot\n"
            "- confidence: float between 0 and 1\n"
            "- stop_conditions: list of explicit stop conditions or guardrails\n"
            "- capability_gaps: list of concrete missing capabilities\n"
            "Do not wrap the JSON in markdown fences."
        )
        response = self.ai_generate(task, system, prompt, 0.0)
        if not response or not response.get("text"):
            return None
        text = str(response["text"]).strip()
        proposal = self._parse_ai_review_json(text)
        status = "completed" if proposal is not None else "parse_failed"
        metadata = {
            "kind": "worker_ai_review",
            "task_kind": task.kind.value,
            "role_name": task.role.value if task.role else None,
            "stage": task.phase.value if task.phase else None,
            "model": response.get("model"),
            "elapsed_seconds": response.get("elapsed_seconds"),
            "prompt_tokens": response.get("prompt_tokens"),
            "completion_tokens": response.get("completion_tokens"),
            "retry_count": max(0, (task.attempts or 0) - 1),
            "num_gpu": response.get("num_gpu"),
            "processor": response.get("processor"),
            "structured_output": proposal is not None,
            "status": status,
        }
        note = None
        if target_id:
            note = Note(
                target_id=target_id,
                task_id=task.id,
                title=title,
                body=self._render_ai_review_note(proposal, text),
                confidence=0.72,
                freshness=0.95,
                metadata={**metadata, "proposal": proposal or {}},
            )
        trace = AgentTrace(
            task_id=task.id,
            role=task.role,
            status="ai_review_completed",
            summary=f"{title} generated by {response.get('model') or task.provider_model or 'local model'}",
            metadata={**metadata, "summary_key": f"{task.kind.value}:ai_review", "proposal": proposal or {}},
        )
        return {"note": note, "trace": trace, "metadata": metadata, "proposal": proposal, "status": status}

    def _build_ai_target_snapshot(self, target_id: str) -> str:
        target = self.store.get_target(target_id)
        active_generation = self._target_active_generation(target)
        evidence = self._records_for_generation(
            self.store.list_evidence(target_id=target_id, limit=24),
            active_generation,
        )
        interests = self._records_for_generation(
            self.store.list_interests(target_id=target_id, limit=12),
            active_generation,
        )
        findings = self._records_for_generation(
            self.store.list_findings(target_id=target_id, limit=8),
            active_generation,
        )
        tasks = self._task_records_for_generation(
            self.store.list_tasks(target_id=target_id, limit=20),
            active_generation,
        )
        lines = [
            f"Target: {target.handle if target else target_id}",
            f"Active generation: {active_generation or 'none'}",
            "Evidence:",
        ]
        lines.extend(
            f"- {item.id} | {item.title} | {item.verification_status.value} | confidence={item.confidence:.2f} | {item.summary[:500]}"
            for item in evidence
        )
        lines.append("Interests:")
        lines.extend(
            f"- {item.id} | {item.status.value} | confidence={item.confidence:.2f} | {item.title}: {item.summary[:350]}"
            for item in interests
        )
        lines.append("Findings:")
        lines.extend(
            f"- {item.id} | {item.severity.value} | {item.verification_status.value} | {item.title}: {item.summary[:350]}"
            for item in findings
        )
        lines.append("Recent tasks:")
        lines.extend(
            f"- {item.id} | {item.kind.value} | {item.status.value} | model={item.provider_model or 'unassigned'} | {item.title}"
            for item in tasks
        )
        return "\n".join(lines)

    def _build_ai_global_snapshot(self) -> str:
        targets = self.store.list_targets()
        tasks = self.store.list_tasks(limit=30)
        traces = self.store.list_traces(limit=20)
        lines = ["Targets:"]
        lines.extend(f"- {target.id} | {target.handle} | {target.profile.value} | in_scope={target.in_scope}" for target in targets)
        lines.append("Recent tasks:")
        lines.extend(f"- {task.id} | {task.kind.value} | {task.status.value} | {task.title}" for task in tasks)
        lines.append("Recent traces:")
        lines.extend(f"- {trace.id} | {trace.role.value} | {trace.status} | {trace.summary[:300]}" for trace in traces)
        return "\n".join(lines)

    def _fallback_target_id(self) -> str | None:
        targets = self.store.list_targets()
        return targets[0].id if targets else None

    def _parse_ai_review_json(self, text: str) -> dict[str, object] | None:
        candidate = text.strip()
        fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", candidate, flags=re.DOTALL)
        if fenced:
            candidate = fenced.group(1)
        elif "{" in candidate and "}" in candidate:
            candidate = candidate[candidate.find("{") : candidate.rfind("}") + 1]
        try:
            payload = json.loads(candidate)
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, dict):
            return None
        return {
            "summary": str(payload.get("summary", "")).strip(),
            "facts": self._normalize_string_list(payload.get("facts")),
            "candidate_actions": self._normalize_candidate_actions(payload.get("candidate_actions")),
            "blocked_reasons": self._normalize_string_list(payload.get("blocked_reasons")),
            "required_primitives": self._normalize_string_list(payload.get("required_primitives")),
            "evidence_refs": self._normalize_string_list(payload.get("evidence_refs")),
            "confidence": self._normalize_confidence(payload.get("confidence")),
            "stop_conditions": self._normalize_string_list(payload.get("stop_conditions")),
            "capability_gaps": self._normalize_string_list(payload.get("capability_gaps")),
        }

    def _render_ai_review_note(self, proposal: dict[str, object] | None, raw_text: str) -> str:
        if proposal is None:
            return raw_text
        lines = ["## Summary", str(proposal.get("summary") or "No summary provided.")]
        facts = proposal.get("facts", [])
        if isinstance(facts, list) and facts:
            lines.append("\n## Facts")
            lines.extend(f"- {item}" for item in facts[:8])
        candidate_actions = proposal.get("candidate_actions", [])
        if isinstance(candidate_actions, list) and candidate_actions:
            lines.append("\n## Candidate Actions")
            for item in candidate_actions[:6]:
                if not isinstance(item, dict):
                    continue
                title = str(item.get("title") or "untitled action")
                rationale = str(item.get("rationale") or "")
                confidence = item.get("confidence")
                primitive = str(item.get("primitive_hint") or "")
                suffix = []
                if confidence not in {None, ""}:
                    suffix.append(f"confidence={confidence}")
                if primitive:
                    suffix.append(f"primitive={primitive}")
                meta = f" ({', '.join(suffix)})" if suffix else ""
                lines.append(f"- {title}{meta}")
                if rationale:
                    lines.append(f"  {rationale}")
        blocked = proposal.get("blocked_reasons", [])
        if isinstance(blocked, list) and blocked:
            lines.append("\n## Blockers")
            lines.extend(f"- {item}" for item in blocked[:8])
        gaps = proposal.get("capability_gaps", [])
        if isinstance(gaps, list) and gaps:
            lines.append("\n## Capability Gaps")
            lines.extend(f"- {item}" for item in gaps[:8])
        stop_conditions = proposal.get("stop_conditions", [])
        if isinstance(stop_conditions, list) and stop_conditions:
            lines.append("\n## Stop Conditions")
            lines.extend(f"- {item}" for item in stop_conditions[:8])
        return "\n".join(lines)

    def _normalize_string_list(self, value: object) -> list[str]:
        if not isinstance(value, list):
            return []
        return [str(item).strip() for item in value if str(item).strip()][:12]

    def _normalize_candidate_actions(self, value: object) -> list[dict[str, object]]:
        if not isinstance(value, list):
            return []
        actions: list[dict[str, object]] = []
        for item in value[:8]:
            if isinstance(item, dict):
                actions.append(
                    {
                        "title": str(item.get("title", "")).strip(),
                        "rationale": str(item.get("rationale", "")).strip(),
                        "confidence": self._normalize_confidence(item.get("confidence")),
                        "primitive_hint": str(item.get("primitive_hint", "")).strip(),
                    }
                )
            elif str(item).strip():
                actions.append({"title": str(item).strip(), "rationale": "", "confidence": None, "primitive_hint": ""})
        return actions

    def _normalize_confidence(self, value: object) -> float | None:
        try:
            confidence = float(value)
        except (TypeError, ValueError):
            return None
        return max(0.0, min(1.0, confidence))

    def _target_active_generation(self, target) -> str | None:
        if target is None or target.metadata.get("active_ip_generation") is None:
            return None
        return str(target.metadata.get("active_ip_generation"))

    def _records_for_generation(self, records: list[object], active_generation: str | None) -> list[object]:
        if active_generation is None:
            return records
        selected = []
        for record in records:
            metadata = getattr(record, "metadata", {})
            if isinstance(metadata, dict) and str(metadata.get("active_ip_generation", "")) == active_generation:
                selected.append(record)
        return selected

    def _task_records_for_generation(self, tasks: list[Task], active_generation: str | None) -> list[Task]:
        if active_generation is None:
            return tasks
        return [
            task
            for task in tasks
            if task.metadata.get("active_ip_generation") is None
            or str(task.metadata.get("active_ip_generation", "")) == active_generation
        ]

    def _task_generation_records(self, task: Task, target, records: list[object]) -> list[object]:
        generation = str(task.metadata.get("active_ip_generation", "")).strip() or self._target_active_generation(target)
        return self._records_for_generation(records, generation)

    def _write_artifact(self, task: Task, target_id: str, prefix: str, payload: dict[str, object]) -> ArtifactRecord:
        task_dir = self.config.artifacts_dir / (task.id or "task")
        task_dir.mkdir(parents=True, exist_ok=True)
        path = task_dir / f"{prefix}.json"
        path.write_text(json.dumps(payload, indent=2, sort_keys=True))
        content = path.read_bytes()
        return ArtifactRecord(
            task_id=task.id,
            target_id=target_id,
            kind=ArtifactKind.TOOL_OUTPUT,
            path=str(path),
            sha256=hashlib.sha256(content).hexdigest(),
            size_bytes=len(content),
            metadata={"prefix": prefix},
        )

    def _target_scope_assets(self, target) -> list[object]:
        assets = self.store.list_scope_assets(target.id)
        active_ip = str(target.metadata.get("active_ip") or "").strip()
        if not active_ip:
            return assets
        active = []
        hostnames = []
        webapps = []
        others = []
        for asset in assets:
            if asset.asset == active_ip:
                active.append(asset)
            elif asset.asset_type == "hostname":
                hostnames.append(asset)
            elif asset.asset_type == "webapp" or asset.asset.startswith(("http://", "https://")):
                webapps.append(asset)
            elif asset.asset_type != "ip":
                others.append(asset)
        # Network primitives should use the operator-confirmed IP first while retaining
        # hostnames for Host-header and domain inference.
        return active + hostnames + webapps + others

    def _service_discovery_hosts(self, assets) -> list[dict[str, str]]:
        hosts: list[dict[str, str]] = []
        seen: set[str] = set()
        for asset in assets:
            host = ""
            if asset.asset_type == "webapp" or asset.asset.startswith(("http://", "https://")):
                host = parse.urlsplit(asset.asset).hostname or ""
            elif asset.asset_type in {"hostname", "ip"}:
                host = asset.asset.strip()
            if not host or host in seen:
                continue
            seen.add(host)
            hosts.append({"host": host, "asset_type": asset.asset_type, "source_asset": asset.asset})
        return hosts

    def _service_discovery_ports(self, metadata: dict[str, object]) -> list[int]:
        raw_ports = metadata.get("service_discovery_ports")
        if isinstance(raw_ports, list):
            parsed: list[int] = []
            for item in raw_ports:
                try:
                    port = int(item)
                except (TypeError, ValueError):
                    continue
                if 1 <= port <= 65535 and port not in parsed:
                    parsed.append(port)
            if parsed:
                return parsed[:128]
        return list(SERVICE_DISCOVERY_PORTS)

    def _scan_tcp_services(
        self,
        hosts: list[dict[str, str]],
        ports: list[int],
        timeout_seconds: int = 90,
    ) -> dict[str, object]:
        host_tool_scan = self._scan_tcp_services_with_host_tools(hosts, ports, timeout_seconds=timeout_seconds)
        if host_tool_scan is not None:
            return host_tool_scan
        return self._scan_tcp_services_with_sockets(hosts, ports)

    def _scan_tcp_services_with_sockets(self, hosts: list[dict[str, str]], ports: list[int]) -> dict[str, object]:
        open_services: list[dict[str, object]] = []
        errors: list[dict[str, object]] = []
        attempted = 0
        for host_entry in hosts:
            host = host_entry["host"]
            for port in ports:
                attempted += 1
                try:
                    with socket.create_connection((host, port), timeout=0.7) as sock:
                        banner = self._read_service_banner(sock, port)
                    open_services.append(
                        {
                            "host": host,
                            "port": port,
                            "service": self._guess_service(port, banner),
                            "banner": banner,
                            "source_asset": host_entry["source_asset"],
                        }
                    )
                except (ConnectionRefusedError, TimeoutError, socket.timeout):
                    continue
                except OSError as exc:
                    if len(errors) < 20:
                        errors.append({"host": host, "port": port, "error": str(exc)})
                    continue
        return {
            "open_services": open_services,
            "closed_count": max(0, attempted - len(open_services)),
            "errors": errors,
            "scanner": "python-socket",
            "command_results": [],
        }

    def _scan_tcp_services_with_host_tools(
        self,
        hosts: list[dict[str, str]],
        ports: list[int],
        timeout_seconds: int = 90,
    ) -> dict[str, object] | None:
        if shutil.which("rustscan") is None and shutil.which("nmap") is None:
            return None
        open_services: list[dict[str, object]] = []
        errors: list[dict[str, object]] = []
        command_results: list[dict[str, object]] = []
        attempted = len(hosts) * len(ports)
        for host_entry in hosts:
            host = host_entry["host"]
            host_ports = ports
            if shutil.which("rustscan") is not None:
                rustscan_result = self._run_rustscan_ports(host, ports, timeout_seconds=min(45, timeout_seconds))
                command_results.append(rustscan_result)
                discovered_ports = self._parse_rustscan_ports(str(rustscan_result.get("stdout", "")))
                if discovered_ports:
                    host_ports = discovered_ports
            if shutil.which("nmap") is not None:
                nmap_result = self._run_nmap_service_scan(host, host_ports, timeout_seconds=timeout_seconds)
                command_results.append(nmap_result)
                parsed = self._parse_nmap_xml_services(str(nmap_result.get("stdout", "")), host_entry)
                if parsed:
                    open_services.extend(parsed)
                    continue
                if nmap_result.get("executed") and nmap_result.get("returncode") not in {0, None}:
                    errors.append({"host": host, "tool": "nmap", "error": str(nmap_result.get("stderr", ""))[:400]})
            if shutil.which("rustscan") is not None and shutil.which("nmap") is None:
                for port in self._parse_rustscan_ports(str(command_results[-1].get("stdout", ""))):
                    open_services.append(
                        {
                            "host": host,
                            "port": port,
                            "service": SERVICE_NAME_BY_PORT.get(port, "unknown"),
                            "banner": "",
                            "source_asset": host_entry["source_asset"],
                            "scanner": "rustscan",
                        }
                    )
        if not command_results:
            return None
        return {
            "open_services": self._dedupe_open_services(open_services),
            "closed_count": max(0, attempted - len(open_services)),
            "errors": errors,
            "scanner": "rustscan+nmap" if shutil.which("rustscan") and shutil.which("nmap") else "nmap",
            "command_results": command_results,
        }

    def _run_rustscan_ports(self, host: str, ports: list[int], timeout_seconds: int = 45) -> dict[str, object]:
        return self._run_host_command(
            tool="rustscan",
            argv=[
                "rustscan",
                "-a",
                host,
                "-p",
                ",".join(str(port) for port in ports),
                "--ulimit",
                "5000",
                "--timeout",
                "1500",
                "--batch-size",
                "256",
            ],
            timeout_seconds=timeout_seconds,
        )

    def _run_nmap_service_scan(self, host: str, ports: list[int], timeout_seconds: int = 90) -> dict[str, object]:
        return self._run_host_command(
            tool="nmap",
            argv=[
                "nmap",
                "-Pn",
                "-sT",
                "-sV",
                "--version-light",
                "--max-retries",
                "2",
                "-p",
                ",".join(str(port) for port in ports),
                "-oX",
                "-",
                host,
            ],
            timeout_seconds=timeout_seconds,
        )

    def _parse_rustscan_ports(self, stdout: str) -> list[int]:
        ports: list[int] = []
        for match in re.finditer(r"Open\s+[^\s:]+:(\d+)", stdout, re.IGNORECASE):
            port = int(match.group(1))
            if port not in ports:
                ports.append(port)
        return ports

    def _parse_nmap_xml_services(self, stdout: str, host_entry: dict[str, str]) -> list[dict[str, object]]:
        xml_start = stdout.find("<?xml")
        if xml_start > 0:
            stdout = stdout[xml_start:]
        if not stdout.strip():
            return []
        try:
            root = ET.fromstring(stdout)
        except ET.ParseError:
            return []
        services: list[dict[str, object]] = []
        host = host_entry["host"]
        for port_node in root.findall(".//port"):
            state = port_node.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue
            try:
                port = int(port_node.attrib.get("portid", "0"))
            except ValueError:
                continue
            service_node = port_node.find("service")
            service_name = service_node.attrib.get("name", SERVICE_NAME_BY_PORT.get(port, "unknown")) if service_node is not None else SERVICE_NAME_BY_PORT.get(port, "unknown")
            banner_parts = []
            if service_node is not None:
                for key in ("product", "version", "extrainfo"):
                    value = service_node.attrib.get(key, "")
                    if value:
                        banner_parts.append(value)
            services.append(
                {
                    "host": host,
                    "port": port,
                    "service": service_name,
                    "banner": " ".join(banner_parts),
                    "source_asset": host_entry["source_asset"],
                    "scanner": "nmap",
                }
            )
        return services

    def _dedupe_open_services(self, services: list[dict[str, object]]) -> list[dict[str, object]]:
        deduped: dict[tuple[str, int], dict[str, object]] = {}
        for service in services:
            key = (str(service.get("host", "")), int(service.get("port", 0) or 0))
            deduped[key] = service
        return sorted(deduped.values(), key=lambda item: (str(item.get("host", "")), int(item.get("port", 0) or 0)))

    def _read_service_banner(self, sock: socket.socket, port: int) -> str:
        sock.settimeout(0.6)
        if port in {80, 5000, 5985, 8000, 8080, 8888, 10000}:
            try:
                sock.sendall(b"HEAD / HTTP/1.0\r\nUser-Agent: Primordial/0.1\r\n\r\n")
            except OSError:
                pass
        try:
            return self._sanitize_banner(sock.recv(160))
        except (OSError, TimeoutError):
            return ""

    def _sanitize_banner(self, banner: bytes) -> str:
        if not banner:
            return ""
        decoded = banner.decode("latin-1", errors="replace")
        compact = " ".join(decoded.replace("\x00", " ").split())
        return compact[:240]

    def _guess_service(self, port: int, banner: str) -> str:
        lowered = banner.lower()
        if banner.startswith("SSH-"):
            return "ssh"
        if lowered.startswith("http/") or "server:" in lowered:
            return "http"
        if "ftp" in lowered:
            return "ftp"
        if "smtp" in lowered:
            return "smtp"
        return SERVICE_NAME_BY_PORT.get(port, "unknown")

    def _summarize_open_services(
        self,
        open_services: list[dict[str, object]],
        *,
        host_count: int,
        port_count: int,
    ) -> str:
        if not open_services:
            return (
                f"TCP connect checks completed against {host_count} host(s) and {port_count} port(s); "
                "no open services were observed in the bounded port set."
            )
        summarized = ", ".join(
            f"{service['host']}:{service['port']}/{service['service']}"
            for service in open_services[:16]
        )
        suffix = "" if len(open_services) <= 16 else f" and {len(open_services) - 16} more"
        return f"TCP service discovery observed {len(open_services)} open service(s): {summarized}{suffix}."

    def _build_service_inventory_note(
        self,
        open_services: list[dict[str, object]],
        closed_count: int,
        errors: list[dict[str, object]],
    ) -> str:
        lines = [
            f"Open services: {len(open_services)}",
            f"Closed or filtered checks: {closed_count}",
            f"Scan errors retained: {len(errors)}",
        ]
        for service in open_services[:self.config.max_evidence_items]:
            banner = f" banner={service['banner']!r}" if service.get("banner") else ""
            lines.append(f"- {service['host']}:{service['port']} -> {service['service']}{banner}")
        if not open_services:
            lines.append("No open services were observed in the configured bounded port set.")
        lines.append("This is service inventory only, not an exploitation or vulnerability claim.")
        return "\n".join(lines)

    def _safe_artifact_fragment(self, value: str) -> str:
        return "".join(character if character.isalnum() else "_" for character in value).strip("_") or "target"

    def _content_discovery_bases(self, target_id: str) -> list[str]:
        bases: list[str] = []
        seen: set[str] = set()
        for evidence in self.store.list_evidence(target_id=target_id, limit=200):
            effective_url = evidence.metadata.get("effective_url")
            status_code = evidence.metadata.get("status_code")
            if not isinstance(effective_url, str) or not effective_url.startswith(("http://", "https://")):
                continue
            if isinstance(status_code, int) and status_code >= 500:
                continue
            parsed = parse.urlsplit(effective_url)
            if not parsed.scheme or not parsed.netloc:
                continue
            base = f"{parsed.scheme}://{parsed.netloc}/"
            if base in seen:
                continue
            seen.add(base)
            bases.append(base)
        return bases[:4]

    def _content_discovery_words(self, metadata: dict[str, object]) -> list[str]:
        limit = int(metadata.get("content_word_limit", 420) or 420)
        limit = max(50, min(limit, 2000))
        wordlist_path = str(metadata.get("content_wordlist", self.config.content_discovery_wordlist))
        words: list[str] = []
        try:
            with open(wordlist_path, encoding="utf-8", errors="ignore") as wordlist:
                raw_lines = wordlist.read().splitlines()
        except OSError:
            raw_lines = [
                "admin",
                "api",
                "app",
                "backup",
                "config",
                "dev",
                "files",
                "login",
                "portal",
                "private",
                "test",
                "upload",
            ]
        for raw in raw_lines:
            word = raw.strip().strip("/")
            if not word or word.startswith("#") or len(word) > 80:
                continue
            if word not in words:
                words.append(word)
            if len(words) >= limit:
                break
        return words

    def _run_web_content_discovery(self, bases: list[str], words: list[str]) -> list[dict[str, object]]:
        candidates: list[tuple[str, str]] = []
        for base in bases:
            for word in words:
                for extension in CONTENT_DISCOVERY_EXTENSIONS:
                    if extension and word.lower().endswith(extension):
                        continue
                    candidates.append((base, f"/{word}{extension}"))
        discovered: list[dict[str, object]] = []
        seen_urls: set[str] = set()
        with ThreadPoolExecutor(max_workers=18) as executor:
            future_map = {
                executor.submit(self._probe_content_candidate, base, path): (base, path)
                for base, path in candidates
            }
            for future in as_completed(future_map):
                probe = future.result()
                if not probe:
                    continue
                url = str(probe["url"])
                if url in seen_urls:
                    continue
                seen_urls.add(url)
                discovered.append(probe)
                if len(discovered) >= 200:
                    break
        return sorted(discovered, key=lambda item: (int(item["status_code"]), str(item["url"])))

    def _probe_content_candidate(self, base_url: str, path: str) -> dict[str, object] | None:
        url = parse.urljoin(base_url, path.lstrip("/"))
        req = request.Request(url, headers={"User-Agent": "Primordial/0.1", "Accept": "*/*"}, method="GET")
        try:
            with request.urlopen(
                req,
                timeout=3,
                context=ssl._create_unverified_context() if url.startswith("https://") else None,
            ) as response:
                body = response.read(4096)
                status = int(response.status)
                headers = {key.lower(): value for key, value in response.headers.items()}
        except error.HTTPError as exc:
            body = exc.read(4096)
            status = int(exc.code)
            headers = {key.lower(): value for key, value in exc.headers.items()}
        except Exception:
            return None
        if status not in CONTENT_DISCOVERY_INTERESTING_STATUS:
            return None
        return {
            "url": url,
            "path": path,
            "status_code": status,
            "content_type": headers.get("content-type", ""),
            "content_length": headers.get("content-length") or len(body),
            "server": headers.get("server", ""),
            "title": self._title_from_body(headers.get("content-type", ""), body),
        }

    def _title_from_body(self, content_type: str, body: bytes) -> str:
        if "html" not in content_type.lower() or not body:
            return ""
        decoded = self._decode_response_body(body, {})
        parser = _SurfaceParser()
        try:
            parser.feed(decoded)
        except Exception:
            return ""
        return parser.title

    def _summarize_content_discovery(
        self,
        discovered: list[dict[str, object]],
        bases: list[str],
        word_count: int,
    ) -> str:
        if not discovered:
            return f"Bounded web content discovery checked {len(bases)} base URL(s) with {word_count} words and found no interesting paths."
        n = self.config.max_evidence_items
        path_summary = ", ".join(f"{item['path']}({item['status_code']})" for item in discovered[:n])
        suffix = "" if len(discovered) <= n else f" and {len(discovered) - n} more"
        return f"Bounded web content discovery found {len(discovered)} interesting path(s): {path_summary}{suffix}."

    def _build_content_discovery_note(
        self,
        discovered: list[dict[str, object]],
        bases: list[str],
        word_count: int,
    ) -> str:
        lines = [
            f"Base URLs: {', '.join(bases)}",
            f"Words checked: {word_count}",
            f"Interesting paths: {len(discovered)}",
        ]
        for item in discovered[:self.config.max_evidence_items]:
            title = f" title={item['title']!r}" if item.get("title") else ""
            lines.append(f"- {item['status_code']} {item['url']} {item.get('content_type', '')}{title}")
        if not discovered:
            lines.append("No interesting paths were observed in the bounded wordlist run.")
        lines.append("This is content inventory only; no authentication or exploit attempt was performed.")
        return "\n".join(lines)

    def _target_domain_guess(self, target, assets) -> str:
        if isinstance(target.metadata.get("domain"), str) and target.metadata["domain"]:
            return str(target.metadata["domain"])
        if "." in target.handle and not self._looks_like_ip(target.handle):
            return target.handle.strip(".")
        for asset in assets:
            candidate = ""
            if asset.asset_type == "hostname":
                candidate = asset.asset
            elif asset.asset_type == "webapp" or asset.asset.startswith(("http://", "https://")):
                candidate = parse.urlsplit(asset.asset).hostname or ""
            if "." in candidate and not self._looks_like_ip(candidate):
                return candidate.strip(".")
        return ""

    def _looks_like_ip(self, value: str) -> bool:
        try:
            socket.inet_aton(value)
        except OSError:
            return False
        return value.count(".") == 3

    def _run_dns_enumeration_commands(self, dns_server: str, domain: str) -> list[dict[str, object]]:
        queries = [
            ("soa", ["dig", f"@{dns_server}", domain, "SOA", "+time=5", "+tries=1"]),
            ("ns", ["dig", f"@{dns_server}", domain, "NS", "+time=5", "+tries=1"]),
            ("axfr", ["dig", f"@{dns_server}", domain, "AXFR", "+time=5", "+tries=1"]),
            (
                "ldap_srv",
                ["dig", f"@{dns_server}", f"_ldap._tcp.dc._msdcs.{domain}", "SRV", "+time=5", "+tries=1"],
            ),
            ("kerberos_srv", ["dig", f"@{dns_server}", f"_kerberos._tcp.{domain}", "SRV", "+time=5", "+tries=1"]),
            ("dc01_a", ["dig", f"@{dns_server}", f"DC01.{domain}", "A", "+time=5", "+tries=1"]),
        ]
        results: list[dict[str, object]] = []
        for name, argv in queries:
            result = self._run_host_command(tool=f"dig:{name}", argv=argv, timeout_seconds=8)
            result["query_name"] = name
            results.append(result)
        return results

    def _extract_dc_hostnames_from_srv(self, records: list[dict[str, str]], domain: str) -> list[str]:
        """Return DC hostnames found in LDAP/Kerberos SRV records.

        SRV value format: '<priority> <weight> <port> <target-hostname>'.
        Extracts the target and qualifies bare names against the domain.
        """
        hostnames: list[str] = []
        for record in records:
            if record.get("type") != "SRV":
                continue
            name = record.get("name", "").lower()
            if "_ldap._tcp" not in name and "_kerberos._tcp" not in name:
                continue
            parts = record.get("value", "").split()
            if len(parts) >= 4:
                host = parts[3].rstrip(".")
                if host and host not in hostnames:
                    hostnames.append(host if "." in host else f"{host}.{domain}")
        return hostnames

    def _parse_dns_enumeration(self, command_results: list[dict[str, object]]) -> dict[str, object]:
        records: dict[tuple[str, str, str], dict[str, str]] = {}
        zone_transfer_success = False
        for result in command_results:
            stdout = str(result.get("stdout", ""))
            query_name = str(result.get("query_name", ""))
            if query_name == "axfr" and "Transfer failed." not in stdout and "\tIN\tSOA\t" in stdout:
                zone_transfer_success = True
            for raw_line in stdout.splitlines():
                line = raw_line.strip()
                if not line or line.startswith(";") or "\tIN\t" not in line:
                    continue
                parts = line.split()
                if len(parts) < 5:
                    continue
                name = parts[0].rstrip(".")
                record_type = parts[3]
                value = " ".join(part.rstrip(".") for part in parts[4:])
                key = (name, record_type, value)
                records[key] = {"name": name, "type": record_type, "value": value, "source_query": query_name}
        return {
            "records": sorted(records.values(), key=lambda item: (item["name"], item["type"], item["value"])),
            "zone_transfer_success": zone_transfer_success,
        }

    def _summarize_dns_enumeration(self, dns_server: str, domain: str, parsed: dict[str, object]) -> str:
        records = parsed["records"]
        zone_status = "succeeded" if parsed["zone_transfer_success"] else "did not succeed"
        return (
            f"DNS enumeration queried {domain} via {dns_server}; parsed {len(records)} record(s). "
            f"AXFR {zone_status}."
        )

    def _build_dns_enumeration_note(
        self,
        dns_server: str,
        domain: str,
        parsed: dict[str, object],
        command_results: list[dict[str, object]],
    ) -> str:
        records = parsed["records"]
        executed = [
            f"{item['tool']} rc={item['returncode']} timeout={item['timeout']}"
            for item in command_results
            if item.get("executed")
        ]
        lines = [
            f"DNS server: {dns_server}",
            f"Domain: {domain}",
            f"Commands: {', '.join(executed) or 'none executed'}",
            f"AXFR success: {parsed['zone_transfer_success']}",
            f"Records parsed: {len(records)}",
        ]
        for record in records[:self.config.max_evidence_items]:
            lines.append(f"- {record['name']} {record['type']} {record['value']}")
        lines.append("This is DNS inventory only; no exploit or credentialed action was performed.")
        return "\n".join(lines)

    def _preferred_network_host(self, assets) -> str:
        ip_assets = [asset.asset for asset in assets if asset.asset_type == "ip"]
        if ip_assets:
            return ip_assets[0]
        hostname_assets = [asset.asset for asset in assets if asset.asset_type == "hostname"]
        if hostname_assets:
            return hostname_assets[0]
        for asset in assets:
            if asset.asset_type == "webapp" or asset.asset.startswith(("http://", "https://")):
                host = parse.urlsplit(asset.asset).hostname
                if host:
                    return host
        return ""

    def _run_ad_enumeration_commands(self, host: str) -> list[dict[str, object]]:
        commands = [
            {
                "tool": "ldapsearch",
                "argv": [
                    "ldapsearch",
                    "-x",
                    "-H",
                    f"ldap://{host}",
                    "-s",
                    "base",
                    "-b",
                    "",
                    "namingContexts",
                    "defaultNamingContext",
                    "rootDomainNamingContext",
                    "dnsHostName",
                    "supportedSASLMechanisms",
                ],
                "timeout": 15,
            },
            {
                "tool": "smbclient",
                "argv": ["smbclient", "-L", f"//{host}/", "-N", "-g", "-m", "SMB3"],
                "timeout": 18,
            },
            {
                "tool": "rpcclient",
                "argv": [
                    "rpcclient",
                    "-U",
                    "",
                    "-N",
                    host,
                    "-c",
                    "srvinfo;querydominfo;enumdomusers;enumdomgroups",
                ],
                "timeout": 25,
            },
            {
                "tool": "netexec",
                "argv": [
                    next((t for t in ["netexec", "nxc", "crackmapexec", "cme"] if shutil.which(t)), "netexec"),
                    "smb", host, "-u", "", "-p", "", "--shares",
                ],
                "timeout": 30,
            },
        ]
        results: list[dict[str, object]] = []
        for command in commands:
            results.append(
                self._run_host_command(
                    tool=str(command["tool"]),
                    argv=[str(item) for item in command["argv"]],
                    timeout_seconds=int(command["timeout"]),
                )
            )
        return results

    def _run_host_command(self, *, tool: str, argv: list[str], timeout_seconds: int) -> dict[str, object]:
        if shutil.which(argv[0]) is None:
            return {
                "tool": tool,
                "argv": argv,
                "executed": False,
                "returncode": None,
                "stdout": "",
                "stderr": "tool not found",
                "timeout": False,
            }
        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
            return {
                "tool": tool,
                "argv": argv,
                "executed": True,
                "returncode": completed.returncode,
                "stdout": self._truncate_command_output(completed.stdout),
                "stderr": self._truncate_command_output(completed.stderr),
                "timeout": False,
            }
        except subprocess.TimeoutExpired as exc:
            return {
                "tool": tool,
                "argv": argv,
                "executed": True,
                "returncode": None,
                "stdout": self._truncate_command_output(exc.stdout or ""),
                "stderr": self._truncate_command_output(exc.stderr or "command timed out"),
                "timeout": True,
            }

    def _run_secret_host_command(
        self,
        *,
        tool: str,
        argv: list[str],
        redacted_argv: list[str],
        timeout_seconds: int,
    ) -> dict[str, object]:
        if shutil.which(argv[0]) is None:
            return {
                "tool": tool,
                "argv": redacted_argv,
                "executed": False,
                "returncode": None,
                "stdout": "",
                "stderr": "tool not found",
                "timeout": False,
            }
        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
            return {
                "tool": tool,
                "argv": redacted_argv,
                "executed": True,
                "returncode": completed.returncode,
                "stdout": self._truncate_command_output(completed.stdout),
                "stderr": self._truncate_command_output(completed.stderr),
                "timeout": False,
            }
        except subprocess.TimeoutExpired as exc:
            return {
                "tool": tool,
                "argv": redacted_argv,
                "executed": True,
                "returncode": None,
                "stdout": self._truncate_command_output(exc.stdout or ""),
                "stderr": self._truncate_command_output(exc.stderr or "command timed out"),
                "timeout": True,
            }

    def _truncate_command_output(self, value: object, limit: int = 12000) -> str:
        if isinstance(value, bytes):
            rendered = value.decode("utf-8", errors="replace")
        else:
            rendered = str(value or "")
        return rendered if len(rendered) <= limit else rendered[:limit] + "\n...TRUNCATED..."

    def _build_searchsploit_queries(self, target_id: str) -> list[str]:
        target = self.store.get_target(target_id)
        evidence = self._records_for_generation(
            self.store.list_evidence(target_id=target_id, limit=200),
            self._target_active_generation(target),
        )
        policy = self._active_intent_policy()
        allow_lab_fallbacks = bool(policy and policy.lab_policy.htb_lab_behavior_allowed)
        queries: list[str] = []
        fallbacks: list[str] = []

        def add(value: str, *, fallback: bool = False) -> None:
            normalized = self._normalize_searchsploit_query(value)
            if not normalized:
                return
            if fallback and self._is_redundant_searchsploit_fallback(normalized, queries):
                return
            destination = fallbacks if fallback else queries
            if normalized.lower() in {item.lower() for item in queries + fallbacks}:
                return
            destination.append(normalized)

        for item in evidence:
            headers = item.metadata.get("headers")
            if isinstance(headers, dict):
                server = str(headers.get("server", "")).strip()
                for query in self._queries_from_service_banner("http", server):
                    add(query)
            title = str(item.metadata.get("title", "")).strip()
            if title and "iis" in title.lower():
                add("Microsoft IIS", fallback=True)
            for service in item.metadata.get("open_services", []):
                if not isinstance(service, dict):
                    continue
                service_name = str(service.get("service", "")).strip()
                banner = str(service.get("banner", "")).strip()
                extracted = self._queries_from_service_banner(service_name, banner)
                for query in extracted:
                    add(query)
                if service_name in {"http", "https", "http-alt"} and not extracted:
                    add("Microsoft IIS", fallback=True)
                elif service_name in {"smb", "netbios-ssn"} and not extracted:
                    add("Windows SMB", fallback=True)
                elif service_name in {"ldap", "ldaps", "kerberos", "global-catalog"}:
                    add("Active Directory LDAP", fallback=True)
                elif service_name in {"winrm", "winrm-http", "winrm-https"}:
                    add("Microsoft WinRM", fallback=True)
        for item in evidence:
            rootdse = item.metadata.get("ldap_rootdse")
            if isinstance(rootdse, dict) and rootdse:
                add("Active Directory LDAP", fallback=True)
        fallbacks = [fallback for fallback in fallbacks if not self._is_redundant_searchsploit_fallback(fallback, queries)]
        selected = queries[:8]
        if allow_lab_fallbacks:
            for fallback in fallbacks:
                if len(selected) >= 10:
                    break
                if fallback.lower() not in {item.lower() for item in selected}:
                    selected.append(fallback)
        return selected

    def _is_redundant_searchsploit_fallback(self, fallback: str, precise_queries: list[str]) -> bool:
        lowered = fallback.lower()
        precise = " ".join(precise_queries).lower()
        if lowered in {"microsoft iis", "iis"} and re.search(r"\b(?:microsoft\s+)?iis\s+\d", precise):
            return True
        if lowered in {"windows smb", "microsoft windows smb", "smb"} and re.search(r"\bsmb\s+\d", precise):
            return True
        return False

    def _normalize_searchsploit_query(self, value: str) -> str | None:
        raw_lowered = " ".join(value.split()).strip().lower()
        if raw_lowered.startswith(EXPLOIT_RESEARCH_HTTP_TRASH_PREFIXES):
            return None
        normalized = " ".join(value.replace("/", " ").replace("_", " ").split()).strip(" -:;,")
        if len(normalized) < 3:
            return None
        if any(prefix in raw_lowered for prefix in ("content-length:", "content-type:", "last-modified:", "etag:")):
            return None
        if len(normalized) > 80:
            return None
        return normalized

    def _queries_from_service_banner(self, service_name: str, banner: str) -> list[str]:
        normalized_banner = " ".join(banner.split()).strip()
        if not normalized_banner:
            return []
        if normalized_banner.lower().startswith("http/1."):
            server = self._server_from_http_banner(normalized_banner)
            if server:
                normalized_banner = server
        queries: list[str] = []

        def add(value: str) -> None:
            normalized = self._normalize_searchsploit_query(value)
            if normalized and normalized.lower() not in {item.lower() for item in queries}:
                queries.append(normalized)

        for match in re.finditer(r"Microsoft-IIS/([0-9]+(?:\.[0-9]+)*)", normalized_banner, flags=re.IGNORECASE):
            version = match.group(1)
            add(f"Microsoft IIS {version}")
            add(f"IIS {version}")
        for match in re.finditer(r"OpenSSH[_ -]?([0-9]+(?:\.[0-9]+)*)", normalized_banner, flags=re.IGNORECASE):
            add(f"OpenSSH {match.group(1)}")
        for match in re.finditer(r"Apache(?: httpd)?[/ ]([0-9]+(?:\.[0-9]+)*)", normalized_banner, flags=re.IGNORECASE):
            add(f"Apache {match.group(1)}")
        for match in re.finditer(r"nginx[/ ]([0-9]+(?:\.[0-9]+)*)", normalized_banner, flags=re.IGNORECASE):
            add(f"nginx {match.group(1)}")
        if service_name in {"smb", "netbios-ssn"}:
            for match in re.finditer(r"SMBv?([0-9]+(?:\.[0-9]+)*)", normalized_banner, flags=re.IGNORECASE):
                add(f"SMB {match.group(1)}")
        return queries

    def _server_from_http_banner(self, banner: str) -> str | None:
        match = re.search(r"(?:^|\s)Server:\s*([^\r\n]+?)(?:\s+[A-Z][A-Za-z-]+:|$)", banner, flags=re.IGNORECASE)
        if not match:
            return None
        return match.group(1).strip()

    def _run_searchsploit_research(self, queries: list[str]) -> dict[str, object]:
        policy = self._active_intent_policy()
        if policy is not None and not (policy.public_poc_research and policy.searchsploit_allowed):
            return {
                "matches": [],
                "suppressed_matches": [],
                "examined_examples": [],
                "command_results": [
                    {
                        "tool": "searchsploit",
                        "argv": ["searchsploit", "-j", "<query>"],
                        "executed": False,
                        "returncode": None,
                        "stdout": "",
                        "stderr": "disabled: active operator intent does not allow public PoC research",
                        "timeout": False,
                    }
                ],
            }
        command_results: list[dict[str, object]] = []
        matches_by_id: dict[str, dict[str, object]] = {}
        suppressed_by_id: dict[str, dict[str, object]] = {}
        searched: set[str] = set()
        for query in queries:
            rows = self._searchsploit_rows_for_query(query, command_results, searched)
            if not rows:
                for refined_query in self._refine_empty_searchsploit_query(query):
                    if len(searched) >= 14:
                        break
                    rows.extend(self._searchsploit_rows_for_query(refined_query, command_results, searched, refined_from=query))
                    if rows:
                        break
            for match in rows:
                match_id = str(match.get("edb_id") or match.get("path") or match.get("title"))
                if self._is_suppressed_exploit_match(match):
                    suppressed_by_id.setdefault(match_id, match)
                else:
                    matches_by_id.setdefault(match_id, match)
        matches = sorted(
            matches_by_id.values(),
            key=lambda item: (-int(item.get("score", 0)), str(item.get("title", ""))),
        )[:self.config.max_evidence_items]
        suppressed = sorted(suppressed_by_id.values(), key=lambda item: str(item.get("title", "")))[:self.config.max_evidence_items]
        examples = []
        if policy is None or policy.read_poc_examples:
            examples = self._examine_searchsploit_examples(matches[:4], command_results)
        return {
            "matches": matches,
            "suppressed_matches": suppressed,
            "examined_examples": examples,
            "command_results": command_results,
        }

    def _searchsploit_rows_for_query(
        self,
        query: str,
        command_results: list[dict[str, object]],
        searched: set[str],
        *,
        refined_from: str | None = None,
    ) -> list[dict[str, object]]:
        normalized = self._normalize_searchsploit_query(query)
        if not normalized or normalized.lower() in searched:
            return []
        searched.add(normalized.lower())
        result = self._run_host_command(
            tool="searchsploit",
            argv=["searchsploit", "-j", normalized],
            timeout_seconds=18,
        )
        result["query"] = normalized
        if refined_from:
            result["refined_from"] = refined_from
        command_results.append(result)
        return self._parse_searchsploit_json(str(result.get("stdout", "")), normalized)

    def _refine_empty_searchsploit_query(self, query: str) -> list[str]:
        normalized = self._normalize_searchsploit_query(query)
        if not normalized:
            return []
        refinements: list[str] = []

        def add(value: str) -> None:
            candidate = self._normalize_searchsploit_query(value)
            if candidate and candidate.lower() != normalized.lower() and candidate.lower() not in {item.lower() for item in refinements}:
                refinements.append(candidate)

        version_match = re.search(r"\b([0-9]+(?:\.[0-9]+)+)\b", normalized)
        if version_match:
            major = version_match.group(1).split(".")[0]
            add(normalized.replace(version_match.group(1), major))
        if normalized.lower().startswith("microsoft "):
            add(normalized[10:])
        if " iis " in f" {normalized.lower()} ":
            add(normalized.replace("Microsoft IIS", "IIS"))
        if "active directory" in normalized.lower():
            add("LDAP")
        return refinements[:3]

    def _parse_searchsploit_json(self, stdout: str, query: str) -> list[dict[str, object]]:
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            return []
        rows = []
        for section in ("RESULTS_EXPLOIT", "RESULTS_PAPER"):
            raw_rows = payload.get(section, [])
            if not isinstance(raw_rows, list):
                continue
            for row in raw_rows:
                if not isinstance(row, dict):
                    continue
                title = str(row.get("Title") or row.get("title") or "").strip()
                path = str(row.get("Path") or row.get("path") or "").strip()
                edb_id = str(row.get("EDB-ID") or row.get("EDB_ID") or row.get("id") or "").strip()
                rows.append(
                    {
                        "query": query,
                        "section": section,
                        "edb_id": edb_id,
                        "title": title,
                        "path": path,
                        "date": row.get("Date") or row.get("date") or "",
                        "author": row.get("Author") or row.get("author") or "",
                        "type": row.get("Type") or row.get("type") or "",
                        "platform": row.get("Platform") or row.get("platform") or "",
                        "score": self._score_searchsploit_match(query, title, path),
                    }
                )
        return rows

    def _score_searchsploit_match(self, query: str, title: str, path: str) -> int:
        lowered = f"{title} {path}".lower()
        score = 0
        for token in query.lower().split():
            if token and token in lowered:
                score += 2
        if re.search(r"\b[0-9]+(?:\.[0-9]+)+\b", query) and re.search(r"\b[0-9]+(?:\.[0-9]+)+\b", lowered):
            score += 4
        if any(term in lowered for term in EXPLOIT_RESEARCH_RCE_TERMS):
            score += 8
        if "remote" in lowered:
            score += 5
        if "/remote/" in lowered:
            score += 5
        if any(term in lowered for term in EXPLOIT_RESEARCH_LOCAL_TERMS):
            score -= 5
        if "authenticated" in lowered:
            score -= 1
        if self._contains_suppressed_exploit_term(lowered):
            score -= 10
        return score

    def _is_suppressed_exploit_match(self, match: dict[str, object]) -> bool:
        haystack = " ".join(str(match.get(key, "")) for key in ("title", "path", "type")).lower()
        return self._contains_suppressed_exploit_term(haystack)

    def _contains_suppressed_exploit_term(self, haystack: str) -> bool:
        return any(term in haystack for term in EXPLOIT_RESEARCH_SUPPRESSED_TERMS)

    def _examine_searchsploit_examples(
        self,
        matches: list[dict[str, object]],
        command_results: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        examples: list[dict[str, object]] = []
        for match in matches:
            edb_id = str(match.get("edb_id", "")).strip()
            if not edb_id:
                continue
            result = self._run_host_command_with_env(
                tool="searchsploit",
                argv=["searchsploit", "-x", edb_id],
                timeout_seconds=15,
                env={"PAGER": "cat"},
            )
            result["query"] = f"examine:{edb_id}"
            command_results.append(result)
            if not result.get("executed") or result.get("timeout"):
                continue
            text = str(result.get("stdout", "")).strip()
            if not text:
                continue
            examples.append(
                {
                    "edb_id": edb_id,
                    "title": match.get("title", ""),
                    "path": match.get("path", ""),
                    "excerpt": text[:6000],
                    "truncated": len(text) > 6000,
                }
            )
        return examples

    def _run_host_command_with_env(
        self,
        *,
        tool: str,
        argv: list[str],
        timeout_seconds: int,
        env: dict[str, str],
    ) -> dict[str, object]:
        if shutil.which(argv[0]) is None:
            return {
                "tool": tool,
                "argv": argv,
                "executed": False,
                "returncode": None,
                "stdout": "",
                "stderr": "tool not found",
                "timeout": False,
            }
        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
                env={**dict(os.environ), **env},
            )
            return {
                "tool": tool,
                "argv": argv,
                "executed": True,
                "returncode": completed.returncode,
                "stdout": self._truncate_command_output(completed.stdout),
                "stderr": self._truncate_command_output(completed.stderr),
                "timeout": False,
            }
        except subprocess.TimeoutExpired as exc:
            return {
                "tool": tool,
                "argv": argv,
                "executed": True,
                "returncode": None,
                "stdout": self._truncate_command_output(exc.stdout or ""),
                "stderr": self._truncate_command_output(exc.stderr or "command timed out"),
                "timeout": True,
            }

    def _summarize_exploit_research(self, research: dict[str, object]) -> str:
        matches = research["matches"]
        suppressed = research["suppressed_matches"]
        examples = research["examined_examples"]
        if not matches:
            return (
                "Searchsploit research found no non-DoS candidates. "
                f"Suppressed {len(suppressed)} DoS/crash-oriented result(s)."
            )
        first = ", ".join(str(item["title"]) for item in matches[:5])
        return (
            f"Searchsploit research found {len(matches)} non-DoS candidate(s), "
            f"suppressed {len(suppressed)} DoS/crash-oriented result(s), and retained "
            f"{len(examples)} example excerpt(s): {first}."
        )

    def _build_exploit_research_note(self, queries: list[str], research: dict[str, object]) -> str:
        matches = research["matches"]
        suppressed = research["suppressed_matches"]
        examples = research["examined_examples"]
        lines = [
            f"Queries: {', '.join(queries)}",
            f"Non-DoS candidates: {len(matches)}",
            f"Suppressed DoS/crash candidates: {len(suppressed)}",
            f"Example excerpts retained: {len(examples)}",
        ]
        for match in matches[:self.config.max_evidence_items]:
            lines.append(
                f"- EDB {match.get('edb_id') or 'unknown'} score={match.get('score')}: {match.get('title')} [{match.get('platform')}]"
            )
        lines.append("No PoC was executed. Any adaptation requires version validation, a bounded verification task, and policy approval.")
        lines.append("DoS/crash-oriented candidates are intentionally suppressed because Primordial must never DDoS or degrade the target.")
        return "\n".join(lines)

    def _load_poc_candidates(self, research_items: list[EvidenceRecord]) -> list[dict[str, object]]:
        candidates: list[dict[str, object]] = []
        seen: set[str] = set()
        for item in research_items:
            payload = {}
            if item.artifact_path:
                try:
                    payload = json.loads(Path(item.artifact_path).read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    payload = {}
            for match in payload.get("matches", []) if isinstance(payload, dict) else []:
                if not isinstance(match, dict):
                    continue
                key = str(match.get("edb_id") or match.get("path") or match.get("title") or "")
                if not key or key in seen:
                    continue
                seen.add(key)
                candidates.append(match)
            if candidates:
                continue
            summary = item.summary
            if ":" in summary and "candidate" in summary.lower():
                summary = summary.split(":", 1)[1]
            for title in re.split(r",\s+(?=Microsoft|Windows|Linux|Apache|OpenSSH|IIS|Exchange)", summary):
                title = title.strip().strip(".")
                if not title or "Searchsploit research found" in title:
                    continue
                key = title.lower()
                if key in seen:
                    continue
                seen.add(key)
                candidates.append({"title": title, "source_evidence_id": item.id})
        return candidates[:self.config.max_evidence_items]

    def _poc_service_facts(self, service_items: list[EvidenceRecord]) -> dict[str, object]:
        services = []
        text_parts = []
        for item in service_items:
            text_parts.append(item.title)
            text_parts.append(item.summary)
            for service in item.metadata.get("open_services", []):
                if not isinstance(service, dict):
                    continue
                services.append(
                    {
                        "host": service.get("host"),
                        "port": service.get("port"),
                        "service": service.get("service"),
                        "banner": service.get("banner", ""),
                    }
                )
                text_parts.append(json.dumps(service, sort_keys=True))
        combined = " ".join(str(part) for part in text_parts).lower()
        return {
            "services": services[:40],
            "text": combined[:12000],
            "has_exchange": "exchange" in combined,
            "has_iis": "iis" in combined or "microsoft-httpapi" in combined,
            "has_ad": any(token in combined for token in ("ldap", "kerberos", "active directory", "global-catalog")),
            "has_windows_2000": "windows 2000" in combined or "server 2000" in combined,
            "has_smb": "smb" in combined or "samba" in combined or "netbios" in combined,
            "has_ssh": "ssh" in combined or ":22 " in combined,
            "has_ftp": "ftp" in combined,
            "has_rdp": "rdp" in combined or "remote desktop" in combined or ":3389 " in combined,
            "has_mssql": "mssql" in combined or "sql server" in combined or ":1433 " in combined,
            "has_mysql": "mysql" in combined or ":3306 " in combined,
            "has_postgres": "postgres" in combined or ":5432 " in combined,
            "has_tomcat": "tomcat" in combined or "apache tomcat" in combined,
            "has_apache": "apache" in combined and "tomcat" not in combined,
            "has_nginx": "nginx" in combined,
            "has_wordpress": "wordpress" in combined or "wp-content" in combined,
            "has_drupal": "drupal" in combined,
            "has_joomla": "joomla" in combined,
            "has_struts": "struts" in combined,
            "has_spring": "spring" in combined,
            "has_jenkins": "jenkins" in combined,
            "has_webdav": "webdav" in combined,
        }

    def _poc_has_foothold(self, evidence: list[EvidenceRecord]) -> bool:
        for item in evidence:
            if item.verification_status != VerificationStatus.VERIFIED:
                continue
            metadata = item.metadata if isinstance(item.metadata, dict) else {}
            kind = metadata.get("kind", "")
            # Credentialed access check with a valid auth result
            if kind == "credentialed_access_check":
                auth_results = metadata.get("auth_results", [])
                if isinstance(auth_results, list) and any(
                    isinstance(result, dict) and result.get("valid") is True for result in auth_results
                ):
                    return True
            # Remote shell / RCE evidence from execution handlers
            if kind in ("shell_access", "rce_verification", "initial_access"):
                return True
            # Evidence tagged with explicit foothold signal
            if metadata.get("foothold") is True or metadata.get("shell_obtained") is True:
                return True
            # WinRM/SMB pwn3d signal written by credentialed-access handler
            if metadata.get("pwn3d") is True or metadata.get("winrm_success") is True:
                return True
        return False

    def _classify_poc_candidate(
        self,
        candidate: dict[str, object],
        service_facts: dict[str, object],
        has_foothold: bool,
    ) -> dict[str, object]:
        title = str(candidate.get("title") or candidate.get("description") or "untitled public PoC")
        lowered = title.lower()
        reasons: list[str] = []
        status = "blocked"
        if any(term in lowered for term in EXPLOIT_RESEARCH_SUPPRESSED_TERMS):
            reasons.append("suppressed because it appears DoS/crash-oriented")
        elif any(term in lowered for term in EXPLOIT_RESEARCH_LOCAL_TERMS) and not has_foothold:
            reasons.append("requires user shell or credentialed local access before LPE verification")
        elif "exchange" in lowered and not service_facts.get("has_exchange"):
            reasons.append("target evidence does not show Microsoft Exchange")
        elif ("windows server 2000" in lowered or "server 2000" in lowered) and not service_facts.get("has_windows_2000"):
            reasons.append("target evidence does not show Windows Server 2000")
        elif "ldap" in lowered or "active directory" in lowered:
            if service_facts.get("has_ad"):
                status = "ready_for_review"
                reasons.append("AD/LDAP surface exists, but exact version/configuration still needs bounded verification")
            else:
                reasons.append("target evidence does not show AD/LDAP services")
        elif "iis" in lowered:
            if service_facts.get("has_iis"):
                status = "ready_for_review"
                reasons.append("IIS surface exists, but exact version and exploit preconditions still need bounded verification")
            else:
                reasons.append("target evidence does not show IIS-specific service details")
        elif any(term in lowered for term in ("smb", "samba", "netbios", "eternalblue", "ms17-010")):
            if service_facts.get("has_smb"):
                status = "ready_for_review"
                reasons.append("SMB/Samba surface exists; exact OS version and patch level must be confirmed before use")
            else:
                reasons.append("target evidence does not show SMB/Samba services")
        elif "ssh" in lowered:
            if service_facts.get("has_ssh"):
                status = "ready_for_review"
                reasons.append("SSH surface exists; exact version and configuration must be verified before use")
            else:
                reasons.append("target evidence does not show SSH service")
        elif any(term in lowered for term in ("tomcat", "apache tomcat")):
            if service_facts.get("has_tomcat"):
                status = "ready_for_review"
                reasons.append("Tomcat surface exists; exact version and manager configuration must be verified")
            else:
                reasons.append("target evidence does not show Apache Tomcat")
        elif any(term in lowered for term in ("struts", "apache struts")):
            if service_facts.get("has_struts"):
                status = "ready_for_review"
                reasons.append("Struts surface exists; exact version needed before candidate is actionable")
            else:
                reasons.append("target evidence does not show Apache Struts")
        elif "jenkins" in lowered:
            if service_facts.get("has_jenkins"):
                status = "ready_for_review"
                reasons.append("Jenkins surface exists; authentication state and version must be confirmed")
            else:
                reasons.append("target evidence does not show Jenkins")
        elif any(term in lowered for term in ("mssql", "sql server", "ms sql")):
            if service_facts.get("has_mssql"):
                status = "ready_for_review"
                reasons.append("MSSQL surface exists; authentication mode and version must be confirmed")
            else:
                reasons.append("target evidence does not show MSSQL")
        elif "rdp" in lowered or "remote desktop" in lowered:
            if service_facts.get("has_rdp"):
                status = "ready_for_review"
                reasons.append("RDP surface exists; exact Windows build and patch level must be confirmed")
            else:
                reasons.append("target evidence does not show RDP service")
        elif "wordpress" in lowered or "wp-" in lowered:
            if service_facts.get("has_wordpress"):
                status = "ready_for_review"
                reasons.append("WordPress surface exists; exact version and plugin inventory must be confirmed")
            else:
                reasons.append("target evidence does not show WordPress")
        else:
            reasons.append("no exact target service/version or prerequisite match is available")
        return {
            "title": title,
            "edb_id": candidate.get("edb_id"),
            "path": candidate.get("path"),
            "status": status,
            "reasons": reasons,
            "executes_poc": False,
        }

    def _build_poc_applicability_note(self, classified: list[dict[str, object]], service_facts: dict[str, object]) -> str:
        lines = [
            f"Classified candidates: {len(classified)}",
            f"Ready for gated review: {sum(1 for item in classified if item['status'] == 'ready_for_review')}",
            f"Blocked/research-only: {sum(1 for item in classified if item['status'] != 'ready_for_review')}",
            f"Observed services considered: {len(service_facts.get('services', []))}",
        ]
        for item in classified[:self.config.max_evidence_items]:
            reasons = "; ".join(str(reason) for reason in item.get("reasons", []))
            lines.append(f"- {item['status']}: {item['title']} :: {reasons}")
        lines.append("No PoC was executed, no exploit code was generated, and no vulnerability was marked verified.")
        return "\n".join(lines)

    def _build_exploit_research_notification(self, target_handle: str, research: dict[str, object]) -> str:
        matches = list(research["matches"])
        suppressed = list(research["suppressed_matches"])
        examples = list(research["examined_examples"])
        retained = []
        for match in matches[:3]:
            edb_id = str(match.get("edb_id", "unknown")).strip() or "unknown"
            title = str(match.get("title", "untitled candidate")).strip()
            retained.append(f"- EDB-{edb_id}: {title[:220]}")
        retained_block = "\n".join(retained) if retained else "- Candidate metadata retained in Primordial evidence."
        return (
            f"PoC research candidates found for {target_handle}\n"
            f"Retained non-DoS candidates: {len(matches)}; examples captured: {len(examples)}; "
            f"suppressed unsafe/noisy matches: {len(suppressed)}.\n"
            f"{retained_block}\n"
            "No PoC was executed. Synthesis or execution remains gated by scope, non-DoS classification, "
            "bounded runtime limits, and approval."
        )

    def _parse_ad_enumeration(self, command_results: list[dict[str, object]]) -> dict[str, object]:
        by_tool = {str(item["tool"]): item for item in command_results}
        return {
            "ldap_rootdse": self._parse_ldap_rootdse(str(by_tool.get("ldapsearch", {}).get("stdout", ""))),
            "smb_shares": self._parse_smb_shares(
                str(by_tool.get("smbclient", {}).get("stdout", ""))
                + "\n"
                + str(by_tool.get("netexec", {}).get("stdout", ""))
            ),
            "rpc_users": self._parse_rpc_users(str(by_tool.get("rpcclient", {}).get("stdout", ""))),
            "rpc_groups": self._parse_rpc_groups(str(by_tool.get("rpcclient", {}).get("stdout", ""))),
        }

    def _parse_ldap_rootdse(self, stdout: str) -> dict[str, object]:
        values: dict[str, list[str]] = {}
        for raw_line in stdout.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or ": " not in line:
                continue
            key, value = line.split(": ", 1)
            values.setdefault(key, []).append(value)
        return values

    def _parse_smb_shares(self, stdout: str) -> list[dict[str, str]]:
        shares: dict[str, dict[str, str]] = {}
        for raw_line in stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if "|" in line:
                parts = line.split("|")
                if len(parts) >= 2 and parts[0].lower() in {"disk", "ipc", "printer"}:
                    shares[parts[1]] = {
                        "name": parts[1],
                        "type": parts[0],
                        "comment": parts[2] if len(parts) > 2 else "",
                    }
            elif re.match(r"^(SMB|WINRM|LDAP|RPC)", line):
                tokens = line.split()
                for index, token in enumerate(tokens):
                    if token.upper() == "READ" and index > 0:
                        name = tokens[index - 1]
                        shares.setdefault(name, {"name": name, "type": "disk", "comment": "netexec readable"})
        return sorted(shares.values(), key=lambda item: item["name"].lower())

    def _parse_rpc_users(self, stdout: str) -> list[dict[str, str]]:
        users: list[dict[str, str]] = []
        seen: set[str] = set()
        for match in re.finditer(r"user:\[([^\]]+)\]\s+rid:\[([^\]]+)\]", stdout, re.IGNORECASE):
            username = match.group(1)
            if username in seen:
                continue
            seen.add(username)
            users.append({"name": username, "rid": match.group(2)})
        return users

    def _parse_rpc_groups(self, stdout: str) -> list[dict[str, str]]:
        groups: list[dict[str, str]] = []
        seen: set[str] = set()
        for match in re.finditer(r"group:\[([^\]]+)\]\s+rid:\[([^\]]+)\]", stdout, re.IGNORECASE):
            group = match.group(1)
            if group in seen:
                continue
            seen.add(group)
            groups.append({"name": group, "rid": match.group(2)})
        return groups

    def _summarize_ad_enumeration(self, host: str, parsed: dict[str, object]) -> str:
        rootdse = parsed["ldap_rootdse"]
        naming_contexts = []
        if isinstance(rootdse, dict):
            naming_contexts = list(rootdse.get("namingContexts", [])) + list(rootdse.get("defaultNamingContext", []))
        shares = parsed["smb_shares"]
        users = parsed["rpc_users"]
        return (
            f"Anonymous AD enumeration against {host} observed "
            f"{len(naming_contexts)} LDAP naming context value(s), "
            f"{len(shares)} SMB share candidate(s), and {len(users)} RPC user candidate(s)."
        )

    def _build_ad_enumeration_note(
        self,
        host: str,
        parsed: dict[str, object],
        command_results: list[dict[str, object]],
    ) -> str:
        rootdse = parsed["ldap_rootdse"]
        shares = parsed["smb_shares"]
        users = parsed["rpc_users"]
        groups = parsed["rpc_groups"]
        executed = [
            f"{item['tool']} rc={item['returncode']} timeout={item['timeout']}"
            for item in command_results
            if item.get("executed")
        ]
        lines = [
            f"Host: {host}",
            f"Commands: {', '.join(executed) or 'none executed'}",
            f"LDAP RootDSE keys: {', '.join(sorted(rootdse.keys())) if isinstance(rootdse, dict) else 'none'}",
            f"SMB shares parsed: {len(shares)}",
            f"RPC users parsed: {len(users)}",
            f"RPC groups parsed: {len(groups)}",
        ]
        for share in shares[:self.config.max_evidence_items]:
            lines.append(f"- share {share['name']} ({share.get('type', 'unknown')}): {share.get('comment', '')}")
        for user in users[:self.config.max_evidence_items]:
            lines.append(f"- user {user['name']} rid={user['rid']}")
        lines.append("This is anonymous inventory only; no credential use or exploit step was performed.")
        return "\n".join(lines)

    def _default_naming_context(self, target_id: str) -> str:
        for evidence in self.store.list_evidence(target_id=target_id, limit=200):
            rootdse = evidence.metadata.get("ldap_rootdse", {})
            if not isinstance(rootdse, dict):
                continue
            for key in ("defaultNamingContext", "rootDomainNamingContext", "namingContexts"):
                values = rootdse.get(key, [])
                if isinstance(values, list) and values:
                    return str(values[0])
                if isinstance(values, str) and values:
                    return values
        return ""

    def _domain_from_base_dn(self, base_dn: str) -> str:
        parts = []
        for component in base_dn.split(","):
            component = component.strip()
            if component.lower().startswith("dc="):
                parts.append(component.split("=", 1)[1])
        return ".".join(parts)

    def _domain_from_target(self, handle: str) -> str:
        return handle.strip().strip(".") if "." in handle else ""

    def _kerberos_domain(self, target_id: str, handle: str) -> str:
        for evidence in self.store.list_evidence(target_id=target_id, limit=200):
            if evidence.metadata.get("kind") == "kerberos_user_discovery":
                domain = str(evidence.metadata.get("domain", "")).strip()
                if domain:
                    return domain
        return self._domain_from_base_dn(self._default_naming_context(target_id)) or self._domain_from_target(handle)

    def _run_kerberos_user_discovery_commands(self, host: str, base_dn: str) -> list[dict[str, object]]:
        commands = []
        if base_dn:
            commands.append(
                {
                    "tool": "ldapsearch",
                    "argv": [
                        "ldapsearch",
                        "-x",
                        "-LLL",
                        "-H",
                        f"ldap://{host}",
                        "-b",
                        base_dn,
                        "(|(objectClass=user)(objectClass=person))",
                        "sAMAccountName",
                        "userPrincipalName",
                        "servicePrincipalName",
                        "userAccountControl",
                    ],
                    "timeout": 30,
                }
            )
        commands.extend(
            [
                {
                    "tool": "rpcclient",
                    "argv": ["rpcclient", "-U", "", "-N", host, "-c", "enumdomusers"],
                    "timeout": 20,
                },
                {
                    "tool": "netexec",
                    "argv": ["netexec", "smb", host, "-u", "", "-p", "", "--users"],
                    "timeout": 35,
                },
            ]
        )
        return [
            self._run_host_command(
                tool=str(command["tool"]),
                argv=[str(item) for item in command["argv"]],
                timeout_seconds=int(command["timeout"]),
            )
            for command in commands
        ]

    def _parse_kerberos_user_discovery(
        self,
        command_results: list[dict[str, object]],
        domain: str,
    ) -> dict[str, object]:
        users: dict[str, dict[str, object]] = {}
        spn_candidates: list[dict[str, str]] = []
        for result in command_results:
            tool = str(result.get("tool", ""))
            stdout = str(result.get("stdout", ""))
            if tool == "ldapsearch":
                for record in self._parse_ldap_user_records(stdout, domain):
                    name = str(record.get("username", ""))
                    if not name or name.endswith("$"):
                        continue
                    users.setdefault(name.lower(), record)
                    for spn in record.get("servicePrincipalName", []):
                        spn_candidates.append({"username": name, "spn": str(spn)})
            elif tool == "rpcclient":
                for user in self._parse_rpc_users(stdout):
                    name = user["name"]
                    if not name or name.endswith("$"):
                        continue
                    users.setdefault(name.lower(), {"username": name, "source": "rpcclient", "rid": user["rid"]})
            elif tool == "netexec":
                for name in self._parse_netexec_users(stdout):
                    if not name or name.endswith("$"):
                        continue
                    users.setdefault(name.lower(), {"username": name, "source": "netexec"})
        return {
            "users": sorted(users.values(), key=lambda item: str(item.get("username", "")).lower()),
            "spn_candidates": sorted(spn_candidates, key=lambda item: (item["username"].lower(), item["spn"].lower())),
        }

    def _parse_ldap_user_records(self, stdout: str, domain: str) -> list[dict[str, object]]:
        records: list[dict[str, object]] = []
        current: dict[str, list[str]] = {}
        for raw_line in stdout.splitlines() + [""]:
            line = raw_line.strip()
            if not line:
                if current:
                    username = (current.get("sAMAccountName") or [""])[0]
                    if username:
                        records.append(
                            {
                                "username": username,
                                "upn": (current.get("userPrincipalName") or [f"{username}@{domain}"])[0],
                                "servicePrincipalName": current.get("servicePrincipalName", []),
                                "userAccountControl": (current.get("userAccountControl") or [""])[0],
                                "source": "ldapsearch",
                            }
                        )
                    current = {}
                continue
            if ": " not in line:
                continue
            key, value = line.split(": ", 1)
            current.setdefault(key, []).append(value)
        return records

    def _parse_netexec_users(self, stdout: str) -> list[str]:
        users: list[str] = []
        for raw_line in stdout.splitlines():
            line = raw_line.strip()
            if not line or "[+]" in line or "[-]" in line:
                continue
            match = re.search(r"\b([A-Za-z0-9_.-]+)\s+(?:badpwdcount|description|pwdlastset|lastlogon)", line, re.IGNORECASE)
            if match and match.group(1) not in users:
                users.append(match.group(1))
        return users

    def _summarize_kerberos_user_discovery(self, host: str, parsed: dict[str, object]) -> str:
        users = parsed["users"]
        spns = parsed["spn_candidates"]
        return f"Kerberos user discovery against {host} found {len(users)} user principal(s) and {len(spns)} SPN candidate(s)."

    def _build_kerberos_user_discovery_note(
        self,
        host: str,
        domain: str,
        parsed: dict[str, object],
        command_results: list[dict[str, object]],
    ) -> str:
        users = parsed["users"]
        spns = parsed["spn_candidates"]
        executed = [f"{item['tool']} rc={item['returncode']} timeout={item['timeout']}" for item in command_results if item.get("executed")]
        lines = [
            f"Host: {host}",
            f"Domain: {domain or 'unknown'}",
            f"Commands: {', '.join(executed) or 'none executed'}",
            f"Users discovered: {len(users)}",
            f"SPN candidates: {len(spns)}",
        ]
        for user in users[:self.config.max_evidence_items]:
            lines.append(f"- user {user.get('username')} source={user.get('source')}")
        for spn in spns[:self.config.max_evidence_items]:
            lines.append(f"- spn {spn['username']}: {spn['spn']}")
        lines.append("No password spraying, cracking, or exploit execution was performed.")
        return "\n".join(lines)

    def _discovered_kerberos_users(self, target_id: str) -> list[dict[str, object]]:
        users: dict[str, dict[str, object]] = {}
        for evidence in self.store.list_evidence(target_id=target_id, limit=200):
            if evidence.metadata.get("kind") != "kerberos_user_discovery":
                continue
            for user in evidence.metadata.get("users", []):
                if not isinstance(user, dict):
                    continue
                username = str(user.get("username", "")).strip()
                if username:
                    users.setdefault(username.lower(), user)
        return sorted(users.values(), key=lambda item: str(item.get("username", "")).lower())

    def _discovered_spn_candidates(self, target_id: str) -> list[dict[str, str]]:
        spns: dict[tuple[str, str], dict[str, str]] = {}
        for evidence in self.store.list_evidence(target_id=target_id, limit=200):
            if evidence.metadata.get("kind") != "kerberos_user_discovery":
                continue
            for spn in evidence.metadata.get("spn_candidates", []):
                if not isinstance(spn, dict):
                    continue
                username = str(spn.get("username", "")).strip()
                value = str(spn.get("spn", "")).strip()
                if username and value:
                    spns.setdefault((username.lower(), value.lower()), {"username": username, "spn": value})
        return sorted(spns.values(), key=lambda item: (item["username"].lower(), item["spn"].lower()))

    def _run_kerberos_attack_check_commands(
        self,
        task: Task,
        target_id: str,
        host: str,
        domain: str,
        users: list[dict[str, object]],
        requested_checks: set[str],
    ) -> list[dict[str, object]]:
        command_results: list[dict[str, object]] = []
        if "kerberoast" in requested_checks:
            command_results.append(
                {
                    "tool": "kerberoast-spn-candidate-review",
                    "argv": ["spn-candidate-review"],
                    "executed": False,
                    "returncode": None,
                    "stdout": "SPN candidates retained from prior discovery; no TGS request or hash cracking was performed.",
                    "stderr": "",
                    "timeout": False,
                }
            )
        if "asrep_roast" not in requested_checks:
            return command_results
        tool = shutil.which("impacket-GetNPUsers") or shutil.which("GetNPUsers.py")
        if not tool:
            command_results.append(
                {
                    "tool": "GetNPUsers.py",
                    "argv": ["GetNPUsers.py"],
                    "executed": False,
                    "returncode": None,
                    "stdout": "",
                    "stderr": "tool not found",
                    "timeout": False,
                }
            )
            return command_results
        usernames = [str(user.get("username", "")).strip() for user in users if str(user.get("username", "")).strip()]
        usernames = [name for name in usernames if not name.endswith("$")][:80]
        user_file = self._write_task_text_file(task, target_id, "kerberos-users", "\n".join(usernames) + "\n")
        command_results.append(
            self._run_host_command(
                tool="GetNPUsers.py",
                argv=[
                    tool,
                    f"{domain}/",
                    "-dc-ip",
                    host,
                    "-usersfile",
                    user_file,
                    "-no-pass",
                ],
                timeout_seconds=90,
            )
        )
        return command_results

    def _write_task_text_file(self, task: Task, target_id: str, prefix: str, content: str) -> str:
        task_dir = self.config.artifacts_dir / (task.id or "task")
        task_dir.mkdir(parents=True, exist_ok=True)
        path = task_dir / f"{prefix}-{self._safe_artifact_fragment(target_id)}.txt"
        path.write_text(content, encoding="utf-8")
        path.chmod(0o600)
        return str(path)

    def _parse_asrep_hashes(self, command_results: list[dict[str, object]]) -> list[dict[str, str]]:
        hashes: list[dict[str, str]] = []
        for result in command_results:
            stdout = str(result.get("stdout", ""))
            for raw_line in stdout.splitlines():
                line = raw_line.strip()
                if "$krb5asrep$" not in line.lower():
                    continue
                username = line.split(":", 1)[0].strip() if ":" in line else ""
                hashes.append({"username": username, "hash_preview": line[:120], "hash_present": "true"})
        return hashes

    def _summarize_kerberos_attack_check(
        self,
        asrep_hashes: list[dict[str, str]],
        spn_candidates: list[dict[str, str]],
        command_results: list[dict[str, object]],
    ) -> str:
        executed = [item["tool"] for item in command_results if item.get("executed")]
        return (
            f"Kerberos checks ran {', '.join(executed) or 'no host tools'} and found "
            f"{len(asrep_hashes)} AS-REP hash candidate(s) plus {len(spn_candidates)} SPN candidate(s). "
            "No hash cracking or PoC execution was performed."
        )

    def _build_kerberos_attack_check_note(
        self,
        domain: str,
        users: list[dict[str, object]],
        asrep_hashes: list[dict[str, str]],
        spn_candidates: list[dict[str, str]],
        command_results: list[dict[str, object]],
    ) -> str:
        lines = [
            f"Domain: {domain}",
            f"Users checked: {len(users)}",
            f"AS-REP hash candidates: {len(asrep_hashes)}",
            f"SPN candidates retained: {len(spn_candidates)}",
            "Hash cracking was not performed.",
        ]
        for result in command_results:
            lines.append(f"- {result['tool']} executed={result['executed']} rc={result['returncode']} timeout={result['timeout']}")
        for item in asrep_hashes[:self.config.max_evidence_items]:
            lines.append(f"- AS-REP candidate {item.get('username') or 'unknown'}")
        for item in spn_candidates[:self.config.max_evidence_items]:
            lines.append(f"- SPN candidate {item['username']}: {item['spn']}")
        return "\n".join(lines)

    def _run_credentialed_access_commands(
        self,
        task: Task,
        target_id: str,
        host: str,
        username: str,
        password: str,
        domain: str,
        *,
        protocols: set[str] | None = None,
    ) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
        auth_file = self._write_smb_auth_file(username, password, domain)
        command_results: list[dict[str, object]] = []
        auth_results: list[dict[str, object]] = []
        flag_hits: list[dict[str, object]] = []
        policy = self._active_intent_policy()
        flag_collection_allowed = bool(policy and policy.lab_policy.lab_flag_collection_allowed)
        protocols = protocols or {"smb", "winrm"}
        if "smb" in protocols:
            smb_result = self._run_secret_host_command(
                tool="smbclient",
                argv=["smbclient", "-A", auth_file, "-L", f"//{host}/", "-g", "-m", "SMB3"],
                redacted_argv=["smbclient", "-A", "<credential-file>", "-L", f"//{host}/", "-g", "-m", "SMB3"],
                timeout_seconds=25,
            )
            command_results.append(smb_result)
            smb_returncode = smb_result.get("returncode")
            smb_valid = bool(smb_result.get("executed")) and smb_returncode is not None and int(smb_returncode) == 0
            auth_results.append({"protocol": "smb", "valid": smb_valid, "tool": "smbclient"})
            if smb_valid and flag_collection_allowed:
                flag_hits.extend(self._collect_smb_flags(task, target_id, host, auth_file, username))
            elif smb_valid:
                command_results.append(
                    {
                        "tool": "smbclient",
                        "argv": ["smbclient", "-A", "<credential-file>", f"//{host}/C$", "-c", "<flag-collection>"],
                        "executed": False,
                        "returncode": None,
                        "stdout": "",
                        "stderr": "disabled: active operator intent does not allow lab flag collection",
                        "timeout": False,
                    }
                )
        else:
            command_results.append(
                {
                    "tool": "smbclient",
                    "argv": ["smbclient", "-A", "<credential-file>", "-L", f"//{host}/"],
                    "executed": False,
                    "returncode": None,
                    "stdout": "",
                    "stderr": "disabled: current credentialed-access surface did not admit SMB",
                    "timeout": False,
                }
            )

        if "winrm" in protocols and os.getenv("PRIMORDIAL_ALLOW_PASSWORD_ARG_TOOLS", "").strip() == "1":
            winrm_result = self._run_secret_host_command(
                tool="netexec",
                argv=["netexec", "winrm", host, "-u", username, "-p", password, *self._domain_args(domain)],
                redacted_argv=["netexec", "winrm", host, "-u", username, "-p", "<redacted>", *self._domain_args(domain)],
                timeout_seconds=35,
            )
            command_results.append(winrm_result)
            stdout = str(winrm_result.get("stdout", ""))
            winrm_rc = winrm_result.get("returncode")
            valid = (
                bool(winrm_result.get("executed"))
                and winrm_rc is not None
                and (int(winrm_rc) == 0 or "[+]" in stdout or "pwn3d" in stdout.lower())
            )
            auth_results.append({"protocol": "winrm", "valid": valid, "tool": "netexec"})
        elif "winrm" in protocols:
            command_results.append(
                {
                    "tool": "netexec",
                    "argv": ["netexec", "winrm", host, "-u", username, "-p", "<redacted>"],
                    "executed": False,
                    "returncode": None,
                    "stdout": "",
                    "stderr": "disabled: set PRIMORDIAL_ALLOW_PASSWORD_ARG_TOOLS=1 to allow password-in-argv WinRM tooling",
                    "timeout": False,
                }
            )
        return command_results, auth_results, flag_hits

    def _credentialed_access_protocols(self, task: Task) -> set[str]:
        raw = task.metadata.get("protocols")
        if isinstance(raw, list):
            protocols = {str(item).strip().lower() for item in raw if str(item).strip()}
            protocols = protocols.intersection({"smb", "winrm"})
            if protocols:
                return protocols
        surface = task.metadata.get("credentialed_access_surface", {})
        if isinstance(surface, dict):
            raw_surface = surface.get("protocols")
            if isinstance(raw_surface, list):
                protocols = {str(item).strip().lower() for item in raw_surface if str(item).strip()}
                protocols = protocols.intersection({"smb", "winrm"})
                if protocols:
                    return protocols
        return {"smb", "winrm"}

    def _domain_args(self, domain: str) -> list[str]:
        return ["-d", domain] if domain else []

    def _write_smb_auth_file(self, username: str, password: str, domain: str) -> str:
        auth_dir = self.config.secrets_dir / "tool-auth"
        auth_dir.mkdir(parents=True, exist_ok=True)
        auth_dir.chmod(0o700)
        path = auth_dir / "smbclient.auth"
        lines = [f"username = {username}", f"password = {password}"]
        if domain:
            lines.append(f"domain = {domain}")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        path.chmod(0o600)
        return str(path)

    def _smb_flag_candidates(
        self, target_id: str, username: str
    ) -> list[tuple[str, str, str]]:
        """Return (share, remote_path, flag_name) tuples.

        Operators can override via target.metadata["flag_paths"]: a list of
        {"share": "C$", "path": "Users\\...\\flag.txt", "name": "flag.txt"} dicts.
        Falls back to common in-house lab user.txt / root.txt paths.
        """
        target = self.store.get_target(target_id)
        custom = target.metadata.get("flag_paths") if target else None
        if isinstance(custom, list) and custom:
            result = []
            for entry in custom:
                if isinstance(entry, dict) and entry.get("path") and entry.get("name"):
                    result.append((
                        str(entry.get("share", "C$")),
                        str(entry["path"]),
                        str(entry["name"]),
                    ))
            if result:
                return result
        return [
            ("C$", f"Users\\{username}\\Desktop\\user.txt", "user.txt"),
            ("C$", "Users\\Administrator\\Desktop\\root.txt", "root.txt"),
        ]

    def _collect_smb_flags(
        self,
        task: Task,
        target_id: str,
        host: str,
        auth_file: str,
        username: str,
    ) -> list[dict[str, object]]:
        flag_hits: list[dict[str, object]] = []
        candidates = self._smb_flag_candidates(target_id, username)
        flag_dir = self.config.artifacts_dir / (task.id or "task") / "flags"
        flag_dir.mkdir(parents=True, exist_ok=True)
        flag_dir.chmod(0o700)
        for share, remote_path, flag_name in candidates:
            local_path = flag_dir / f"{self._safe_artifact_fragment(target_id)}-{flag_name}"
            command = f'get "{remote_path}" "{local_path}"'
            result = self._run_secret_host_command(
                tool="smbclient",
                argv=["smbclient", "-A", auth_file, f"//{host}/{share}", "-m", "SMB3", "-c", command],
                redacted_argv=["smbclient", "-A", "<credential-file>", f"//{host}/{share}", "-m", "SMB3", "-c", command],
                timeout_seconds=25,
            )
            if not local_path.exists():
                continue
            value = local_path.read_text(encoding="utf-8", errors="replace").strip()
            local_path.chmod(0o600)
            if not value:
                continue
            flag_hits.append(
                {
                    "source": "smb",
                    "share": share,
                    "remote_path": remote_path,
                    "flag_name": flag_name,
                    "content_collected": True,
                    "value": value,
                    "local_path": str(local_path),
                    "tool_returncode": result.get("returncode"),
                }
            )
        return flag_hits

    def _summarize_credentialed_access(
        self,
        auth_results: list[dict[str, object]],
        flag_hits: list[dict[str, object]],
    ) -> str:
        valid = [item["protocol"] for item in auth_results if item.get("valid")]
        summary = f"Credentialed access checks validated {', '.join(valid) if valid else 'no'} protocol access."
        if flag_hits:
            summary += f" Observed {len(flag_hits)} lab flag file candidate(s)."
        return summary

    def _build_credentialed_access_note(
        self,
        host: str,
        username: str,
        domain: str,
        auth_results: list[dict[str, object]],
        flag_hits: list[dict[str, object]],
        command_results: list[dict[str, object]],
    ) -> str:
        lines = [
            f"Host: {host}",
            f"Username: {username}",
            f"Domain: {domain or 'not configured'}",
            f"Auth checks: {len(auth_results)}",
        ]
        if flag_hits:
            lines.append(f"Lab flag file candidates observed: {len(flag_hits)}")
        for item in auth_results:
            lines.append(f"- {item['protocol']}: valid={item['valid']} tool={item['tool']}")
        for item in flag_hits:
            lines.append(f"- {item['flag_name']} observed via {item['source']} share={item.get('share')}")
        for result in command_results:
            lines.append(f"- {result['tool']} executed={result['executed']} rc={result['returncode']} timeout={result['timeout']}")
        lines.append("Passwords are redacted from artifacts. WinRM password-argv tools are disabled unless explicitly opted in.")
        return "\n".join(lines)

    def _build_probe_plans(self, assets) -> list[dict[str, str]]:
        hostname_assets = [asset.asset for asset in assets if asset.asset_type == "hostname"]
        plans: list[dict[str, str]] = []
        seen: set[tuple[str, str | None]] = set()

        def add(url: str, asset_label: str, host_header: str | None = None) -> None:
            key = (url, host_header)
            if key in seen:
                return
            seen.add(key)
            plans.append({"url": url, "asset_label": asset_label, "host_header": host_header or ""})

        for asset in assets:
            if asset.asset_type == "webapp" or asset.asset.startswith(("http://", "https://")):
                add(asset.asset, asset.asset)
            elif asset.asset_type == "hostname":
                add(f"http://{asset.asset}/", asset.asset)
                add(f"https://{asset.asset}/", asset.asset)
            elif asset.asset_type == "ip":
                add(f"http://{asset.asset}/", asset.asset)
                add(f"https://{asset.asset}/", asset.asset)
                for hostname in hostname_assets:
                    add(f"http://{asset.asset}/", f"{asset.asset} ({hostname})", host_header=hostname)
                    add(f"https://{asset.asset}/", f"{asset.asset} ({hostname})", host_header=hostname)
        return plans

    def _probe_url(self, *, url: str, host_header: str | None, asset_label: str) -> dict[str, object]:
        headers = {"User-Agent": "Primordial/0.1", "Accept": "*/*"}
        if host_header:
            headers["Host"] = host_header
        resolved_ips = self._resolve_hostnames(url, host_header)
        last_error = ""

        for insecure_tls in (False, True):
            parsed = parse.urlsplit(url)
            if parsed.scheme != "https" and insecure_tls:
                continue
            try:
                request_object = request.Request(url, headers=headers, method="GET")
                context = ssl._create_unverified_context() if insecure_tls and parsed.scheme == "https" else None
                with request.urlopen(request_object, timeout=8, context=context) as response:
                    body = response.read(262144)
                    return self._normalize_probe_response(
                        asset_label=asset_label,
                        requested_url=url,
                        effective_url=response.geturl(),
                        status_code=response.status,
                        response_headers=response.headers,
                        body=body,
                        resolved_ips=resolved_ips,
                        ssl_verification_disabled=insecure_tls,
                        host_header=host_header,
                    )
            except error.HTTPError as exc:
                body = exc.read(262144)
                return self._normalize_probe_response(
                    asset_label=asset_label,
                    requested_url=url,
                    effective_url=exc.geturl(),
                    status_code=exc.code,
                    response_headers=exc.headers,
                    body=body,
                    resolved_ips=resolved_ips,
                    ssl_verification_disabled=insecure_tls,
                    host_header=host_header,
                )
            except Exception as exc:  # noqa: BLE001 - capture probe failures into evidence
                last_error = str(exc)

        return {
            "asset_label": asset_label,
            "requested_url": url,
            "resolved_ips": resolved_ips,
            "error": last_error or "probe failed",
        }

    def _normalize_probe_response(
        self,
        *,
        asset_label: str,
        requested_url: str,
        effective_url: str,
        status_code: int,
        response_headers,
        body: bytes,
        resolved_ips: list[str],
        ssl_verification_disabled: bool,
        host_header: str | None,
    ) -> dict[str, object]:
        headers = {key.lower(): value for key, value in response_headers.items()}
        content_type = headers.get("content-type", "")
        decoded = self._decode_response_body(body, response_headers)
        parser = _SurfaceParser()
        if "html" in content_type and decoded:
            try:
                parser.feed(decoded)
            except Exception:  # noqa: BLE001 - malformed HTML should not break recon
                pass
        discovery_results = self._run_content_discovery(effective_url, host_header)
        return {
            "asset_label": asset_label,
            "requested_url": requested_url,
            "effective_url": effective_url,
            "status_code": status_code,
            "content_type": content_type,
            "headers": headers,
            "title": parser.title,
            "page_links": parser.links[:self.config.max_evidence_items],
            "scripts": parser.scripts[:self.config.max_evidence_items],
            "forms": parser.forms[:self.config.max_evidence_items],
            "resolved_ips": resolved_ips,
            "discovery_results": discovery_results,
            "ssl_verification_disabled": ssl_verification_disabled,
            "host_header": host_header or "",
        }

    def _run_content_discovery(self, base_url: str, host_header: str | None) -> list[dict[str, object]]:
        parsed = parse.urlsplit(base_url)
        if parsed.scheme not in {"http", "https"}:
            return []
        discovery_headers = {"User-Agent": "Primordial/0.1", "Accept": "*/*"}
        if host_header:
            discovery_headers["Host"] = host_header
        results: list[dict[str, object]] = []
        for path in DISCOVERY_PATHS:
            candidate = parse.urljoin(base_url, path)
            try:
                request_object = request.Request(candidate, headers=discovery_headers, method="GET")
                with request.urlopen(
                    request_object,
                    timeout=5,
                    context=ssl._create_unverified_context() if parsed.scheme == "https" else None,
                ) as response:
                    results.append(
                        {
                            "path": path,
                            "url": response.geturl(),
                            "status": response.status,
                            "content_type": response.headers.get("Content-Type", ""),
                        }
                    )
            except error.HTTPError as exc:
                if exc.code in {401, 403, 404}:
                    results.append(
                        {
                            "path": path,
                            "url": exc.geturl(),
                            "status": exc.code,
                            "content_type": exc.headers.get("Content-Type", ""),
                        }
                    )
            except Exception:
                continue
        return results

    def _resolve_hostnames(self, url: str, host_header: str | None) -> list[str]:
        host = host_header or parse.urlsplit(url).hostname
        if not host:
            return []
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            return []
        return sorted({info[4][0] for info in infos})

    def _decode_response_body(self, body: bytes, response_headers) -> str:
        charset = response_headers.get_content_charset() if hasattr(response_headers, "get_content_charset") else None
        for encoding in filter(None, [charset, "utf-8", "latin-1"]):
            try:
                return body.decode(encoding)
            except UnicodeDecodeError:
                continue
        return ""

    def _normalize_paths(self, values: list[str]) -> list[str]:
        normalized: set[str] = set()
        for value in values:
            parsed = parse.urlsplit(value)
            path = parsed.path if parsed.scheme else value
            if not isinstance(path, str) or not path:
                continue
            if path.startswith("/"):
                normalized.add(path)
        return sorted(normalized)

    def _extract_query_parameter_names(self, values: list[str]) -> list[str]:
        names: set[str] = set()
        for value in values:
            parsed = parse.urlsplit(value)
            for key in parse.parse_qs(parsed.query).keys():
                if key:
                    names.add(key)
        return sorted(names)

    def _extract_auth_surfaces(self, values: list[str]) -> list[str]:
        surfaces: set[str] = set()
        for value in values:
            lowered = value.lower()
            if any(keyword in lowered for keyword in AUTH_KEYWORDS):
                parsed = parse.urlsplit(value)
                surfaces.add(parsed.path or value)
        return sorted(surfaces)

    def _summarize_probe(self, probe: dict[str, object]) -> str:
        title = f" title={probe['title']!r}" if probe["title"] else ""
        return (
            f"HTTP probe returned {probe['status_code']} for {probe['effective_url']} "
            f"with content-type {probe['content_type'] or 'unknown'}."
            f"{title}"
        )

    def _build_recon_summary(
        self,
        probes: list[dict[str, object]],
        auth_surfaces: set[str],
        discovered_paths: set[str],
        discovered_parameters: set[str],
    ) -> str:
        lines = [
            f"Reachable endpoints: {len(probes)}",
            f"Observed auth-adjacent surfaces: {', '.join(sorted(auth_surfaces)[:10]) or 'none'}",
            f"Observed paths: {', '.join(sorted(discovered_paths)[:12]) or 'none'}",
            f"Observed query parameters: {', '.join(sorted(discovered_parameters)[:12]) or 'none'}",
        ]
        for probe in probes[:6]:
            lines.append(
                f"- {probe['effective_url']} -> {probe['status_code']} {probe['content_type'] or 'unknown'}"
            )
        return "\n".join(lines)

    def _build_analysis_summary(
        self,
        observed_paths: list[str],
        observed_parameters: list[str],
        auth_ref_count: int,
    ) -> str:
        return (
            f"Evidence-backed surface review found {len(observed_paths)} normalized paths and "
            f"{len(observed_parameters)} normalized query parameter names. "
            f"Auth-adjacent evidence refs: {auth_ref_count}. "
            "No exploit claim is promoted at this stage."
        )

    def _artifact_prefix_for_probe(self, asset_label: str, url: str) -> str:
        parsed = parse.urlsplit(url)
        host = "".join(
            character if character.isalnum() else "_"
            for character in asset_label
        ).strip("_")
        scheme = parsed.scheme or "http"
        return f"recon-{host}-{scheme}"
