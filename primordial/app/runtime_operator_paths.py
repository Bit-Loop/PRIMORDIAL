from __future__ import annotations

from primordial.app.runtime_deps import (
    CredentialedAccessSurface,
    EvidenceRecord,
    Finding,
    Interest,
    InterestStatus,
    re,
    VerificationStatus,
)

class RuntimeOperatorPathsMixin:
    def _deterministic_potential_paths(
        self,
        evidence: list[EvidenceRecord],
        interests: list[Interest],
        findings: list[Finding],
    ) -> list[str]:
        paths: list[str] = []
        seen: set[str] = set()

        for finding in findings:
            status = getattr(finding, "verification_status", None)
            if status == VerificationStatus.VERIFIED:
                continue
            line = (
                f"`{finding.title}` is a {finding.severity.value} candidate with "
                f"{finding.confidence:.2f} confidence and {finding.verification_status.value} verification."
            )
            self._append_unique(paths, seen, line)

        for interest in interests:
            if interest.status in {InterestStatus.REJECTED, InterestStatus.STALE, InterestStatus.SUPERSEDED}:
                continue
            interest_class = str(interest.metadata.get("class", ""))
            if interest_class == "exploit_research" or "poc" in interest.title.lower() or "exploit" in interest.title.lower():
                line = f"`{interest.title}`: {interest.summary} Confidence {interest.confidence:.2f}."
                if self._looks_like_lpe(interest.title, interest.summary):
                    line += " Prerequisite: requires user shell or credentialed access before LPE verification."
                self._append_unique(paths, seen, line)

        for item in evidence:
            if item.metadata.get("kind") != "exploit_research":
                continue
            match_count = int(item.metadata.get("match_count", 0) or 0)
            if match_count <= 0:
                continue
            line = (
                f"`{item.title}` retained {match_count} non-DoS public exploit reference(s). "
                "These are potential paths until target-specific version/applicability evidence verifies them."
            )
            if self._looks_like_lpe(item.title, item.summary):
                line += " Prerequisite: requires user shell or credentialed access before LPE verification."
            self._append_unique(paths, seen, line)

        return paths

    def _deterministic_blockers(
        self,
        flag_hits: list[EvidenceRecord],
        findings: list[Finding],
        potential_paths: list[str],
        capabilities: set[str],
        lab_credentials_configured: bool,
        credential_surface: CredentialedAccessSurface,
    ) -> list[str]:
        blockers: list[str] = []
        if not flag_hits:
            blockers.append("No stored evidence contains a user/root flag or flag-like token.")
        verified_findings = [
            finding for finding in findings if getattr(finding, "verification_status", None) == VerificationStatus.VERIFIED
        ]
        if not verified_findings and not potential_paths:
            blockers.append("No verified findings or potential exploit paths are stored for this target.")
        if not self._has_any_capability(capabilities, "finding-verification", "auth-analysis"):
            blockers.append("No registered finding-verification primitive is available for exploitation-phase validation.")
        if not self._has_any_capability(capabilities, "winrm", "smb-session", "flag-collection", "credential-use"):
            blockers.append("No credentialed WinRM/SMB flag-collection primitive is registered.")
        elif credential_surface.eligible and not lab_credentials_configured and not flag_hits:
            blockers.append("Known username/password are not configured, so credentialed Windows SMB/WinRM verification cannot run.")
        if potential_paths and not self._poc_adaptation_available(capabilities):
            blockers.append(
                "Retained public PoC candidates exist, but no gated PoC applicability/adaptation primitive is registered."
            )
        return blockers

    def _lab_credentials_configured(self) -> bool:
        username = self.credentials.get("known", "username")
        password = self.credentials.get("known", "password")
        return bool(username and password)

    def _deterministic_next_actions(
        self,
        evidence: list[EvidenceRecord],
        interests: list[Interest],
        findings: list[Finding],
        capabilities: set[str],
        credential_surface: CredentialedAccessSurface,
    ) -> list[str]:
        actions: list[tuple[float, str]] = []
        evidence_kinds = {
            str(item.metadata.get("kind"))
            for item in evidence
            if item.metadata.get("kind")
        }
        has_http = any(self._evidence_has_http_surface(item) for item in evidence)
        has_dns_port = self._evidence_has_port(evidence, 53)
        has_ad_ports = any(
            self._evidence_has_port(evidence, port)
            for port in (88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269)
        )
        has_shell = self._has_shell_or_credentialed_access(evidence, interests, findings)
        lab_credentials_configured = self._lab_credentials_configured()
        intent_policy = self.intent_policy()
        allows_exploit_research = bool(intent_policy.public_poc_research and intent_policy.searchsploit_allowed)
        allows_poc_validation = bool(intent_policy.poc_applicability_validation)
        allows_kerberos = bool(
            intent_policy.kerberos_policy.asrep_roast_check_allowed
            or intent_policy.kerberos_policy.kerberoast_check_allowed
        )
        allows_credential_validation = bool(intent_policy.credential_policy.credential_validation_allowed)
        has_exploit_candidates = any(
            item.metadata.get("kind") == "exploit_research" and int(item.metadata.get("match_count", 0) or 0) > 0
            for item in evidence
        ) or any(interest.metadata.get("class") == "exploit_research" for interest in interests)
        has_versioned_service_terms = self._has_service_version_terms(evidence)
        has_lpe_candidate = any(
            self._looks_like_lpe(item.title, item.summary)
            for item in [*evidence, *interests]
        ) or any(self._looks_like_lpe(finding.title, finding.summary) for finding in findings)

        if "tcp_service_discovery" not in evidence_kinds and self._has_any_capability(capabilities, "tcp-service-discovery"):
            actions.append((0.92, "Run bounded TCP service discovery. Prerequisite: target is in scope."))
        if has_dns_port and "dns_enumeration" not in evidence_kinds and self._has_any_capability(capabilities, "dns-enumeration"):
            actions.append((0.88, "Run bounded DNS enumeration. Prerequisite: TCP evidence shows DNS/53."))
        if has_ad_ports and "ad_enumeration" not in evidence_kinds and self._has_any_capability(capabilities, "ad-enumeration", "ldap-enumeration"):
            if allows_kerberos:
                actions.append((0.87, "Run anonymous AD enumeration. Prerequisite: TCP evidence shows LDAP/Kerberos/SMB services."))
            else:
                actions.append((0.87, "Verify lab/AD operator intent before anonymous AD enumeration. Prerequisite: active intent blocks LDAP/SMB/RPC inventory."))
        if has_http and "web_content_discovery" not in evidence_kinds and self._has_any_capability(capabilities, "content-discovery", "path-enumeration"):
            actions.append((0.82, "Run bounded web content discovery. Prerequisite: HTTP probe evidence shows a live web surface."))
        if (
            {"tcp_service_discovery", "dns_enumeration", "ad_enumeration"}.intersection(evidence_kinds)
            and "exploit_research" not in evidence_kinds
            and self._has_any_capability(capabilities, "exploit-research", "searchsploit")
            and has_versioned_service_terms
        ):
            if allows_exploit_research:
                actions.append((0.78, "Run evidence-backed Searchsploit research. Prerequisite: service/version terms from stored recon evidence."))
            else:
                actions.append((0.78, "Switch to an operator intent that allows public PoC research before running Searchsploit. Prerequisite: active intent policy currently blocks it."))
        elif (
            {"tcp_service_discovery", "dns_enumeration", "ad_enumeration"}.intersection(evidence_kinds)
            and "exploit_research" not in evidence_kinds
            and self._has_any_capability(capabilities, "exploit-research", "searchsploit")
        ):
            if allows_exploit_research:
                actions.append((0.77, "Collect current service/version evidence before Searchsploit research. Prerequisite: exact product/version terms are not yet stored."))
            else:
                actions.append((0.77, "Keep collecting exact service/version evidence; Searchsploit is blocked by the active operator intent."))
        if has_exploit_candidates:
            if self._poc_adaptation_available(capabilities) and allows_poc_validation:
                actions.append((0.76, "Run gated public PoC applicability validation against exact service/version evidence. Prerequisite: retained non-DoS Searchsploit candidates."))
            elif self._poc_adaptation_available(capabilities):
                actions.append((0.76, "Switch to an operator intent that allows PoC applicability validation before reviewing retained public exploit references."))
            else:
                actions.append((0.76, "Add a gated PoC applicability/adaptation primitive before validating retained public exploit references. Prerequisite: retained non-DoS Searchsploit candidates."))
        if has_ad_ports and "ad_enumeration" in evidence_kinds and "kerberos_user_discovery" not in evidence_kinds:
            if allows_kerberos:
                actions.append((0.74, "Add or run Kerberos/LDAP user discovery before AS-REP/Kerberoast checks. Prerequisite: AD enumeration evidence exists."))
            else:
                actions.append((0.74, "Verify lab/AD operator intent before Kerberos/LDAP user discovery. Prerequisite: active intent blocks principal discovery."))
        if has_lpe_candidate and has_shell:
            actions.append((0.80, "Verify local privilege-escalation candidate. Prerequisite: credentialed shell/access evidence exists."))
        elif has_lpe_candidate:
            actions.append((0.54, "Defer local privilege-escalation candidate until user shell or credentialed access exists. Prerequisite: foothold not yet evidenced."))
        if (
            credential_surface.eligible
            and self._has_any_capability(capabilities, "credentialed-access-check", "smb-session", "winrm")
            and not lab_credentials_configured
        ):
            if allows_credential_validation:
                actions.append((0.72, "Configure known credentials before credentialed Windows SMB/WinRM verification. Prerequisite: operator-provided username/password."))
            else:
                actions.append((0.72, "Switch to an intent that allows credential validation before configuring SMB/WinRM verification credentials."))

        return [f"{text} Confidence: {score:.2f}." for score, text in sorted(actions, reverse=True)[:5]]

    def _has_service_version_terms(self, evidence: list[EvidenceRecord]) -> bool:
        version_pattern = re.compile(r"\b\d+(?:\.\d+){1,3}[A-Za-z0-9._+-]*\b")
        empty_values = {"", "unknown", "none", "n/a", "tcpwrapped"}

        def has_version(value: object) -> bool:
            text = str(value or "").strip()
            if text.lower() in empty_values:
                return False
            return bool(version_pattern.search(text))

        for item in evidence:
            metadata = item.metadata
            for key in ("service_version", "version", "product_version", "banner", "fingerprint"):
                if has_version(metadata.get(key)):
                    return True
            for service in metadata.get("open_services", []):
                if not isinstance(service, dict):
                    continue
                version = service.get("version") or service.get("product_version")
                product = service.get("product") or service.get("name") or service.get("service")
                if has_version(version):
                    return True
                combined = " ".join(str(service.get(key) or "") for key in ("product", "banner", "extrainfo", "fingerprint"))
                if product and has_version(combined):
                    return True
            headers = metadata.get("headers")
            if isinstance(headers, dict) and has_version(headers.get("server") or headers.get("Server")):
                return True
        return False

    def _deterministic_capability_gaps(
        self,
        evidence: list[EvidenceRecord],
        evidence_kinds: set[str],
        capabilities: set[str],
        credential_surface: CredentialedAccessSurface,
    ) -> list[str]:
        gaps: list[str] = []
        has_http = any(self._evidence_has_http_surface(item) for item in evidence)
        has_ad_ports = any(self._evidence_has_port(evidence, port) for port in (88, 389, 445, 636, 3268, 3269))
        has_exploit_candidates = any(
            item.metadata.get("kind") == "exploit_research" and int(item.metadata.get("match_count", 0) or 0) > 0
            for item in evidence
        )
        if has_http and "web_content_discovery" not in evidence_kinds and not self._has_any_capability(capabilities, "content-discovery", "path-enumeration"):
            gaps.append("Content discovery primitive is missing for live HTTP surfaces.")
        if has_ad_ports and not self._has_any_capability(capabilities, "kerberos-user-discovery", "ldap-user-discovery", "asrep-roast", "kerberoast"):
            gaps.append("Kerberos/LDAP user-discovery primitive is missing for AD attack-path validation.")
        if has_exploit_candidates and not self._poc_adaptation_available(capabilities):
            gaps.append("Gated exploit-synthesis/adaptation primitive is missing for retained public PoC candidates.")
        if credential_surface.eligible and not self._has_any_capability(capabilities, "winrm", "smb-session", "flag-collection", "credential-use"):
            gaps.append("Credentialed WinRM/SMB flag-collection primitive is missing.")
        return gaps

    def _append_unique(self, values: list[str], seen: set[str], value: str) -> None:
        key = value.lower()
        if key not in seen:
            values.append(value)
            seen.add(key)
