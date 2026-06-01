from __future__ import annotations

from primordial.modes.security.execution_common import *


class PrimitivePocToolMixin:
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
        blocked_reason = self._poc_guardrail_block_reason(lowered, service_facts, has_foothold)
        if blocked_reason:
            reasons.append(blocked_reason)
        else:
            match = self._poc_service_match(lowered, service_facts)
            if match is None:
                reasons.append("no exact target service/version or prerequisite match is available")
            else:
                status, reason = match
                reasons.append(reason)
        return {
            "title": title,
            "edb_id": candidate.get("edb_id"),
            "path": candidate.get("path"),
            "status": status,
            "reasons": reasons,
            "executes_poc": False,
        }

    def _poc_guardrail_block_reason(
        self,
        lowered: str,
        service_facts: dict[str, object],
        has_foothold: bool,
    ) -> str:
        if any(term in lowered for term in EXPLOIT_RESEARCH_SUPPRESSED_TERMS):
            return "suppressed because it appears DoS/crash-oriented"
        if any(term in lowered for term in EXPLOIT_RESEARCH_LOCAL_TERMS) and not has_foothold:
            return "requires user shell or credentialed local access before LPE verification"
        if "exchange" in lowered and not service_facts.get("has_exchange"):
            return "target evidence does not show Microsoft Exchange"
        if ("windows server 2000" in lowered or "server 2000" in lowered) and not service_facts.get("has_windows_2000"):
            return "target evidence does not show Windows Server 2000"
        return ""

    def _poc_service_match(
        self,
        lowered: str,
        service_facts: dict[str, object],
    ) -> tuple[str, str] | None:
        checks = [
            (("ldap", "active directory"), "has_ad", "AD/LDAP surface exists, but exact version/configuration still needs bounded verification", "target evidence does not show AD/LDAP services"),
            (("iis",), "has_iis", "IIS surface exists, but exact version and exploit preconditions still need bounded verification", "target evidence does not show IIS-specific service details"),
            (("smb", "samba", "netbios", "eternalblue", "ms17-010"), "has_smb", "SMB/Samba surface exists; exact OS version and patch level must be confirmed before use", "target evidence does not show SMB/Samba services"),
            (("ssh",), "has_ssh", "SSH surface exists; exact version and configuration must be verified before use", "target evidence does not show SSH service"),
            (("tomcat", "apache tomcat"), "has_tomcat", "Tomcat surface exists; exact version and manager configuration must be verified", "target evidence does not show Apache Tomcat"),
            (("struts", "apache struts"), "has_struts", "Struts surface exists; exact version needed before candidate is actionable", "target evidence does not show Apache Struts"),
            (("jenkins",), "has_jenkins", "Jenkins surface exists; authentication state and version must be confirmed", "target evidence does not show Jenkins"),
            (("mssql", "sql server", "ms sql"), "has_mssql", "MSSQL surface exists; authentication mode and version must be confirmed", "target evidence does not show MSSQL"),
            (("rdp", "remote desktop"), "has_rdp", "RDP surface exists; exact Windows build and patch level must be confirmed", "target evidence does not show RDP service"),
            (("wordpress", "wp-"), "has_wordpress", "WordPress surface exists; exact version and plugin inventory must be confirmed", "target evidence does not show WordPress"),
        ]
        for terms, fact_key, ready_reason, blocked_reason in checks:
            if any(term in lowered for term in terms):
                if service_facts.get(fact_key):
                    return "ready_for_review", ready_reason
                return "blocked", blocked_reason
        return None

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
