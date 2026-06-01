from __future__ import annotations

from primordial.app.runtime_deps import (
    EvidenceRecord,
    Finding,
    Interest,
    json,
    VerificationStatus,
)

class RuntimeOperatorEvidenceMixin:
    def _poc_adaptation_available(self, capabilities: set[str]) -> bool:
        if self._has_any_capability(capabilities, "poc-adaptation", "poc-applicability-validation"):
            return True
        return self.config.autonomy.allow_remote_premium and self._has_any_capability(capabilities, "exploit-synthesis")

    def _has_any_capability(self, capabilities: set[str], *needles: str) -> bool:
        lowered = {capability.lower() for capability in capabilities}
        return any(any(needle in capability for capability in lowered) for needle in needles)

    def _evidence_has_port(self, evidence: list[EvidenceRecord], port: int) -> bool:
        for item in evidence:
            for service in item.metadata.get("open_services", []):
                if isinstance(service, dict) and int(service.get("port", 0) or 0) == port:
                    return True
        return False

    def _evidence_has_http_surface(self, item: EvidenceRecord) -> bool:
        effective_url = item.metadata.get("effective_url")
        status_code = item.metadata.get("status_code")
        if isinstance(effective_url, str) and effective_url.startswith(("http://", "https://")):
            return not isinstance(status_code, int) or status_code < 500
        for service in item.metadata.get("open_services", []):
            if not isinstance(service, dict):
                continue
            name = str(service.get("service", "")).lower()
            port = int(service.get("port", 0) or 0)
            if name in {"http", "https", "http-rpc-epmap"} or port in {80, 443, 593, 5985}:
                return True
        return False

    def _has_shell_or_credentialed_access(
        self,
        evidence: list[EvidenceRecord],
        interests: list[Interest],
        findings: list[Finding],
    ) -> bool:
        del interests
        records = [item.as_payload() for item in evidence]
        records.extend(
            finding.as_payload()
            for finding in findings
            if getattr(finding, "verification_status", None) in {VerificationStatus.PARTIAL, VerificationStatus.VERIFIED}
        )
        joined = json.dumps(records).lower()
        if any(token in joined for token in ("requires credentialed access", "requires user shell", "before lpe verification")):
            joined = joined.replace("requires credentialed access", "")
            joined = joined.replace("requires user shell", "")
            joined = joined.replace("before lpe verification", "")
        return any(
            token in joined
            for token in (
                "user.txt",
                "root.txt",
                "shell",
                "credentialed",
                "valid credential",
                "winrm session",
                "smb session",
                "meterpreter",
                # Linux / generic shell indicators
                "interactive shell",
                "shell obtained",
                "reverse shell",
                "bind shell",
                "command execution",
                "rce confirmed",
                "arbitrary command",
                "shell_access",
                "initial_access",
                # HTB/CTF flag patterns
                "flag.txt",
                "proof.txt",
                "local.txt",
                "pwned",
                "pwn3d",
                "foothold",
            )
        )

    def _looks_like_lpe(self, *values: str) -> bool:
        joined = " ".join(values).lower()
        return any(
            token in joined
            for token in (
                "unquoted service path",
                "local privilege escalation",
                "privilege escalation",
                "lpe",
                "privesc",
                # Linux LPE signals
                "sudo exploit",
                "suid",
                "sgid",
                "kernel exploit",
                "dirtycow",
                "dirty cow",
                "dirty pipe",
                "pwnkit",
                "polkit",
                "cve-2021-4034",
                "cve-2022-0847",
                "writable /etc/passwd",
                "writable sudoers",
                "no passwd sudo",
                "capabilities exploit",
                "cap_setuid",
            )
        )
