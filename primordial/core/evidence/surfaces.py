from __future__ import annotations

from dataclasses import dataclass, field
import json
from typing import Any, Iterable


WINDOWS_TERMS = (
    "windows",
    "microsoft",
    "microsoft-ds",
    "msrpc",
    "netbios",
    "winrm",
    "wsman",
    "httpapi",
    "active directory",
    "domain controller",
    "global catalog",
    "iis",
)

LINUX_TERMS = (
    "linux",
    "ubuntu",
    "debian",
    "centos",
    "red hat",
    "fedora",
    "freebsd",
    "openssh",
    "apache",
    "nginx",
    "samba",
    "webmin",
)

SSH_HTTP_SERVICES = {"ssh", "http", "https", "http-alt", "https-alt", "http-proxy", "webmin"}
SMB_SERVICES = {"smb", "microsoft-ds", "netbios-ssn", "netbios"}
WINRM_SERVICES = {"winrm", "wsman"}
AD_SERVICES = {
    "kerberos",
    "ldap",
    "ldaps",
    "kpasswd",
    "global-catalog",
    "global-catalog-ssl",
    "msrpc",
    "microsoft-ds",
    "netbios-ssn",
}
AD_PORTS = {88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269}
SMB_PORTS = {139, 445}
WINRM_PORTS = {5985, 5986, 47001}


@dataclass(slots=True, frozen=True)
class CredentialedAccessSurface:
    eligible: bool
    protocols: tuple[str, ...] = ()
    os_family: str = "unknown"
    evidence_refs: tuple[str, ...] = ()
    blocked_reason: str = ""
    service_facts: tuple[dict[str, Any], ...] = ()
    signals: dict[str, Any] = field(default_factory=dict)

    def as_payload(self) -> dict[str, Any]:
        return {
            "eligible": self.eligible,
            "protocols": list(self.protocols),
            "os_family": self.os_family,
            "evidence_refs": list(self.evidence_refs),
            "blocked_reason": self.blocked_reason,
            "service_facts": list(self.service_facts),
            "signals": dict(self.signals),
        }


def classify_credentialed_access_surface(evidence: Iterable[object]) -> CredentialedAccessSurface:
    """Classify whether stored evidence supports Windows SMB/WinRM credential validation.

    This intentionally separates Windows SMB/WinRM from generic remote admin
    surfaces such as SSH, HTTP admin panels, NFS, RDP, databases, or Linux Samba.
    """

    evidence_list = list(evidence)
    protocols: set[str] = set()
    supporting_refs: set[str] = set()
    windows_refs: set[str] = set()
    linux_refs: set[str] = set()
    samba_refs: set[str] = set()
    smb_refs: set[str] = set()
    winrm_refs: set[str] = set()
    ad_refs: set[str] = set()
    ssh_http_refs: set[str] = set()
    service_facts: list[dict[str, Any]] = []
    ad_service_refs: dict[str, set[str]] = {}

    for item in evidence_list:
        evidence_id = str(getattr(item, "id", "") or "")
        metadata = getattr(item, "metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
        item_text = _record_text(item, metadata)
        item_kind = str(metadata.get("kind") or "").lower()
        if _has_any(item_text, WINDOWS_TERMS):
            windows_refs.add(evidence_id)
        if _has_any(item_text, LINUX_TERMS):
            linux_refs.add(evidence_id)
        if "samba" in item_text:
            samba_refs.add(evidence_id)
        if item_kind == "ad_enumeration" or _looks_like_ad_text(item_text):
            ad_refs.add(evidence_id)
            windows_refs.add(evidence_id)

        for service in _iter_services(metadata):
            port = _service_port(service)
            service_text = _service_text(service)
            service_name = _service_name(service)
            fact = _service_fact(evidence_id, service)
            if fact:
                service_facts.append(fact)

            if _has_any(service_text, WINDOWS_TERMS):
                windows_refs.add(evidence_id)
            if _has_any(service_text, LINUX_TERMS):
                linux_refs.add(evidence_id)
            if "samba" in service_text:
                samba_refs.add(evidence_id)

            if service_name in SSH_HTTP_SERVICES:
                ssh_http_refs.add(evidence_id)
            if port in SMB_PORTS or service_name in SMB_SERVICES:
                smb_refs.add(evidence_id)
            if port in WINRM_PORTS or service_name in WINRM_SERVICES or "winrm" in service_text or "wsman" in service_text:
                if _service_supports_winrm(port, service_name, service_text):
                    protocols.add("winrm")
                    winrm_refs.add(evidence_id)
                    supporting_refs.add(evidence_id)
                    windows_refs.add(evidence_id)
            if _service_supports_ad(port, service_name, service_text):
                ad_refs.add(evidence_id)
                ad_service_refs.setdefault(evidence_id, set()).add(service_name or str(port))
            if _service_supports_windows_smb(port, service_name, service_text):
                protocols.add("smb")
                supporting_refs.add(evidence_id)
                windows_refs.add(evidence_id)

    # AD/DC evidence plus SMB means the SMB path is Windows-domain-adjacent even
    # when the SMB banner itself is sparse.
    if ad_refs:
        supporting_refs.update(ad_refs)
        windows_refs.update(ad_refs)
        if smb_refs:
            protocols.add("smb")
            supporting_refs.update(smb_refs.intersection(ad_refs) or smb_refs)

    # A lone Samba service is SMB, but it is not a Windows SMB/WinRM credentialed
    # surface and must not trigger Windows flag-path assumptions.
    if samba_refs and not (windows_refs or ad_refs or winrm_refs):
        protocols.discard("smb")

    normalized_protocols = tuple(sorted(protocol for protocol in protocols if protocol in {"smb", "winrm"}))
    refs = tuple(sorted(ref for ref in supporting_refs if ref))
    os_family = _os_family(windows_refs, linux_refs, normalized_protocols)
    eligible = bool(normalized_protocols) and os_family == "windows"
    blocked_reason = "" if eligible else _blocked_reason(
        evidence_list=evidence_list,
        linux_refs=linux_refs,
        samba_refs=samba_refs,
        smb_refs=smb_refs,
        windows_refs=windows_refs,
        ad_refs=ad_refs,
        winrm_refs=winrm_refs,
        ssh_http_refs=ssh_http_refs,
    )
    if not refs and not eligible:
        refs = tuple(sorted(ref for ref in linux_refs.union(samba_refs, smb_refs, ssh_http_refs) if ref))
    return CredentialedAccessSurface(
        eligible=eligible,
        protocols=normalized_protocols,
        os_family=os_family,
        evidence_refs=refs,
        blocked_reason=blocked_reason,
        service_facts=tuple(service_facts[:40]),
        signals={
            "windows_evidence_ids": sorted(ref for ref in windows_refs if ref),
            "linux_evidence_ids": sorted(ref for ref in linux_refs if ref),
            "samba_evidence_ids": sorted(ref for ref in samba_refs if ref),
            "smb_evidence_ids": sorted(ref for ref in smb_refs if ref),
            "winrm_evidence_ids": sorted(ref for ref in winrm_refs if ref),
            "ad_evidence_ids": sorted(ref for ref in ad_refs if ref),
            "ssh_http_evidence_ids": sorted(ref for ref in ssh_http_refs if ref),
            "ad_service_refs": {key: sorted(values) for key, values in ad_service_refs.items()},
        },
    )


def _blocked_reason(
    *,
    evidence_list: list[object],
    linux_refs: set[str],
    samba_refs: set[str],
    smb_refs: set[str],
    windows_refs: set[str],
    ad_refs: set[str],
    winrm_refs: set[str],
    ssh_http_refs: set[str],
) -> str:
    if not evidence_list:
        return "No current-generation evidence is available for credentialed Windows access planning."
    if samba_refs and not (windows_refs or ad_refs or winrm_refs):
        return "SMB evidence appears to be Samba or another non-Windows SMB surface, not Windows SMB/WinRM."
    if linux_refs and not (windows_refs or ad_refs or winrm_refs):
        return "Current evidence indicates Linux/Unix services, not Windows SMB/WinRM or AD/DC."
    if ssh_http_refs and not (smb_refs or windows_refs or ad_refs or winrm_refs):
        return "Current evidence only identifies SSH/HTTP-style services, not Windows SMB/WinRM or AD/DC."
    return "Current evidence does not identify WinRM, Microsoft/Windows SMB, or AD/DC indicators."


def _os_family(windows_refs: set[str], linux_refs: set[str], protocols: tuple[str, ...]) -> str:
    if windows_refs or "winrm" in protocols:
        return "windows"
    if linux_refs:
        return "linux"
    return "unknown"


def _iter_services(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    services = metadata.get("open_services", [])
    if isinstance(services, list):
        return [service for service in services if isinstance(service, dict)]
    return []


def _service_port(service: dict[str, Any]) -> int:
    try:
        return int(service.get("port", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _service_name(service: dict[str, Any]) -> str:
    raw = service.get("service") or service.get("name") or service.get("service_name") or ""
    return str(raw).strip().lower()


def _service_text(service: dict[str, Any]) -> str:
    parts = [
        service.get("service"),
        service.get("name"),
        service.get("service_name"),
        service.get("product"),
        service.get("version"),
        service.get("banner"),
        service.get("extrainfo"),
        service.get("ostype"),
        service.get("cpe"),
    ]
    return " ".join(str(part).lower() for part in parts if part is not None and part != "")


def _record_text(item: object, metadata: dict[str, Any]) -> str:
    safe_metadata = {
        key: value
        for key, value in metadata.items()
        if key
        in {
            "kind",
            "open_services",
            "os",
            "os_family",
            "service",
            "service_name",
            "domain",
            "dns_domain",
            "netbios_name",
            "workgroup",
            "forest",
            "ldap_naming_contexts",
            "smb_os",
            "smb_domain",
        }
    }
    parts = [
        getattr(item, "title", ""),
        getattr(item, "summary", ""),
        getattr(item, "source_ref", ""),
        json.dumps(safe_metadata, sort_keys=True, default=str),
    ]
    return " ".join(str(part).lower() for part in parts if part)


def _service_fact(evidence_id: str, service: dict[str, Any]) -> dict[str, Any]:
    fact: dict[str, Any] = {"evidence_id": evidence_id}
    for key in ("host", "port", "service", "product", "version", "banner", "extrainfo", "ostype"):
        value = service.get(key)
        if value is not None and value != "":
            fact[key] = value
    return fact


def _service_supports_winrm(port: int, service_name: str, text: str) -> bool:
    if service_name in WINRM_SERVICES or "winrm" in text or "wsman" in text:
        return True
    return port in WINRM_PORTS and ("microsoft" in text or "httpapi" in text)


def _service_supports_windows_smb(port: int, service_name: str, text: str) -> bool:
    if port not in SMB_PORTS and service_name not in SMB_SERVICES:
        return False
    if "samba" in text:
        return False
    return _has_any(text, ("windows", "microsoft", "microsoft-ds", "active directory", "domain controller"))


def _service_supports_ad(port: int, service_name: str, text: str) -> bool:
    if _looks_like_ad_text(text):
        return True
    if port in {3268, 3269} or service_name in {"global-catalog", "global-catalog-ssl"}:
        return True
    if port in AD_PORTS and service_name in AD_SERVICES and "samba" not in text:
        return True
    return False


def _looks_like_ad_text(text: str) -> bool:
    return _has_any(
        text,
        (
            "active directory",
            "domain controller",
            "domain controllers",
            "ldapservice",
            "ldap service name",
            "rootdse",
            "defaultnamingcontext",
            "domaindnszones",
            "forestdnszones",
            "global catalog",
        ),
    )


def _has_any(value: str, needles: tuple[str, ...]) -> bool:
    return any(needle in value for needle in needles)
