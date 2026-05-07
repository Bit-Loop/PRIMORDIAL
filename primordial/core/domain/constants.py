from __future__ import annotations

# Canonical TCP port lists. Import from here; do not redefine in execution or workflow layers.

SERVICE_DISCOVERY_PORTS: tuple[int, ...] = (
    21,
    22,
    25,
    53,
    80,
    88,
    110,
    111,
    135,
    139,
    143,
    389,
    443,
    445,
    464,
    593,
    636,
    1433,
    2049,
    3268,
    3269,
    3306,
    3389,
    5000,
    5985,
    5986,
    8000,
    8080,
    8443,
    8888,
    10000,
    47001,
    49152,
    49153,
    49154,
    49155,
    49156,
    49157,
)

SERVICE_NAME_BY_PORT: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    88: "kerberos",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "smb",
    464: "kpasswd",
    593: "http-rpc-epmap",
    636: "ldaps",
    1433: "mssql",
    2049: "nfs",
    3268: "global-catalog",
    3269: "global-catalog-ssl",
    3306: "mysql",
    3389: "rdp",
    5000: "http-alt",
    5985: "winrm-http",
    5986: "winrm-https",
    8000: "http-alt",
    8080: "http-alt",
    8443: "https-alt",
    8888: "http-alt",
    10000: "webmin",
    47001: "winrm",
}

# Ports that indicate an exposed remote-administration or data-access surface.
# Used by both the execution layer (interest classification) and the workflow
# orchestrator (credentialed-access task planning). Must stay in sync.
REMOTE_ADMIN_PORTS: frozenset[int] = frozenset({21, 22, 445, 1433, 2049, 3306, 3389, 5985, 5986})

# Ports whose presence implies Active Directory is reachable.
AD_INDICATOR_PORTS: frozenset[int] = frozenset({88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269})

# Ports that carry DNS traffic (standard + DNS-over-TLS).
DNS_PORTS: frozenset[int] = frozenset({53, 853})

# Scope-profile → set of task kind values that are planned without requiring
# explicit per-target allow_* metadata. Extend here when adding new profiles
# rather than adding more string literals in the workflow layer.
PROFILE_DEFAULT_TASK_ALLOWLIST: dict[str, frozenset[str]] = {
    "hack_the_box": frozenset({
        "service_discovery",
        "ad_enumeration",
        "dns_enumeration",
        "web_content_discovery",
        "exploit_research",
        "poc_applicability_validation",
        "kerberos_user_discovery",
        "kerberos_attack_check",
        "credentialed_access_check",
    }),
    "hackerone": frozenset(),
}
