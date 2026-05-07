from __future__ import annotations

from pathlib import Path

from primordial.core.catalog.heuristics import HeuristicCatalog


_CATALOG_ROOT = Path(__file__).resolve().parents[3] / "catalog" / "heuristics"
_HEURISTICS = HeuristicCatalog(_CATALOG_ROOT)


def _load_service_discovery() -> dict[str, object]:
    try:
        return _HEURISTICS.load("service_discovery")
    except Exception:
        return {}


_SERVICE_DISCOVERY = _load_service_discovery()

# Canonical TCP port lists. Import from here; do not redefine in execution or workflow layers.

_DEFAULT_SERVICE_DISCOVERY_PORTS: tuple[int, ...] = (
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

_DEFAULT_SERVICE_NAME_BY_PORT: dict[int, str] = {
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

SERVICE_DISCOVERY_PORTS: tuple[int, ...] = tuple(
    int(item) for item in _SERVICE_DISCOVERY.get("service_ports", _DEFAULT_SERVICE_DISCOVERY_PORTS)
)

SERVICE_NAME_BY_PORT: dict[int, str] = {
    int(port): str(name)
    for port, name in (
        _SERVICE_DISCOVERY.get("service_names", _DEFAULT_SERVICE_NAME_BY_PORT)
        if isinstance(_SERVICE_DISCOVERY.get("service_names", _DEFAULT_SERVICE_NAME_BY_PORT), dict)
        else _DEFAULT_SERVICE_NAME_BY_PORT
    ).items()
}

# Ports that indicate an exposed remote-administration or data-access surface.
# Used by both the execution layer (interest classification) and the workflow
# orchestrator (credentialed-access task planning). Must stay in sync.
REMOTE_ADMIN_PORTS: frozenset[int] = frozenset(
    int(item) for item in _SERVICE_DISCOVERY.get("remote_admin_ports", {21, 22, 445, 1433, 2049, 3306, 3389, 5985, 5986})
)

# Ports whose presence implies Active Directory is reachable.
AD_INDICATOR_PORTS: frozenset[int] = frozenset(
    int(item) for item in _SERVICE_DISCOVERY.get("ad_indicator_ports", {88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269})
)

# Ports that carry DNS traffic (standard + DNS-over-TLS).
DNS_PORTS: frozenset[int] = frozenset(int(item) for item in _SERVICE_DISCOVERY.get("dns_ports", {53, 853}))

# Scope-profile → set of task kind values that are planned without requiring
# explicit per-target allow_* metadata. Extend here when adding new profiles
# rather than adding more string literals in the workflow layer.
PROFILE_DEFAULT_TASK_ALLOWLIST: dict[str, frozenset[str]] = {
    "hack_the_box": frozenset({
        "service_discovery",
        "ad_enumeration",
        "dns_enumeration",
        "web_content_discovery",
        "kerberos_user_discovery",
    }),
    "hackerone": frozenset(),
}
