from __future__ import annotations

from .models import VulnerabilityRecord


INTEREST_DOMAINS = {
    "api_security",
    "web_security",
    "kubernetes_cloud",
    "container_security",
    "windows_linux",
    "network_infra",
    "kernel_security",
    "package_security",
    "cloud_security",
}


def domains_for_record(record: VulnerabilityRecord) -> list[str]:
    domains: set[str] = {"vuln_intel"}
    text = " ".join(
        [
            record.title,
            record.description,
            " ".join(record.affected_products),
            " ".join(pkg.ecosystem for pkg in record.affected_packages),
            " ".join(pkg.name for pkg in record.affected_packages),
        ]
    ).lower()
    if any(token in text for token in ("api", "http", "web", "browser", "xss", "ssrf", "csrf")):
        domains.update({"api_security", "web_security"})
    if any(token in text for token in ("kubernetes", "k8s", "container", "docker", "helm")):
        domains.update({"kubernetes_cloud", "container_security"})
    if any(token in text for token in ("linux", "windows", "openssh", "openssl", "nginx", "apache")):
        domains.update({"windows_linux", "network_infra"})
    if any(token in text for token in ("kernel", "driver", "ebpf")):
        domains.add("kernel_security")
    if record.affected_packages:
        domains.add("package_security")
    return sorted(domains)


def should_embed_record(record: VulnerabilityRecord, *, epss_percentile_threshold: float = 0.90, embed_all: bool = False) -> bool:
    if embed_all:
        return True
    if record.kev.get("known_exploited"):
        return True
    if record.epss and record.epss.percentile is not None and record.epss.percentile >= epss_percentile_threshold:
        return True
    if any((metric.severity or "").upper() in {"HIGH", "CRITICAL"} for metric in record.cvss):
        return True
    if set(domains_for_record(record)) & INTEREST_DOMAINS:
        return True
    if record.advisory_references or record.patch_references:
        return True
    return False
