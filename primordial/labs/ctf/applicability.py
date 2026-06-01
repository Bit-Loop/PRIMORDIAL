from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping

from primordial.labs.ctf.hidden_material import reject_hidden_flag_material
from primordial.labs.ctf.targets import CTFTarget


APPLICABILITY_EXIT_GATES = ("exploit_applicability_checked_against_observed_evidence",)


@dataclass(frozen=True, slots=True)
class ExploitApplicabilityResult:
    target_id: str
    cve_id: str
    status: str
    observed_product: str
    observed_version: str
    evidence_refs: tuple[str, ...]
    reasons: tuple[str, ...]
    exit_gates: tuple[str, ...] = APPLICABILITY_EXIT_GATES
    observations: Mapping[str, Any] | None = None

    def as_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["evidence_refs"] = list(self.evidence_refs)
        payload["reasons"] = list(self.reasons)
        payload["exit_gates"] = list(self.exit_gates)
        payload["observations"] = dict(self.observations or {})
        return payload


def validate_vulhub_exploit_applicability(
    target: CTFTarget,
    *,
    observed_product: str,
    observed_version: str,
    evidence_refs: list[str] | tuple[str, ...],
    observations: Mapping[str, Any] | None = None,
) -> ExploitApplicabilityResult:
    payload = {
        "target_id": target.id,
        "observed_product": observed_product,
        "observed_version": observed_version,
        "evidence_refs": evidence_refs,
        "observations": dict(observations or {}),
    }
    reject_hidden_flag_material(payload, path="ctf_applicability", label="ExploitApplicabilityResult")
    _validate_vulhub_target(target)
    refs = _evidence_refs(evidence_refs)
    product = _required(observed_product, "observed_product")
    version = _required(observed_version, "observed_version")
    status, reasons = _classification(target, product=product, version=version)
    return ExploitApplicabilityResult(
        target_id=target.id,
        cve_id=target.vulnerability.cve_id,
        status=status,
        observed_product=product,
        observed_version=version,
        evidence_refs=refs,
        reasons=reasons,
        observations=dict(observations or {}),
    )


def _validate_vulhub_target(target: CTFTarget) -> None:
    if target.target_family != "vulhub_cve_labs" or not target.vulnerability.cve_id:
        raise ValueError("Exploit applicability requires a Vulhub CVE target manifest")


def _classification(target: CTFTarget, *, product: str, version: str) -> tuple[str, tuple[str, ...]]:
    if _normalized(product) != _normalized(target.vulnerability.product):
        return "not_applicable", ("observed product mismatch",)
    observed = _normalized(version)
    affected = {_normalized(item) for item in target.vulnerability.affected_versions}
    fixed = {_normalized(item) for item in target.vulnerability.fixed_versions}
    if observed in fixed:
        return "not_applicable", ("fixed version observed",)
    if observed in affected:
        return "applicable", ("affected version observed",)
    return "unknown", ("observed version not listed",)


def _evidence_refs(value: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError("Exploit applicability evidence_refs must be a list or tuple")
    refs: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ValueError("Exploit applicability evidence_refs entry requires non-empty text")
        ref = item.strip()
        if not ref.startswith("evidence:"):
            raise ValueError("Exploit applicability evidence_refs entry must use evidence:<id>")
        if ref in refs:
            raise ValueError(f"Exploit applicability duplicate evidence_refs entry: {ref}")
        refs.append(ref)
    if not refs:
        raise ValueError("Exploit applicability requires evidence_refs")
    return tuple(refs)


def _required(value: str, name: str) -> str:
    text = str(value).strip()
    if not text:
        raise ValueError(f"Exploit applicability requires {name}")
    return text


def _normalized(value: str) -> str:
    return " ".join(str(value).strip().casefold().split())
