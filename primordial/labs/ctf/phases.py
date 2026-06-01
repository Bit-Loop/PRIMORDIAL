from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from primordial.core.catalog.loader import CatalogValidationError, expect_bool, expect_string_list, load_yaml_file
from primordial.labs.ctf.hidden_material import reject_hidden_flag_material

EXPECTED_PHASES = (
    (0, "phase_0_harness_first", "Phase 0 Harness First"),
    (1, "phase_1_juice_shop", "Phase 1 Juice Shop"),
    (2, "phase_2_vulhub_cve_labs", "Phase 2 Vulhub CVE Labs"),
    (3, "phase_3_mbptl", "Phase 3 MBPTL"),
    (4, "phase_4_ci_cd_goat", "Phase 4 CI/CD Goat"),
    (5, "phase_5_kubernetes_goat", "Phase 5 Kubernetes Goat"),
    (6, "phase_6_goad_light_goad", "Phase 6 GOAD-Light/GOAD"),
    (7, "phase_7_cloudgoat", "Phase 7 CloudGoat"),
    (8, "phase_8_dreadgoad_ctf_dojo_nyu_ctf_bench", "Phase 8 DreadGOAD/CTF-Dojo/NYU CTF Bench"),
)
ALLOWED_STATUSES = frozenset({"not_started", "in_progress", "ready_for_review", "blocked", "complete"})
ALLOWED_PROFILES = frozenset({"co_internal_lab", "co_hack_the_box"})


@dataclass(frozen=True, slots=True)
class CTFLabPhase:
    number: int
    id: str
    name: str
    status: str
    target_families: tuple[str, ...]
    allowed_profiles: tuple[str, ...]
    environment_proof_required: bool
    deterministic_fixture_required: bool
    exit_gates: tuple[str, ...]
    validation_commands: tuple[str, ...]
    verified_environment_refs: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CTFLabPhaseCatalog:
    version: int
    phases: tuple[CTFLabPhase, ...]

    def phase(self, number: int) -> CTFLabPhase:
        for item in self.phases:
            if item.number == number:
                return item
        raise KeyError(number)


def load_ctf_lab_phase_catalog(path: str | Path) -> CTFLabPhaseCatalog:
    catalog_path = Path(path)
    payload = load_yaml_file(catalog_path)
    reject_hidden_flag_material(payload, path=str(catalog_path), label="CTF lab phase catalog")
    version = _int(payload.get("version"), source=f"{catalog_path}.version")
    raw_phases = payload.get("phases")
    if not isinstance(raw_phases, list):
        raise CatalogValidationError(f"{catalog_path}.phases must be a list")
    phases = tuple(_phase(item, source=f"{catalog_path}.phases[{index}]") for index, item in enumerate(raw_phases))
    _validate_expected_phase_set(phases, source=str(catalog_path))
    return CTFLabPhaseCatalog(version=version, phases=phases)


def _phase(value: Any, *, source: str) -> CTFLabPhase:
    if not isinstance(value, Mapping):
        raise CatalogValidationError(f"{source} must be an object")
    payload = dict(value)
    status = _text(payload.get("status"), source=f"{source}.status")
    if status not in ALLOWED_STATUSES:
        raise CatalogValidationError(f"{source}.status must be one of {sorted(ALLOWED_STATUSES)}")
    profiles = tuple(expect_string_list(payload.get("allowed_profiles"), source=f"{source}.allowed_profiles"))
    invalid_profiles = sorted(profile for profile in profiles if profile not in ALLOWED_PROFILES)
    if invalid_profiles:
        raise CatalogValidationError(f"{source}.allowed_profiles contains unsupported profile(s): {', '.join(invalid_profiles)}")
    phase = CTFLabPhase(
        number=_int(payload.get("number"), source=f"{source}.number"),
        id=_text(payload.get("id"), source=f"{source}.id"),
        name=_text(payload.get("name"), source=f"{source}.name"),
        status=status,
        target_families=tuple(expect_string_list(payload.get("target_families"), source=f"{source}.target_families")),
        allowed_profiles=profiles,
        environment_proof_required=expect_bool(payload.get("environment_proof_required"), source=f"{source}.environment_proof_required"),
        deterministic_fixture_required=expect_bool(
            payload.get("deterministic_fixture_required"),
            source=f"{source}.deterministic_fixture_required",
        ),
        exit_gates=tuple(expect_string_list(payload.get("exit_gates"), source=f"{source}.exit_gates")),
        validation_commands=tuple(expect_string_list(payload.get("validation_commands"), source=f"{source}.validation_commands")),
        verified_environment_refs=tuple(
            expect_string_list(payload.get("verified_environment_refs"), source=f"{source}.verified_environment_refs")
        ),
        evidence_refs=tuple(expect_string_list(payload.get("evidence_refs"), source=f"{source}.evidence_refs")),
    )
    _validate_phase_requirements(phase, source=source)
    return phase


def _validate_expected_phase_set(phases: tuple[CTFLabPhase, ...], *, source: str) -> None:
    expected = EXPECTED_PHASES
    observed = tuple((item.number, item.id, item.name) for item in phases)
    if observed != expected:
        raise CatalogValidationError(f"{source}.phases must define the required lab phases in order")


def _validate_phase_requirements(phase: CTFLabPhase, *, source: str) -> None:
    if not phase.target_families:
        raise CatalogValidationError(f"{source}.target_families must not be empty")
    if not phase.allowed_profiles:
        raise CatalogValidationError(f"{source}.allowed_profiles must not be empty")
    if not phase.exit_gates:
        raise CatalogValidationError(f"{source}.exit_gates must not be empty")
    if phase.number > 0 and not phase.environment_proof_required:
        raise CatalogValidationError(f"{source}.environment_proof_required is mandatory after phase 0")
    if not phase.deterministic_fixture_required:
        raise CatalogValidationError(f"{source}.deterministic_fixture_required must be true")
    if phase.status == "complete":
        if not phase.validation_commands:
            raise CatalogValidationError(f"{source}.validation_commands are required for complete phases")
        if phase.environment_proof_required and not phase.verified_environment_refs:
            raise CatalogValidationError(f"{source}.verified_environment_refs are required for complete lab phases")
        if not phase.evidence_refs:
            raise CatalogValidationError(f"{source}.evidence_refs are required for complete phases")


def _text(value: Any, *, source: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise CatalogValidationError(f"{source} is required")
    return text


def _int(value: Any, *, source: str) -> int:
    if not isinstance(value, int):
        raise CatalogValidationError(f"{source} must be an integer")
    return value
