from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from primordial.labs.ctf.phases import CTFLabPhase
from primordial.labs.ctf.targets import CTFTarget, load_ctf_target_manifest_file


PHASE_TARGET_EXIT_GATES = ("phase_targets_loaded_from_manifests",)


@dataclass(frozen=True, slots=True)
class CTFPhaseTargetSet:
    phase_number: int
    phase_id: str
    target_ids: tuple[str, ...]
    targets: tuple[CTFTarget, ...]
    exit_gates: tuple[str, ...]

    def as_payload(self) -> dict[str, object]:
        return {
            "phase_number": self.phase_number,
            "phase_id": self.phase_id,
            "target_ids": list(self.target_ids),
            "targets": [target.id for target in self.targets],
            "exit_gates": list(self.exit_gates),
        }


def load_ctf_phase_target_manifests(phase: CTFLabPhase, manifest_paths: list[str | Path] | tuple[str | Path, ...]) -> CTFPhaseTargetSet:
    if not manifest_paths:
        raise ValueError("CTF phase target loading requires at least one manifest")
    targets = tuple(load_ctf_target_manifest_file(path) for path in manifest_paths)
    _validate_phase_targets(phase, targets)
    return CTFPhaseTargetSet(
        phase_number=phase.number,
        phase_id=phase.id,
        target_ids=tuple(target.id for target in targets),
        targets=targets,
        exit_gates=PHASE_TARGET_EXIT_GATES,
    )


def _validate_phase_targets(phase: CTFLabPhase, targets: tuple[CTFTarget, ...]) -> None:
    allowed_families = set(phase.target_families)
    seen_ids: set[str] = set()
    for target in targets:
        if target.id in seen_ids:
            raise ValueError(f"CTF phase target loading duplicate target id: {target.id}")
        seen_ids.add(target.id)
        if target.target_family not in allowed_families:
            raise ValueError(
                f"CTF phase target loading target_family {target.target_family!r} is not allowed for {phase.id}"
            )
