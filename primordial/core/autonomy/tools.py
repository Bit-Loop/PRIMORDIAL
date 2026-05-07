from __future__ import annotations

from dataclasses import dataclass, field
import importlib.metadata
from pathlib import Path
import shutil

from primordial.core.intent.models import OperatorIntentPolicy


@dataclass(slots=True, frozen=True)
class ToolingGap:
    capability: str
    missing_tool: str
    reason: str


@dataclass(slots=True, frozen=True)
class ToolSubstitution:
    capability: str
    preferred_tool: str
    substitute_tool: str
    rationale: str


@dataclass(slots=True, frozen=True)
class GiveUpWithReason:
    reason: str


@dataclass(slots=True)
class ToolInventory:
    approved_executables: list[str] = field(default_factory=list)
    approved_packages: list[str] = field(default_factory=list)
    trusted_scripts: list[Path] = field(default_factory=list)

    def executable_available(self, name: str) -> bool:
        return name in self.approved_executables and shutil.which(name) is not None

    def package_available(self, name: str) -> bool:
        if name not in self.approved_packages:
            return False
        try:
            importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            return False
        return True

    def trusted_script_available(self, path: Path) -> bool:
        return path in self.trusted_scripts and path.exists()


class ToolingGapResolver:
    def __init__(self, inventory: ToolInventory) -> None:
        self.inventory = inventory

    def resolve(self, gap: ToolingGap, policy: OperatorIntentPolicy) -> ToolSubstitution | GiveUpWithReason:
        if gap.missing_tool == "netexec" and gap.capability == "smb_share_enumeration":
            if self.inventory.executable_available("smbclient"):
                return ToolSubstitution(
                    capability=gap.capability,
                    preferred_tool="netexec",
                    substitute_tool="smbclient",
                    rationale="smbclient can perform read-only SMB share enumeration without generated helpers.",
                )
        return GiveUpWithReason(f"no approved installed substitute for {gap.missing_tool} ({gap.capability})")
