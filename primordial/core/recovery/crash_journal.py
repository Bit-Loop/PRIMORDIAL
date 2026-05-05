from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from time import sleep


@dataclass(slots=True, frozen=True)
class CrashRecoveryState:
    previous_unclean_shutdown: bool
    backoff_applied_seconds: float


class CrashJournal:
    def __init__(self, path: Path, backoff_seconds: float = 1.0) -> None:
        self.path = path
        self.backoff_seconds = max(0.0, backoff_seconds)
        self._started = False

    def startup(self) -> CrashRecoveryState:
        previous_unclean_shutdown = self.path.exists()
        applied = self.backoff_seconds if previous_unclean_shutdown else 0.0
        if applied:
            sleep(applied)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch()
        self._started = True
        return CrashRecoveryState(
            previous_unclean_shutdown=previous_unclean_shutdown,
            backoff_applied_seconds=applied,
        )

    def shutdown(self) -> None:
        if self.path.exists():
            self.path.unlink()
        self._started = False
