from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from .hashing import payload_hash, stable_id
from .io import append_jsonl, read_jsonl
from .models import VulnEvent


def build_event(
    *,
    source_name: str,
    event_type: str,
    source_record_id: str,
    payload: dict[str, Any],
    vuln_ids: Iterable[str] = (),
    aliases: Iterable[str] = (),
    raw_ref: str = "",
    occurred_at: str | None = None,
) -> VulnEvent:
    digest = payload_hash(payload)
    event_id = stable_id("vuln_event", source_name, event_type, source_record_id, digest, length=28)
    return VulnEvent(
        event_id=event_id,
        source_name=source_name,
        event_type=event_type,
        source_record_id=source_record_id,
        vuln_ids=sorted({str(item) for item in vuln_ids if str(item).strip()}),
        aliases=sorted({str(item) for item in aliases if str(item).strip()}),
        occurred_at=occurred_at,
        raw_ref=raw_ref,
        payload_hash=digest,
        payload=payload,
    )


class EventStore:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self._seen = {str(row.get("event_id")) for row in read_jsonl(self.path)}

    def append_new(self, events: Iterable[VulnEvent]) -> int:
        new: list[VulnEvent] = []
        for event in events:
            if event.event_id in self._seen:
                continue
            self._seen.add(event.event_id)
            new.append(event)
        return append_jsonl(self.path, new)
