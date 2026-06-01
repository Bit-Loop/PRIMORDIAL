from __future__ import annotations

from dataclasses import dataclass

from primordial.core.domain.enums import EventType
from primordial.core.domain.models import EventRecord, Note, Target, utc_now


@dataclass(frozen=True, slots=True)
class ActiveIpUpdate:
    metadata: dict[str, object]
    previous_ip: str
    ip_changed: bool
    generation: int


def build_active_ip_update(target: Target, parsed_ip: str, source: str) -> ActiveIpUpdate:
    previous_ip = str(target.metadata.get("active_ip") or "").strip()
    ip_changed = previous_ip != parsed_ip
    generation = int(target.metadata.get("active_ip_generation", 0) or 0) + (1 if ip_changed else 0)
    metadata = dict(target.metadata)
    metadata.update(
        {
            "active_ip": parsed_ip,
            "operator_confirmed_ip": parsed_ip,
            "operator_confirmed_ip_at": utc_now().isoformat(),
            "active_ip_generation": generation,
            "stale_evidence_before": utc_now().isoformat()
            if ip_changed
            else metadata.get("stale_evidence_before", utc_now().isoformat()),
            "active_ip_source": source,
        }
    )
    return ActiveIpUpdate(
        metadata=metadata,
        previous_ip=previous_ip,
        ip_changed=ip_changed,
        generation=generation,
    )


def active_ip_asset(parsed_ip: str, generation: int, source: str) -> dict[str, object]:
    return {
        "asset": parsed_ip,
        "asset_type": "ip",
        "metadata": {
            "active": True,
            "operator_confirmed": True,
            "active_ip_generation": generation,
            "source": source,
        },
    }


def active_ip_note(
    target: Target,
    parsed_ip: str,
    previous_ip: str,
    generation: int,
    source: str,
) -> Note:
    return Note(
        target_id=target.id,
        title="Operator-confirmed active target IP",
        body=(
            f"Active IP for `{target.handle}` is `{parsed_ip}`. "
            "Prior recon evidence may still reference older IPs and should be treated as historical "
            "until refreshed recon tasks complete."
        ),
        confidence=1.0,
        freshness=1.0,
        metadata={
            "class": "operator_correction",
            "active_ip": parsed_ip,
            "previous_ip": previous_ip,
            "active_ip_generation": generation,
            "source": source,
        },
    )


def active_ip_event(
    target: Target,
    parsed_ip: str,
    previous_ip: str,
    generation: int,
    source: str,
    *,
    ip_changed: bool,
) -> EventRecord:
    return EventRecord(
        type=EventType.SCOPE_UPDATED,
        summary=(
            f"Active IP set for {target.handle}: {parsed_ip}"
            if ip_changed
            else f"Active IP confirmed for {target.handle}: {parsed_ip}"
        ),
        target_id=target.id,
        metadata={
            "active_ip": parsed_ip,
            "previous_ip": previous_ip,
            "active_ip_generation": generation,
            "source": source,
        },
    )
