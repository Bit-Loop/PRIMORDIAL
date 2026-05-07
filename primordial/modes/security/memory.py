from __future__ import annotations

from primordial.core.domain.enums import (
    AgentRole,
    EventType,
    InterestStatus,
    MemoryLayer,
    MemoryStatus,
    VerificationStatus,
)
from primordial.core.domain.models import ContextSlice, EventRecord, MemoryEntry
from primordial.core.storage.runtime import RuntimeStore


class MemoryService:
    def __init__(self, store: RuntimeStore) -> None:
        self.store = store

    def needs_compaction(self, target_id: str | None = None) -> bool:
        notes = self.store.list_notes(target_id=target_id, limit=500)
        evidence = self.store.list_evidence(target_id=target_id, limit=500)
        interests = self.store.list_interests(target_id=target_id, limit=500)
        return len(notes) >= 6 or len(evidence) >= 6 or len(interests) >= 4

    def build_context_slice(self, target_id: str, role: AgentRole, max_items: int = 6) -> ContextSlice:
        target = self.store.get_target(target_id)
        active_generation = (
            str(target.metadata.get("active_ip_generation", ""))
            if target and target.metadata.get("active_ip_generation") is not None
            else None
        )

        working = self.store.list_memory_entries(target_id=target_id, layer=MemoryLayer.WORKING, limit=max_items)
        episodic_raw = self.store.list_memory_entries(target_id=target_id, layer=MemoryLayer.EPISODIC, limit=max_items * 4)
        semantic = self.store.list_memory_entries(target_id=target_id, layer=MemoryLayer.SEMANTIC, limit=max_items)
        evidence_raw = self.store.list_evidence(target_id=target_id, limit=max_items * 4)
        interests_raw = self.store.list_interests(target_id=target_id, limit=max_items * 4)

        if active_generation is not None:
            # Prefer current-generation records; fall back to untagged (pre-generation) records.
            episodic = [
                e for e in episodic_raw
                if str(e.metadata.get("active_ip_generation", "")) in (active_generation, "")
            ][:max_items]
            recent_evidence = [
                e for e in evidence_raw
                if str(e.metadata.get("active_ip_generation", "")) in (active_generation, "")
            ][:max_items]
            recent_interests = [
                i for i in interests_raw
                if str(i.metadata.get("active_ip_generation", "")) in (active_generation, "")
            ][:max_items]
        else:
            episodic = episodic_raw[:max_items]
            recent_evidence = evidence_raw[:max_items]
            recent_interests = interests_raw[:max_items]

        summary = (
            f"role={role.value} gen={active_generation or 'untracked'} working={len(working)} "
            f"episodic={len(episodic)} semantic={len(semantic)} evidence={len(recent_evidence)} "
            f"interests={len(recent_interests)}"
        )
        return ContextSlice(
            target_id=target_id,
            role=role,
            working=working,
            episodic=episodic,
            semantic=semantic,
            recent_evidence=recent_evidence,
            recent_interests=recent_interests,
            summary=summary,
        )

    def compact_target(self, target_id: str) -> list[MemoryEntry]:
        created: list[MemoryEntry] = []
        target = self.store.get_target(target_id)
        active_generation = (
            str(target.metadata.get("active_ip_generation", ""))
            if target and target.metadata.get("active_ip_generation") is not None
            else None
        )
        evidence = self.store.list_evidence(target_id=target_id, limit=500)
        interests = self.store.list_interests(target_id=target_id, limit=500)

        for item in evidence:
            if item.verification_status not in {VerificationStatus.PARTIAL, VerificationStatus.VERIFIED}:
                continue
            title = f"Episodic: {item.title}"
            if self.store.memory_entry_exists(target_id=target_id, layer=MemoryLayer.EPISODIC, title=title):
                continue
            item_generation = str(item.metadata.get("active_ip_generation", "")) or active_generation
            meta: dict = {"source_type": item.type.value}
            if item_generation:
                meta["active_ip_generation"] = item_generation
            created.append(
                MemoryEntry(
                    target_id=target_id,
                    layer=MemoryLayer.EPISODIC,
                    title=title,
                    summary=item.summary,
                    evidence_refs=[item.id],
                    confidence=item.confidence,
                    freshness=item.freshness,
                    metadata=meta,
                )
            )

        for item in interests:
            if item.status != InterestStatus.VERIFIED or item.confidence < 0.7:
                continue
            title = f"Semantic: {item.title}"
            item_generation = str(item.metadata.get("active_ip_generation", "")) or active_generation
            meta = {"promoted_from": "interest"}
            if item_generation:
                meta["active_ip_generation"] = item_generation
            created.append(
                MemoryEntry(
                    target_id=target_id,
                    layer=MemoryLayer.SEMANTIC,
                    title=title,
                    summary=item.summary,
                    evidence_refs=item.evidence_refs,
                    confidence=item.confidence,
                    freshness=0.8,
                    metadata=meta,
                )
            )

        created = self._dedupe_promotions(created)
        for entry in created:
            self._supersede_conflicts(entry)
            self.store.insert_memory_entry(entry)

        if created:
            self.store.insert_event(
                EventRecord(
                    type=EventType.MEMORY_PROMOTION,
                    summary=f"promoted {len(created)} memory entries for target",
                    target_id=target_id,
                )
            )
        return created

    # Decay rate: freshness drops by this fraction per hour of idle time.
    # At 0.01/hr an entry at 1.0 reaches STALE (0.2) in 80 hours (~3.3 days).
    _FRESHNESS_DECAY_PER_HOUR: float = 0.01

    def apply_freshness_decay(self, target_id: str) -> int:
        from datetime import timezone as _tz
        now = __import__("datetime").datetime.now(tz=_tz.utc)
        updated = 0
        for entry in self.store.list_memory_entries(target_id=target_id, limit=500):
            if entry.status != MemoryStatus.ACTIVE:
                continue
            last_updated = entry.updated_at
            if last_updated.tzinfo is None:
                last_updated = last_updated.replace(tzinfo=_tz.utc)
            hours_elapsed = max(0.0, (now - last_updated).total_seconds() / 3600.0)
            decay = hours_elapsed * self._FRESHNESS_DECAY_PER_HOUR
            if decay < 0.001:
                continue
            new_freshness = round(max(0.05, entry.freshness - decay), 2)
            if new_freshness == entry.freshness:
                continue
            entry.freshness = new_freshness
            if new_freshness <= 0.2:
                entry.status = MemoryStatus.STALE
            self.store.insert_memory_entry(entry)
            updated += 1
        return updated

    def supersede_stale_generation_entries(self, target_id: str, current_generation: str) -> int:
        """Mark EPISODIC entries from prior IP generations as SUPERSEDED.

        Called after an active_ip change so stale recon facts stop contaminating
        current-generation reasoning.  SEMANTIC entries are left intact because
        they represent durable knowledge (vulnerability classes, techniques) that
        remains valid across IP rotations.
        """
        superseded = 0
        for entry in self.store.list_memory_entries(target_id=target_id, layer=MemoryLayer.EPISODIC, limit=500):
            if entry.status != MemoryStatus.ACTIVE:
                continue
            entry_gen = str(entry.metadata.get("active_ip_generation", ""))
            if entry_gen and entry_gen != current_generation:
                entry.status = MemoryStatus.SUPERSEDED
                entry.metadata["superseded_reason"] = f"ip_generation_changed_to_{current_generation}"
                self.store.insert_memory_entry(entry)
                superseded += 1
        return superseded

    def _dedupe_promotions(self, entries: list[MemoryEntry]) -> list[MemoryEntry]:
        deduped: dict[tuple[str, str], MemoryEntry] = {}
        for entry in entries:
            key = (entry.layer.value, entry.title)
            existing = deduped.get(key)
            if existing is None or entry.confidence > existing.confidence:
                deduped[key] = entry
        return list(deduped.values())

    def _supersede_conflicts(self, new_entry: MemoryEntry) -> None:
        existing_entries = self.store.list_memory_entries(
            target_id=new_entry.target_id,
            layer=new_entry.layer,
            limit=500,
        )
        for existing in existing_entries:
            if existing.title != new_entry.title or existing.id == new_entry.id:
                continue
            if existing.summary == new_entry.summary:
                continue
            existing.status = MemoryStatus.SUPERSEDED
            existing.metadata["superseded_by"] = new_entry.id
            self.store.insert_memory_entry(existing)
