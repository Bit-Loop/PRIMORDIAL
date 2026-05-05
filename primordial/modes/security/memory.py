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
        working = self.store.list_memory_entries(target_id=target_id, layer=MemoryLayer.WORKING, limit=max_items)
        episodic = self.store.list_memory_entries(target_id=target_id, layer=MemoryLayer.EPISODIC, limit=max_items)
        semantic = self.store.list_memory_entries(target_id=target_id, layer=MemoryLayer.SEMANTIC, limit=max_items)
        recent_evidence = self.store.list_evidence(target_id=target_id, limit=max_items)
        recent_interests = self.store.list_interests(target_id=target_id, limit=max_items)
        summary = (
            f"role={role.value} working={len(working)} episodic={len(episodic)} "
            f"semantic={len(semantic)} evidence={len(recent_evidence)} interests={len(recent_interests)}"
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
        evidence = self.store.list_evidence(target_id=target_id, limit=500)
        interests = self.store.list_interests(target_id=target_id, limit=500)

        for item in evidence:
            if item.verification_status not in {VerificationStatus.PARTIAL, VerificationStatus.VERIFIED}:
                continue
            title = f"Episodic: {item.title}"
            if self.store.memory_entry_exists(target_id=target_id, layer=MemoryLayer.EPISODIC, title=title):
                continue
            created.append(
                MemoryEntry(
                    target_id=target_id,
                    layer=MemoryLayer.EPISODIC,
                    title=title,
                    summary=item.summary,
                    evidence_refs=[item.id],
                    confidence=item.confidence,
                    freshness=item.freshness,
                    metadata={"source_type": item.type.value},
                )
            )

        for item in interests:
            if item.status != InterestStatus.VERIFIED or item.confidence < 0.7:
                continue
            title = f"Semantic: {item.title}"
            created.append(
                MemoryEntry(
                    target_id=target_id,
                    layer=MemoryLayer.SEMANTIC,
                    title=title,
                    summary=item.summary,
                    evidence_refs=item.evidence_refs,
                    confidence=item.confidence,
                    freshness=0.8,
                    metadata={"promoted_from": "interest"},
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

    def apply_freshness_decay(self, target_id: str) -> int:
        updated = 0
        for entry in self.store.list_memory_entries(target_id=target_id, limit=500):
            if entry.status != MemoryStatus.ACTIVE:
                continue
            new_freshness = round(max(0.05, entry.freshness - 0.03), 2)
            if new_freshness == entry.freshness:
                continue
            entry.freshness = new_freshness
            if new_freshness <= 0.2:
                entry.status = MemoryStatus.STALE
            self.store.insert_memory_entry(entry)
            updated += 1
        return updated

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
