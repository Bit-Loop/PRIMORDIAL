from __future__ import annotations

from primordial.core.storage.runtime_common import *


class RuntimeRecordsMixin:
    def insert_evidence(self, evidence: EvidenceRecord) -> None:
        self._execute(
            """
            INSERT INTO evidence
            (id, target_id, task_id, type, title, summary, source_ref, verification_status,
                confidence, freshness, artifact_path, metadata, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET target_id = EXCLUDED.target_id, task_id = EXCLUDED.task_id, type = EXCLUDED.type, title = EXCLUDED.title, summary = EXCLUDED.summary, source_ref = EXCLUDED.source_ref, verification_status = EXCLUDED.verification_status, confidence = EXCLUDED.confidence, freshness = EXCLUDED.freshness, artifact_path = EXCLUDED.artifact_path, metadata = EXCLUDED.metadata, created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at
            """,
            (
                evidence.id,
                evidence.target_id,
                evidence.task_id,
                evidence.type.value,
                evidence.title,
                evidence.summary,
                evidence.source_ref,
                evidence.verification_status.value,
                evidence.confidence,
                evidence.freshness,
                evidence.artifact_path,
                _dump(evidence.metadata),
                evidence.created_at.isoformat(),
                evidence.updated_at.isoformat(),
            ),
        )

    def list_evidence(self, *, target_id: str | None = None, limit: int = 100) -> list[EvidenceRecord]:
        if target_id:
            rows = self._query(
                "SELECT * FROM evidence WHERE target_id = %s ORDER BY created_at DESC LIMIT %s",
                (target_id, limit),
            )
        else:
            rows = self._query("SELECT * FROM evidence ORDER BY created_at DESC LIMIT %s", (limit,))
        return [self._evidence_from_row(row) for row in rows]

    def get_evidence(self, evidence_id: str) -> EvidenceRecord | None:
        row = self._query_one("SELECT * FROM evidence WHERE id = %s", (evidence_id,))
        return self._evidence_from_row(row) if row else None

    def insert_note(self, note: Note) -> None:
        self._execute(
            """
            INSERT INTO notes
            (id, target_id, task_id, title, body, confidence, freshness, metadata, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET target_id = EXCLUDED.target_id, task_id = EXCLUDED.task_id, title = EXCLUDED.title, body = EXCLUDED.body, confidence = EXCLUDED.confidence, freshness = EXCLUDED.freshness, metadata = EXCLUDED.metadata, created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at
            """,
            (
                note.id,
                note.target_id,
                note.task_id,
                note.title,
                note.body,
                note.confidence,
                note.freshness,
                _dump(note.metadata),
                note.created_at.isoformat(),
                note.updated_at.isoformat(),
            ),
        )

    def list_notes(self, *, target_id: str | None = None, limit: int = 100) -> list[Note]:
        if target_id:
            rows = self._query(
                "SELECT * FROM notes WHERE target_id = %s ORDER BY created_at DESC LIMIT %s",
                (target_id, limit),
            )
        else:
            rows = self._query("SELECT * FROM notes ORDER BY created_at DESC LIMIT %s", (limit,))
        return [self._note_from_row(row) for row in rows]

    def get_note(self, note_id: str) -> Note | None:
        row = self._query_one("SELECT * FROM notes WHERE id = %s", (note_id,))
        return self._note_from_row(row) if row else None

    def insert_interest(self, interest: Interest) -> None:
        self._execute(
            """
            INSERT INTO interests
            (id, target_id, title, summary, evidence_refs, status, confidence, metadata, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET target_id = EXCLUDED.target_id, title = EXCLUDED.title, summary = EXCLUDED.summary, evidence_refs = EXCLUDED.evidence_refs, status = EXCLUDED.status, confidence = EXCLUDED.confidence, metadata = EXCLUDED.metadata, created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at
            """,
            (
                interest.id,
                interest.target_id,
                interest.title,
                interest.summary,
                _dump(interest.evidence_refs),
                interest.status.value,
                interest.confidence,
                _dump(interest.metadata),
                interest.created_at.isoformat(),
                interest.updated_at.isoformat(),
            ),
        )

    def list_interests(self, *, target_id: str | None = None, limit: int = 100) -> list[Interest]:
        if target_id:
            rows = self._query(
                "SELECT * FROM interests WHERE target_id = %s ORDER BY created_at DESC LIMIT %s",
                (target_id, limit),
            )
        else:
            rows = self._query("SELECT * FROM interests ORDER BY created_at DESC LIMIT %s", (limit,))
        return [self._interest_from_row(row) for row in rows]

    def get_interest(self, interest_id: str) -> Interest | None:
        row = self._query_one("SELECT * FROM interests WHERE id = %s", (interest_id,))
        return self._interest_from_row(row) if row else None

    def insert_finding(self, finding: Finding) -> None:
        self._execute(
            """
            INSERT INTO findings
            (id, target_id, title, summary, severity, evidence_refs, confidence, verification_status, metadata, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET target_id = EXCLUDED.target_id, title = EXCLUDED.title, summary = EXCLUDED.summary, severity = EXCLUDED.severity, evidence_refs = EXCLUDED.evidence_refs, confidence = EXCLUDED.confidence, verification_status = EXCLUDED.verification_status, metadata = EXCLUDED.metadata, created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at
            """,
            (
                finding.id,
                finding.target_id,
                finding.title,
                finding.summary,
                finding.severity.value,
                _dump(finding.evidence_refs),
                finding.confidence,
                finding.verification_status.value,
                _dump(finding.metadata),
                finding.created_at.isoformat(),
                finding.updated_at.isoformat(),
            ),
        )

    def list_findings(self, *, target_id: str | None = None, limit: int = 100) -> list[Finding]:
        if target_id:
            rows = self._query(
                "SELECT * FROM findings WHERE target_id = %s ORDER BY created_at DESC LIMIT %s",
                (target_id, limit),
            )
        else:
            rows = self._query("SELECT * FROM findings ORDER BY created_at DESC LIMIT %s", (limit,))
        return [self._finding_from_row(row) for row in rows]

    def get_finding(self, finding_id: str) -> Finding | None:
        row = self._query_one("SELECT * FROM findings WHERE id = %s", (finding_id,))
        return self._finding_from_row(row) if row else None

    def insert_memory_entry(self, entry: MemoryEntry) -> None:
        self._execute(
            """
            INSERT INTO memory_entries
            (id, target_id, layer, title, summary, evidence_refs, confidence, freshness, status, metadata, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET target_id = EXCLUDED.target_id, layer = EXCLUDED.layer, title = EXCLUDED.title, summary = EXCLUDED.summary, evidence_refs = EXCLUDED.evidence_refs, confidence = EXCLUDED.confidence, freshness = EXCLUDED.freshness, status = EXCLUDED.status, metadata = EXCLUDED.metadata, created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at
            """,
            (
                entry.id,
                entry.target_id,
                entry.layer.value,
                entry.title,
                entry.summary,
                _dump(entry.evidence_refs),
                entry.confidence,
                entry.freshness,
                entry.status.value,
                _dump(entry.metadata),
                entry.created_at.isoformat(),
                entry.updated_at.isoformat(),
            ),
        )

    def list_memory_entries(
        self,
        *,
        target_id: str | None = None,
        layer: MemoryLayer | None = None,
        limit: int = 100,
    ) -> list[MemoryEntry]:
        where: list[str] = []
        params: list[Any] = []
        if target_id:
            where.append("target_id = %s")
            params.append(target_id)
        if layer:
            where.append("layer = %s")
            params.append(layer.value)
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        rows = self._query(
            f"SELECT * FROM memory_entries {clause} ORDER BY created_at DESC LIMIT %s",
            (*params, limit),
        )
        return [self._memory_from_row(row) for row in rows]

    def get_memory_entry(self, memory_id: str) -> MemoryEntry | None:
        row = self._query_one("SELECT * FROM memory_entries WHERE id = %s", (memory_id,))
        return self._memory_from_row(row) if row else None

    def insert_policy_decision(self, decision: PolicyDecision) -> None:
        self._execute(
            """
            INSERT INTO policy_decisions
            (id, action_kind, verdict, reason, target_id, task_id, metadata, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET action_kind = EXCLUDED.action_kind, verdict = EXCLUDED.verdict, reason = EXCLUDED.reason, target_id = EXCLUDED.target_id, task_id = EXCLUDED.task_id, metadata = EXCLUDED.metadata, created_at = EXCLUDED.created_at
            """,
            (
                decision.id,
                decision.action_kind,
                decision.verdict.value,
                decision.reason,
                decision.target_id,
                decision.task_id,
                _dump(decision.metadata),
                decision.created_at.isoformat(),
            ),
        )
