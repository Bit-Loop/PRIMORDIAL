from __future__ import annotations

from pathlib import Path

from .io import write_json
from .models import VulnSourceCursor, utc_now_iso


class CursorStore:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self._cursors = self._load()

    def get(self, source_name: str, default_type: str = "opaque") -> VulnSourceCursor:
        raw = self._cursors.get(source_name)
        if isinstance(raw, dict):
            return VulnSourceCursor.model_validate(raw)
        return VulnSourceCursor(source_name=source_name, cursor_type=default_type)

    def mark_attempt(self, cursor: VulnSourceCursor) -> VulnSourceCursor:
        cursor.last_attempt_at = utc_now_iso()
        cursor.status = "attempted"
        self.set(cursor)
        return cursor

    def mark_success(self, cursor: VulnSourceCursor, value: str | None = None) -> VulnSourceCursor:
        cursor.last_success_at = utc_now_iso()
        cursor.last_attempt_at = cursor.last_attempt_at or cursor.last_success_at
        if value is not None:
            cursor.cursor_value = value
        cursor.status = "ok"
        cursor.failure_count = 0
        self.set(cursor)
        return cursor

    def mark_failure(self, cursor: VulnSourceCursor, error: str) -> VulnSourceCursor:
        cursor.last_attempt_at = utc_now_iso()
        cursor.status = "failed"
        cursor.failure_count += 1
        cursor.metadata = {**cursor.metadata, "last_error": error}
        self.set(cursor)
        return cursor

    def set(self, cursor: VulnSourceCursor) -> None:
        self._cursors[cursor.source_name] = cursor.model_dump(mode="json")
        self.save()

    def save(self) -> None:
        write_json(self.path, self._cursors)

    def _load(self) -> dict[str, dict[str, object]]:
        if not self.path.exists():
            return {}
        import json

        payload = json.loads(self.path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
