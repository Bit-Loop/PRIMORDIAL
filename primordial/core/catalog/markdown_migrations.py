from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from primordial.core.catalog.loader import CatalogValidationError, expect_string_list, load_yaml_file, validate_allowed_fields


@dataclass(frozen=True, slots=True)
class MarkdownMigration:
    source_path: str
    status: str
    replacement_refs: tuple[str, ...]
    verification_refs: tuple[str, ...]


class MarkdownMigrationCatalog:
    FIELDS = {"migrations"}
    MIGRATION_FIELDS = {"source_path", "status", "replacement_refs", "verification_refs"}
    ALLOWED_STATUSES = frozenset({"archived_historical", "migrated", "blocked"})

    def __init__(self, path: Path) -> None:
        self.path = path
        self._migrations: dict[str, MarkdownMigration] = {}

    def load(self) -> list[MarkdownMigration]:
        payload = load_yaml_file(self.path)
        validate_allowed_fields(payload, self.FIELDS, source=str(self.path))
        raw = payload.get("migrations", [])
        if not isinstance(raw, list):
            raise CatalogValidationError(f"{self.path}.migrations must be a list")
        migrations = []
        for index, item in enumerate(raw):
            migration = self._migration(item, source=f"{self.path}.migrations[{index}]")
            self._migrations[migration.source_path] = migration
            migrations.append(migration)
        return migrations

    def get(self, source_path: str) -> MarkdownMigration | None:
        return self._migrations.get(source_path)

    def _migration(self, payload: Any, *, source: str) -> MarkdownMigration:
        if not isinstance(payload, dict):
            raise CatalogValidationError(f"{source} must be an object")
        validate_allowed_fields(payload, self.MIGRATION_FIELDS, source=source)
        status = str(payload.get("status", "")).strip()
        if status not in self.ALLOWED_STATUSES:
            raise CatalogValidationError(f"{source}.status must be one of: {', '.join(sorted(self.ALLOWED_STATUSES))}")
        source_path = str(payload.get("source_path", "")).strip()
        if not source_path.endswith(".md"):
            raise CatalogValidationError(f"{source}.source_path must reference a Markdown file")
        return MarkdownMigration(
            source_path=source_path,
            status=status,
            replacement_refs=tuple(expect_string_list(payload.get("replacement_refs"), source=f"{source}.replacement_refs")),
            verification_refs=tuple(expect_string_list(payload.get("verification_refs"), source=f"{source}.verification_refs")),
        )
