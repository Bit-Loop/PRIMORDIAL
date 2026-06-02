from __future__ import annotations

from typing import Any, Callable

from primordial.core.domain.enums import EventType, ScopeProfile
from primordial.core.domain.models import EventRecord, Note, ScopeAsset, Target

DumpValue = Callable[[Any], Any]
StorageText = Callable[[Any], str]
TargetFromRow = Callable[[Any], Target]
BlockActiveTasks = Callable[..., int]


def replace_target_scope_assets_in_connection(
    connection: Any,
    *,
    handle: str,
    display_name: str,
    profile: ScopeProfile,
    in_scope: bool,
    active_ip: str | None,
    asset_rows: list[dict[str, Any]],
    now: Any,
    dump: DumpValue,
    storage_text: StorageText,
    target_from_row: TargetFromRow,
    block_active_tasks: BlockActiveTasks,
) -> dict[str, Any]:
    existing = _locked_target_by_handle(connection, target_from_row, handle=handle, profile=profile)
    metadata, previous_ip, ip_changed, generation = _scope_asset_target_metadata(
        existing,
        active_ip=active_ip,
        now=now,
    )
    target = _upsert_scope_asset_target(
        connection,
        existing=existing,
        handle=handle,
        display_name=display_name,
        profile=profile,
        in_scope=in_scope,
        metadata=metadata,
        now=now,
        dump=dump,
        target_from_row=target_from_row,
    )
    invalidated_task_count = _block_target_tasks_if_out_of_scope(connection, target, now, block_active_tasks)
    inserted_assets = _replace_scope_assets_for_target(connection, target.id, asset_rows, dump)
    if active_ip and ip_changed:
        _insert_active_ip_scope_note(
            connection,
            target=target,
            active_ip=active_ip,
            previous_ip=previous_ip,
            generation=generation,
            dump=dump,
            storage_text=storage_text,
        )
    _insert_scope_assets_replaced_event(
        connection,
        target=target,
        profile=profile,
        inserted_assets=inserted_assets,
        active_ip=active_ip,
        previous_ip=previous_ip,
        generation=generation,
        metadata=metadata,
        ip_changed=ip_changed,
        dump=dump,
        storage_text=storage_text,
    )
    return {
        "target": target,
        "asset_count": inserted_assets,
        "active_ip": active_ip,
        "previous_ip": previous_ip,
        "active_ip_generation": generation if active_ip else None,
        "ip_changed": ip_changed,
        "invalidated_task_count": invalidated_task_count,
    }


def _locked_target_by_handle(
    connection: Any,
    target_from_row: TargetFromRow,
    *,
    handle: str,
    profile: ScopeProfile,
) -> Target | None:
    row = connection.execute(
        """
        SELECT * FROM targets
        WHERE handle = %s AND profile = %s
        ORDER BY created_at DESC
        LIMIT 1
        FOR UPDATE
        """,
        (handle, profile.value),
    ).fetchone()
    return target_from_row(row) if row else None


def _scope_asset_target_metadata(
    existing: Target | None,
    *,
    active_ip: str | None,
    now: Any,
) -> tuple[dict[str, Any], str, bool, int]:
    metadata = dict(existing.metadata) if existing else {}
    previous_ip = str(metadata.get("active_ip") or "").strip()
    ip_changed = bool(active_ip) and previous_ip != str(active_ip)
    generation = int(metadata.get("active_ip_generation", 0) or 0)
    if active_ip:
        generation += 1 if ip_changed else 0
        metadata.update(
            {
                "active_ip": active_ip,
                "operator_confirmed_ip": active_ip,
                "operator_confirmed_ip_at": now.isoformat(),
                "active_ip_generation": generation,
                "stale_evidence_before": now.isoformat()
                if ip_changed
                else metadata.get("stale_evidence_before", now.isoformat()),
                "active_ip_source": "scope_editor",
            }
        )
    return metadata, previous_ip, ip_changed, generation


def _upsert_scope_asset_target(
    connection: Any,
    *,
    existing: Target | None,
    handle: str,
    display_name: str,
    profile: ScopeProfile,
    in_scope: bool,
    metadata: dict[str, Any],
    now: Any,
    dump: DumpValue,
    target_from_row: TargetFromRow,
) -> Target:
    if existing is None:
        return _insert_scope_asset_target(
            connection,
            handle=handle,
            display_name=display_name,
            profile=profile,
            in_scope=in_scope,
            metadata=metadata,
            now=now,
            dump=dump,
            target_from_row=target_from_row,
        )
    row = connection.execute(
        """
        UPDATE targets
        SET display_name = %s, in_scope = %s, metadata = %s, updated_at = %s
        WHERE id = %s
        RETURNING *
        """,
        (display_name, in_scope, dump(metadata), now.isoformat(), existing.id),
    ).fetchone()
    return target_from_row(row)


def _insert_scope_asset_target(
    connection: Any,
    *,
    handle: str,
    display_name: str,
    profile: ScopeProfile,
    in_scope: bool,
    metadata: dict[str, Any],
    now: Any,
    dump: DumpValue,
    target_from_row: TargetFromRow,
) -> Target:
    target = Target(handle=handle, display_name=display_name, profile=profile, in_scope=in_scope, metadata=metadata)
    target.created_at = now
    target.updated_at = now
    row = connection.execute(
        """
        INSERT INTO targets
        (id, handle, display_name, profile, in_scope, metadata, created_at, updated_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING *
        """,
        (
            target.id,
            target.handle,
            target.display_name,
            target.profile.value,
            target.in_scope,
            dump(target.metadata),
            target.created_at.isoformat(),
            target.updated_at.isoformat(),
        ),
    ).fetchone()
    return target_from_row(row)


def _block_target_tasks_if_out_of_scope(
    connection: Any,
    target: Target,
    now: Any,
    block_active_tasks: BlockActiveTasks,
) -> int:
    if target.in_scope:
        return 0
    return block_active_tasks(
        connection,
        target_id=target.id,
        reason="target was marked out of scope",
        source="scope_editor",
        now=now,
    )


def _replace_scope_assets_for_target(
    connection: Any,
    target_id: str,
    asset_rows: list[dict[str, Any]],
    dump: DumpValue,
) -> int:
    connection.execute("DELETE FROM scope_assets WHERE target_id = %s", (target_id,))
    inserted_assets = 0
    for row in asset_rows:
        raw_asset = str(row["asset"]).strip()
        if not raw_asset:
            continue
        metadata = row.get("metadata", {})
        asset = ScopeAsset(
            target_id=target_id,
            asset=raw_asset,
            asset_type=str(row.get("asset_type") or "domain"),
            metadata=dict(metadata) if isinstance(metadata, dict) else {},
        )
        _insert_scope_asset(connection, asset, dump)
        inserted_assets += 1
    return inserted_assets


def _insert_scope_asset(connection: Any, asset: ScopeAsset, dump: DumpValue) -> None:
    connection.execute(
        """
        INSERT INTO scope_assets
        (id, target_id, asset, asset_type, metadata, created_at)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (
            asset.id,
            asset.target_id,
            asset.asset,
            asset.asset_type,
            dump(asset.metadata),
            asset.created_at.isoformat(),
        ),
    )


def _insert_active_ip_scope_note(
    connection: Any,
    *,
    target: Target,
    active_ip: str,
    previous_ip: str,
    generation: int,
    dump: DumpValue,
    storage_text: StorageText,
) -> None:
    note = Note(
        target_id=target.id,
        title="Operator-confirmed active target IP",
        body=(
            f"Active IP for `{target.handle}` is `{active_ip}`. "
            "Prior recon evidence may still reference older IPs and should be treated as historical "
            "until refreshed recon tasks complete."
        ),
        confidence=1.0,
        freshness=1.0,
        metadata={
            "class": "operator_correction",
            "active_ip": active_ip,
            "previous_ip": previous_ip,
            "active_ip_generation": generation,
            "source": "scope_editor",
        },
    )
    connection.execute(
        """
        INSERT INTO notes
        (id, target_id, task_id, title, body, confidence, freshness, metadata, created_at, updated_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            note.id,
            note.target_id,
            note.task_id,
            storage_text(note.title),
            storage_text(note.body),
            note.confidence,
            note.freshness,
            dump(note.metadata),
            note.created_at.isoformat(),
            note.updated_at.isoformat(),
        ),
    )


def _insert_scope_assets_replaced_event(
    connection: Any,
    *,
    target: Target,
    profile: ScopeProfile,
    inserted_assets: int,
    active_ip: str | None,
    previous_ip: str,
    generation: int,
    metadata: dict[str, Any],
    ip_changed: bool,
    dump: DumpValue,
    storage_text: StorageText,
) -> None:
    summary = (
        f"Active IP set for {target.handle}: {active_ip}"
        if active_ip and ip_changed
        else f"Scope assets replaced for {target.handle}: {inserted_assets} asset(s)"
    )
    event = EventRecord(
        type=EventType.SCOPE_UPDATED,
        summary=summary,
        target_id=target.id,
        metadata={
            "asset_count": inserted_assets,
            "profile": profile.value,
            "active_ip": active_ip,
            "previous_ip": previous_ip,
            "active_ip_generation": generation if active_ip else metadata.get("active_ip_generation"),
            "source": "scope_editor",
        },
    )
    connection.execute(
        """
        INSERT INTO events
        (id, event_type, target_id, task_id, summary, metadata, created_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """,
        (
            event.id,
            event.type.value,
            event.target_id,
            event.task_id,
            storage_text(event.summary),
            dump(event.metadata),
            event.created_at.isoformat(),
        ),
    )
