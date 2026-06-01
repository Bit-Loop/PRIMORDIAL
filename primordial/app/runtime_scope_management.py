from __future__ import annotations

from primordial.app.runtime_deps import (
    active_ip_asset,
    active_ip_event,
    active_ip_note,
    build_active_ip_update,
    EventRecord,
    EventType,
    normalize_scope_assets,
    Path,
    ScopeAsset,
    ScopeProfile,
    Target,
    utc_now,
)

class RuntimeScopeManagementMixin:
    def import_scope(self, path: Path, profile: ScopeProfile | str | None = None) -> dict[str, object]:
        payload = self._load_scope_payload(path)
        return self.import_scope_payload(payload, profile=profile, source_name=path.name)

    def import_scope_payload(
        self,
        payload: dict[str, object],
        profile: ScopeProfile | str | None = None,
        source_name: str = "operator payload",
    ) -> dict[str, object]:
        if not isinstance(payload, dict):
            raise ValueError("scope payload must be an object")
        raw_profile = str(profile or payload.get("profile", ScopeProfile.HACKERONE.value))
        try:
            payload_profile = self.resolve_scope_profile(raw_profile)
        except ValueError:
            if not self.environment_classifier.has_profile_upgrade(raw_profile):
                raise
            payload_profile = ScopeProfile.HACKERONE
        environment_classification = self._classify_environment(
            profile=raw_profile,
            resolved_profile=payload_profile.value,
            payload=payload,
        )
        targets = payload.get("targets", [])
        if not isinstance(targets, list):
            raise ValueError("scope payload targets must be a list")
        session = self.store.get_active_session() or self.start_session(
            profile=payload_profile,
            environment_classification=environment_classification,
        )
        self._ensure_profile_default_operator_intent(payload_profile, classification=environment_classification)
        session = self.store.get_active_session() or session
        imported_targets = 0
        imported_assets = 0
        for target_payload in targets:
            if not isinstance(target_payload, dict):
                raise ValueError("each scope target must be an object")
            handle = str(target_payload.get("handle", "")).strip()
            if not handle:
                raise ValueError("each scope target requires a handle")
            normalized_assets = normalize_scope_assets(
                target_payload.get("assets", [handle]),
                handle,
                self._infer_asset_type,
            )
            self.register_target(
                handle=handle,
                display_name=str(target_payload.get("display_name", handle)),
                profile=payload_profile,
                assets=normalized_assets,
                in_scope=bool(target_payload.get("in_scope", True)),
                metadata=dict(target_payload.get("metadata", {})),
                emit_event=False,
            )
            imported_targets += 1
            imported_assets += len(normalized_assets)
        self.store.insert_event(
            EventRecord(
                type=EventType.SCOPE_IMPORTED,
                summary=f"Imported scope from {source_name}",
                metadata={
                    "profile": payload_profile.value,
                    "session_id": session.id,
                    "targets_imported": imported_targets,
                    "assets_imported": imported_assets,
                    "environment_classification": environment_classification.as_payload(),
                },
            )
        )
        return {
            "source": source_name,
            "profile": payload_profile.value,
            "session_id": session.id,
            "targets_imported": imported_targets,
            "assets_imported": imported_assets,
            "environment_classification": environment_classification.as_payload(),
        }

    def register_target(
        self,
        *,
        handle: str,
        profile: ScopeProfile,
        display_name: str | None = None,
        assets: list[str | dict[str, object]] | None = None,
        in_scope: bool = True,
        metadata: dict[str, object] | None = None,
        emit_event: bool = True,
    ) -> Target:
        handle = str(handle).strip()
        if not handle:
            raise ValueError("target handle is required")
        display_name = str(display_name or handle).strip() or handle
        existing = self.store.get_target_by_handle(handle, profile)
        if existing is not None:
            target = existing
            target.display_name = display_name or target.display_name
            target.in_scope = in_scope
            merged_metadata = dict(target.metadata)
            if metadata:
                merged_metadata.update(metadata)
            target.metadata = merged_metadata
            target.updated_at = utc_now()
        else:
            target = Target(
                handle=handle,
                display_name=display_name,
                profile=profile,
                in_scope=in_scope,
                metadata=dict(metadata or {}),
            )
        environment_classification = self._classify_environment(
            profile=profile.value,
            target_metadata=metadata or {},
            asset_metadata=self._asset_metadata_from_entries(assets or []),
        )
        self._ensure_profile_default_operator_intent(profile, classification=environment_classification)
        self.store.insert_target(target)
        self.findings_context.ensure_target(target)

        normalized_assets = assets or [handle]
        for asset_entry in normalized_assets:
            if isinstance(asset_entry, dict):
                raw_asset = str(asset_entry["asset"]).strip()
                if not raw_asset:
                    continue
                asset_type = str(asset_entry.get("asset_type", self._infer_asset_type(raw_asset)))
                asset_metadata = dict(asset_entry.get("metadata", {}))
            else:
                raw_asset = str(asset_entry).strip()
                if not raw_asset:
                    continue
                asset_type = self._infer_asset_type(raw_asset)
                asset_metadata = {}
            if self.store.get_scope_asset(target.id, raw_asset) is not None:
                continue
            self.store.insert_scope_asset(
                ScopeAsset(
                    target_id=target.id,
                    asset=raw_asset,
                    asset_type=asset_type,
                    metadata=asset_metadata,
                )
            )

        if emit_event:
            self.store.insert_event(
                EventRecord(
                    type=EventType.SCOPE_UPDATED,
                    summary=f"Registered or updated target: {target.handle}",
                    target_id=target.id,
                    metadata={"profile": profile.value},
                )
            )
        return target

    def update_target_fields(
        self,
        *,
        handle: str,
        profile: ScopeProfile,
        display_name: str | None = None,
        assets: list[str | dict[str, object]] | None = None,
        active_ip: str | None = None,
        in_scope: bool = True,
        metadata: dict[str, object] | None = None,
    ) -> Target:
        handle = str(handle).strip()
        if not handle:
            raise ValueError("target handle is required")
        normalized_assets = list(assets or [handle])
        parsed_active_ip = self._validated_optional_ip(active_ip)
        if parsed_active_ip and not any(
            (item.get("asset") if isinstance(item, dict) else item) == parsed_active_ip
            for item in normalized_assets
        ):
            normalized_assets.append(
                {
                    "asset": parsed_active_ip,
                    "asset_type": "ip",
                    "metadata": {"active": True, "operator_confirmed": True},
                }
            )
        target = self.register_target(
            handle=handle,
            profile=profile,
            display_name=display_name,
            assets=normalized_assets,
            in_scope=in_scope,
            metadata=metadata,
        )
        if parsed_active_ip:
            target = self.set_target_active_ip(target, parsed_active_ip, source="target_update")
        return target

    def set_target_active_ip(self, target: Target | str, ip: str, *, source: str = "operator") -> Target:
        target_record = target if isinstance(target, Target) else self._resolve_target_reference(target)
        if target_record is None:
            raise ValueError("target not found")
        parsed_ip = self._validated_optional_ip(ip)
        if not parsed_ip:
            raise ValueError("active_ip must be a valid IPv4 or IPv6 address")
        active_ip_update = build_active_ip_update(target_record, parsed_ip, source)
        updated = self.register_target(
            handle=target_record.handle,
            profile=target_record.profile,
            display_name=target_record.display_name,
            assets=[active_ip_asset(parsed_ip, active_ip_update.generation, source)],
            in_scope=target_record.in_scope,
            metadata=active_ip_update.metadata,
            emit_event=False,
        )
        if active_ip_update.ip_changed:
            self.store.insert_note(active_ip_note(updated, parsed_ip, active_ip_update.previous_ip, active_ip_update.generation, source))
            # Supersede EPISODIC memory entries from the previous generation so stale
            # IP-specific facts don't contaminate current-generation reasoning.
            self.memory.supersede_stale_generation_entries(updated.id, str(active_ip_update.generation))
        self.store.insert_event(
            active_ip_event(
                updated,
                parsed_ip,
                active_ip_update.previous_ip,
                active_ip_update.generation,
                source,
                ip_changed=active_ip_update.ip_changed,
            )
        )
        return updated
