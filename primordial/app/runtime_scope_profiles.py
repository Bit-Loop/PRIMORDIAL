from __future__ import annotations

from primordial.app.runtime_deps import (
    EventRecord,
    EventType,
    ipaddress,
    ScopeProfile,
    Target,
)

class RuntimeScopeProfilesMixin:
    def scope_payload(self) -> dict[str, object]:
        targets = self.store.list_targets()
        all_tasks = self.store.list_tasks(limit=500)
        all_evidence = self.store.list_evidence(limit=500)
        all_notes = self.store.list_notes(limit=500)
        all_interests = self.store.list_interests(limit=500)
        all_findings = self.store.list_findings(limit=500)
        scope_targets: list[dict[str, object]] = []
        for target in targets:
            assets = self.store.list_scope_assets(target.id)
            scope_targets.append(
                {
                    "target": target.as_payload(),
                    "assets": [asset.as_payload() for asset in assets],
                    "counts": {
                        "assets": len(assets),
                        "tasks": sum(1 for item in all_tasks if item.target_id == target.id),
                        "evidence": sum(1 for item in all_evidence if item.target_id == target.id),
                        "notes": sum(1 for item in all_notes if item.target_id == target.id),
                        "interests": sum(1 for item in all_interests if item.target_id == target.id),
                        "findings": sum(1 for item in all_findings if item.target_id == target.id),
                    },
                }
            )
        return {
            "targets": scope_targets,
            "totals": {
                "targets": len(targets),
                "in_scope": sum(1 for target in targets if target.in_scope),
                "assets": sum(len(item["assets"]) for item in scope_targets),
            },
        }

    def scope_profiles_payload(self) -> dict[str, object]:
        htb_environment = self._classify_environment(profile=ScopeProfile.HACK_THE_BOX.value)
        hackerone_environment = self._classify_environment(profile=ScopeProfile.HACKERONE.value)
        builtins = [
            {
                "id": ScopeProfile.HACK_THE_BOX.value,
                "label": "Hack The Box",
                "base_profile": ScopeProfile.HACK_THE_BOX.value,
                "description": "Lab/CTF profile. Requires verified environment proof before stronger lab defaults apply.",
                "default_intent": htb_environment.default_intent,
                "environment_classification": htb_environment.as_payload(),
                "builtin": True,
            },
            {
                "id": ScopeProfile.HACKERONE.value,
                "label": "HackerOne",
                "base_profile": ScopeProfile.HACKERONE.value,
                "description": "Bug bounty profile. Requires stricter scope and program-rule awareness.",
                "default_intent": hackerone_environment.default_intent,
                "environment_classification": hackerone_environment.as_payload(),
                "builtin": True,
            },
        ]
        custom = self.store.get_setting(self.SCOPE_PROFILE_PRESETS_SETTING, {})
        if not isinstance(custom, dict):
            custom = {}
        custom_profiles = []
        for profile_id, payload in sorted(custom.items()):
            if not isinstance(payload, dict):
                continue
            custom_profiles.append(
                {
                    "id": str(profile_id),
                    "label": str(payload.get("label", profile_id)),
                    "base_profile": str(payload.get("base_profile", ScopeProfile.HACKERONE.value)),
                    "description": str(payload.get("description", "")),
                    "builtin": False,
                }
            )
        return {"profiles": builtins + custom_profiles}

    def upsert_scope_profile(
        self,
        *,
        profile_id: str,
        label: str,
        base_profile: str,
        description: str = "",
    ) -> dict[str, object]:
        normalized_id = self._normalize_scope_profile_id(profile_id or label)
        if normalized_id in {ScopeProfile.HACK_THE_BOX.value, ScopeProfile.HACKERONE.value}:
            raise ValueError("built-in scope profiles cannot be overwritten")
        parsed_base = ScopeProfile(str(base_profile).strip())
        custom = self.store.get_setting(self.SCOPE_PROFILE_PRESETS_SETTING, {})
        if not isinstance(custom, dict):
            custom = {}
        custom[normalized_id] = {
            "label": label.strip() or normalized_id,
            "base_profile": parsed_base.value,
            "description": description.strip(),
        }
        self.store.set_setting(self.SCOPE_PROFILE_PRESETS_SETTING, custom)
        self.store.insert_event(
            EventRecord(
                type=EventType.SCOPE_UPDATED,
                summary=f"Scope profile preset saved: {normalized_id}",
                metadata={"profile_id": normalized_id, "base_profile": parsed_base.value},
            )
        )
        payload = self.scope_profiles_payload()
        payload["saved"] = normalized_id
        return payload

    def delete_scope_profile(self, profile_id: str) -> dict[str, object]:
        normalized_id = self._normalize_scope_profile_id(profile_id)
        if normalized_id in {ScopeProfile.HACK_THE_BOX.value, ScopeProfile.HACKERONE.value}:
            raise ValueError("built-in scope profiles cannot be deleted")
        custom = self.store.get_setting(self.SCOPE_PROFILE_PRESETS_SETTING, {})
        if not isinstance(custom, dict):
            custom = {}
        removed = normalized_id in custom
        custom.pop(normalized_id, None)
        self.store.set_setting(self.SCOPE_PROFILE_PRESETS_SETTING, custom)
        self.store.insert_event(
            EventRecord(
                type=EventType.SCOPE_UPDATED,
                summary=f"Scope profile preset deleted: {normalized_id}",
                metadata={"profile_id": normalized_id, "removed": removed},
            )
        )
        payload = self.scope_profiles_payload()
        payload["deleted"] = normalized_id
        payload["removed"] = removed
        return payload

    def resolve_scope_profile(self, profile_id: str) -> ScopeProfile:
        raw = str(profile_id).strip()
        try:
            return ScopeProfile(raw)
        except ValueError:
            pass
        custom = self.store.get_setting(self.SCOPE_PROFILE_PRESETS_SETTING, {})
        if isinstance(custom, dict):
            payload = custom.get(self._normalize_scope_profile_id(raw))
            if isinstance(payload, dict):
                return ScopeProfile(str(payload.get("base_profile", ScopeProfile.HACKERONE.value)))
        raise ValueError(f"unknown scope profile: {profile_id}")

    def _resolve_target_reference(self, target: str | None) -> Target | None:
        if not target:
            targets = self.store.list_targets()
            return targets[0] if len(targets) == 1 else None
        direct = self.store.get_target(target)
        if direct is not None:
            return direct
        return self.store.get_target_by_handle(target)

    def _infer_asset_type(self, asset: str) -> str:
        if asset.startswith("http://") or asset.startswith("https://"):
            return "webapp"
        try:
            ipaddress.ip_address(asset)
            return "ip"
        except ValueError:
            return "hostname"
