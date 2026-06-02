from __future__ import annotations

from primordial.app.runtime_deps import (
    EnvironmentClassification,
    EnvironmentClassifier,
    EventRecord,
    EventType,
    OperatorIntentRegistry,
    Path,
    ScopeProfile,
    utc_now,
)

class RuntimeEnvironmentMixin:
    def _load_environment_classifier(self, project_root: Path) -> EnvironmentClassifier:
        return EnvironmentClassifier.default()

    def _classify_environment(
        self,
        *,
        profile: str,
        resolved_profile: str | None = None,
        payload: dict[str, object] | None = None,
        target_metadata: dict[str, object] | None = None,
        asset_metadata: list[dict[str, object]] | None = None,
    ) -> EnvironmentClassification:
        return self.environment_classifier.classify(
            profile=profile,
            resolved_profile=resolved_profile,
            payload=payload,
            target_metadata=target_metadata,
            asset_metadata=asset_metadata,
        )

    def _default_operator_intent_for_environment(self, classification: EnvironmentClassification) -> str:
        if not classification.upgrade_applied:
            return OperatorIntentRegistry.DEFAULT_INTENT_ID
        if not self._operator_intent_exists(classification.default_intent):
            return OperatorIntentRegistry.DEFAULT_INTENT_ID
        return classification.default_intent

    def _select_operator_intent_for_session(
        self,
        previous_intent_id: object,
        classification: EnvironmentClassification,
    ) -> str:
        default_intent = self._default_operator_intent_for_environment(classification)
        previous_intent = str(previous_intent_id or "").strip()
        if not previous_intent or previous_intent == OperatorIntentRegistry.DEFAULT_INTENT_ID:
            return default_intent
        try:
            intent = self.operator_intents.get(previous_intent)
        except KeyError:
            return default_intent
        if not self._intent_has_lab_permissions(intent.policy):
            return intent.id
        if not classification.verified_lab:
            return default_intent
        if intent.id != default_intent:
            return default_intent
        return intent.id

    def _intent_has_lab_permissions(self, policy: object) -> bool:
        lab_policy = getattr(policy, "lab_policy", None)
        if lab_policy is None:
            return False
        return any(
            bool(getattr(lab_policy, field, False))
            for field in (
                "lab_flag_collection_allowed",
                "htb_lab_behavior_allowed",
                "reverse_shell_allowed",
            )
        )

    def _operator_intent_exists(self, intent_id: str) -> bool:
        self._load_operator_intents()
        try:
            self.operator_intents.get(intent_id)
        except KeyError:
            return False
        return True

    def _ensure_profile_default_operator_intent(
        self,
        profile: ScopeProfile,
        *,
        classification: EnvironmentClassification | None = None,
    ) -> None:
        classification = classification or self._classify_environment(profile=profile.value)
        default_intent = self._default_operator_intent_for_environment(classification)
        if default_intent == OperatorIntentRegistry.DEFAULT_INTENT_ID:
            return
        intent = self.operator_intents.get(default_intent)
        session = self.store.get_active_session()
        if session is None:
            self.start_session(profile=profile, environment_classification=classification)
            return
        current_intent = str(session.metadata.get("operator_intent_id") or OperatorIntentRegistry.DEFAULT_INTENT_ID)
        if current_intent != OperatorIntentRegistry.DEFAULT_INTENT_ID:
            return
        session.metadata["operator_intent_id"] = intent.id
        session.metadata["environment_classification"] = classification.as_payload()
        session.updated_at = utc_now()
        self.store.insert_session(session)
        self.store.insert_event(
            EventRecord(
                type=EventType.BOOTSTRAP,
                summary=f"Operator intent defaulted for {profile.value} scope: {intent.id}",
                metadata={
                    "operator_intent": intent.as_payload(),
                    "profile": profile.value,
                    "session_id": session.id,
                    "environment_classification": classification.as_payload(),
                },
            )
        )
