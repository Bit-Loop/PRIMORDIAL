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

    def _ensure_operator_intent_allowed_for_session(self, intent: object, session: object) -> None:
        policy = getattr(intent, "policy", None)
        if not self._intent_has_lab_permissions(policy):
            return
        classification = self._environment_classification_for_session(session)
        default_intent = self._default_operator_intent_for_environment(classification)
        intent_id = str(getattr(intent, "id", "")).strip()
        if classification.verified_lab and intent_id == default_intent:
            return
        raise ValueError(
            f"operator intent {intent_id or 'unknown'} requires verified matching lab environment; "
            f"current environment is {classification.environment} with default intent {default_intent}"
        )

    def _environment_classification_for_session(self, session: object) -> EnvironmentClassification:
        metadata = getattr(session, "metadata", {})
        payload = metadata.get("environment_classification") if isinstance(metadata, dict) else None
        profile = getattr(getattr(session, "profile", None), "value", None)
        if isinstance(payload, dict):
            return self._environment_classification_from_payload(payload, fallback_profile=str(profile or ""))
        return self._classify_environment(profile=str(profile or ""))

    def _environment_classification_from_payload(
        self,
        payload: dict[str, object],
        *,
        fallback_profile: str,
    ) -> EnvironmentClassification:
        proof_sources = payload.get("proof_sources", ())
        if not isinstance(proof_sources, (list, tuple)):
            proof_sources = ()
        return EnvironmentClassification(
            profile=str(payload.get("profile") or fallback_profile),
            environment=str(payload.get("environment") or "real_world"),
            default_intent=str(payload.get("default_intent") or OperatorIntentRegistry.DEFAULT_INTENT_ID),
            verified_lab=bool(payload.get("verified_lab")),
            upgrade_applied=bool(payload.get("upgrade_applied")),
            requires_environment_proof=bool(payload.get("requires_environment_proof")),
            proof_sources=tuple(str(item) for item in proof_sources),
            reason=str(payload.get("reason") or "session_metadata"),
        )

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
        session = self.store.get_active_session()
        if session is None:
            self.start_session(profile=profile, environment_classification=classification)
            return
        current_intent = str(session.metadata.get("operator_intent_id") or OperatorIntentRegistry.DEFAULT_INTENT_ID)
        selected_intent = self._select_operator_intent_for_session(current_intent, classification)
        classification_payload = classification.as_payload()
        previous_classification = session.metadata.get("environment_classification")
        if current_intent == selected_intent and previous_classification == classification_payload:
            return
        session.metadata["operator_intent_id"] = selected_intent
        session.metadata["environment_classification"] = classification_payload
        session.updated_at = utc_now()
        self.store.insert_session(session)
        intent = self.operator_intents.get(selected_intent)
        self.store.insert_event(
            EventRecord(
                type=EventType.BOOTSTRAP,
                summary=f"Operator intent reconciled for {profile.value} scope: {intent.id}",
                metadata={
                    "operator_intent": intent.as_payload(),
                    "profile": profile.value,
                    "session_id": session.id,
                    "previous_operator_intent_id": current_intent,
                    "environment_classification": classification_payload,
                },
            )
        )
