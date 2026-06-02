from __future__ import annotations

from primordial.app.runtime_deps import (
    EventRecord,
    EventType,
    OperatorIntentPolicy,
    OperatorIntentRegistry,
    Path,
    utc_now,
)

class RuntimeIntentControlMixin:
    def operator_intent_payload(self) -> dict[str, object]:
        self._load_operator_intents()
        active = self.active_operator_intent()
        return {
            "active": active.as_payload(),
            "intents": [intent.as_payload() for intent in self.operator_intents.all()],
            "default": OperatorIntentRegistry.DEFAULT_INTENT_ID,
        }

    def active_operator_intent(self):
        self._load_operator_intents()
        session = self.store.get_active_session()
        intent_id = None
        if session is not None:
            intent_id = session.metadata.get("operator_intent_id")
        try:
            return self.operator_intents.get(str(intent_id) if intent_id else None)
        except KeyError:
            return self.operator_intents.get(OperatorIntentRegistry.DEFAULT_INTENT_ID)

    def intent_policy(self) -> OperatorIntentPolicy:
        return self.active_operator_intent().policy

    def set_operator_intent(self, intent_id: str) -> dict[str, object]:
        self._load_operator_intents()
        intent = self.operator_intents.get(intent_id)
        session = self.store.get_active_session() or self.start_session()
        self._ensure_operator_intent_allowed_for_session(intent, session)
        session.metadata["operator_intent_id"] = intent.id
        session.updated_at = utc_now()
        self.store.insert_session(session)
        self.store.insert_event(
            EventRecord(
                type=EventType.BOOTSTRAP,
                summary=f"Operator intent set: {intent.id}",
                metadata={"operator_intent": intent.as_payload(), "session_id": session.id},
            )
        )
        return self.operator_intent_payload()

    def update_runtime_control(
        self,
        *,
        mode: str,
        interval_seconds: int | None = None,
        intent_id: str,
    ) -> dict[str, object]:
        selected_mode = str(mode).strip().lower()
        if selected_mode not in self.EXECUTION_MODES:
            raise ValueError(f"unsupported execution mode: {mode}")
        self._load_operator_intents()
        intent = self.operator_intents.get(intent_id)
        session = self.store.get_active_session() or self.start_session()
        self._ensure_operator_intent_allowed_for_session(intent, session)
        execution_mode = self.update_execution_mode(selected_mode, interval_seconds=interval_seconds)
        operator_intent = self.set_operator_intent(intent.id)
        return {
            "execution_mode": execution_mode,
            "operator_intent": operator_intent,
        }

    def _load_operator_intents(self) -> None:
        if self.operator_intents.all():
            return
        configured_dir = self.config.catalog_dir / "intents"
        if not any(configured_dir.glob("*.yaml")):
            self.operator_intents = OperatorIntentRegistry(Path(__file__).resolve().parents[2] / "catalog" / "intents")
        self.operator_intents.load()
