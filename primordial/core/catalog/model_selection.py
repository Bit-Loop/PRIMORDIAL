from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from primordial.core.catalog.loader import CatalogValidationError, expect_string_list, load_yaml_file, validate_allowed_fields


@dataclass(frozen=True, slots=True)
class RoleSelection:
    role: str
    best_current_models: tuple[str, ...]
    optimal_targets: tuple[str, ...]
    decision: str


@dataclass(frozen=True, slots=True)
class LocalDeepSelection:
    authority_hierarchy: tuple[str, ...]
    observed_failures: tuple[str, ...]
    target_model: str
    target_rationale: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PracticalModelConfig:
    role: str
    models: tuple[str, ...]
    note: str


@dataclass(frozen=True, slots=True)
class WrapperPersonality:
    role: str
    personality: str


@dataclass(frozen=True, slots=True)
class WrapperOnlyMode:
    activation_settings: tuple[str, ...]
    applies_to: tuple[str, ...]
    bypassed_actions: tuple[str, ...]
    authority_boundary: str
    personalities: tuple[WrapperPersonality, ...]


@dataclass(frozen=True, slots=True)
class ExternalModelNotes:
    escalation_order: tuple[str, ...]
    rules: tuple[str, ...]
    reference_links: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AuthorityPipeline:
    steps: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PocPressureSplit:
    design_surface: str
    execution_gate: str
    rules: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DurableChannel:
    channel: str
    carries: tuple[str, ...]
    used_by: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AgentCommunication:
    core_rule: str
    flow: tuple[str, ...]
    durable_channels: tuple[DurableChannel, ...]
    handoff_sequence: tuple[str, ...]
    canonical_handoff_packet_fields: tuple[str, ...]
    accepted_gate_response_fields: tuple[str, ...]
    validator_rejection_rules: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ModelSelection:
    id: str
    source_path: str
    status: str
    authority: str
    date: str
    purpose: tuple[str, ...]
    evidence_sources: tuple[str, ...]
    role_selection: tuple[RoleSelection, ...]
    local_deep: LocalDeepSelection
    operating_guardrails: tuple[str, ...]
    practical_configuration: tuple[PracticalModelConfig, ...]
    wrapper_only_mode: WrapperOnlyMode
    next_tests: tuple[str, ...]
    external_model_notes: ExternalModelNotes
    authority_pipeline: AuthorityPipeline
    poc_pressure_split: PocPressureSplit
    follow_up_changes: tuple[str, ...]
    agent_communication: AgentCommunication


class ModelSelectionCatalog:
    FILENAME = "model_selection.yaml"
    FIELDS = {
        "id",
        "source_path",
        "status",
        "authority",
        "date",
        "purpose",
        "evidence_sources",
        "role_selection",
        "local_deep",
        "operating_guardrails",
        "practical_configuration",
        "wrapper_only_mode",
        "next_tests",
        "external_model_notes",
        "authority_pipeline",
        "poc_pressure_split",
        "follow_up_changes",
        "agent_communication",
    }
    ROLE_SELECTION_FIELDS = {"role", "best_current_models", "optimal_targets", "decision"}
    LOCAL_DEEP_FIELDS = {"authority_hierarchy", "observed_failures", "target_model", "target_rationale"}
    PRACTICAL_CONFIG_FIELDS = {"role", "models", "note"}
    WRAPPER_FIELDS = {"activation_settings", "applies_to", "bypassed_actions", "authority_boundary", "personalities"}
    PERSONALITY_FIELDS = {"role", "personality"}
    EXTERNAL_FIELDS = {"escalation_order", "rules", "reference_links"}
    AUTHORITY_PIPELINE_FIELDS = {"steps"}
    POC_PRESSURE_FIELDS = {"design_surface", "execution_gate", "rules"}
    COMMUNICATION_FIELDS = {
        "core_rule",
        "flow",
        "durable_channels",
        "handoff_sequence",
        "canonical_handoff_packet_fields",
        "accepted_gate_response_fields",
        "validator_rejection_rules",
    }
    CHANNEL_FIELDS = {"channel", "carries", "used_by"}

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def load(self) -> ModelSelection:
        path = self.directory / self.FILENAME
        payload = load_yaml_file(path)
        validate_allowed_fields(payload, self.FIELDS, source=str(path))
        source_path = _text(payload.get("source_path"), source=f"{path}.source_path")
        if not source_path.endswith(".md"):
            raise CatalogValidationError(f"{path}.source_path must reference a Markdown source")
        return ModelSelection(
            id=_text(payload.get("id"), source=f"{path}.id"),
            source_path=source_path,
            status=_text(payload.get("status"), source=f"{path}.status"),
            authority=_text(payload.get("authority"), source=f"{path}.authority"),
            date=_text(payload.get("date"), source=f"{path}.date"),
            purpose=tuple(expect_string_list(payload.get("purpose"), source=f"{path}.purpose")),
            evidence_sources=tuple(
                expect_string_list(payload.get("evidence_sources"), source=f"{path}.evidence_sources")
            ),
            role_selection=tuple(
                self._role_selection(item, source=f"{path}.role_selection[{index}]")
                for index, item in enumerate(_list(payload.get("role_selection"), source=f"{path}.role_selection"))
            ),
            local_deep=self._local_deep(payload.get("local_deep"), source=f"{path}.local_deep"),
            operating_guardrails=tuple(
                expect_string_list(payload.get("operating_guardrails"), source=f"{path}.operating_guardrails")
            ),
            practical_configuration=tuple(
                self._practical_config(item, source=f"{path}.practical_configuration[{index}]")
                for index, item in enumerate(
                    _list(payload.get("practical_configuration"), source=f"{path}.practical_configuration")
                )
            ),
            wrapper_only_mode=self._wrapper(payload.get("wrapper_only_mode"), source=f"{path}.wrapper_only_mode"),
            next_tests=tuple(expect_string_list(payload.get("next_tests"), source=f"{path}.next_tests")),
            external_model_notes=self._external(
                payload.get("external_model_notes"), source=f"{path}.external_model_notes"
            ),
            authority_pipeline=self._authority_pipeline(
                payload.get("authority_pipeline"), source=f"{path}.authority_pipeline"
            ),
            poc_pressure_split=self._poc_pressure(
                payload.get("poc_pressure_split"), source=f"{path}.poc_pressure_split"
            ),
            follow_up_changes=tuple(
                expect_string_list(payload.get("follow_up_changes"), source=f"{path}.follow_up_changes")
            ),
            agent_communication=self._communication(
                payload.get("agent_communication"), source=f"{path}.agent_communication"
            ),
        )

    def _role_selection(self, payload: Any, *, source: str) -> RoleSelection:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.ROLE_SELECTION_FIELDS, source=source)
        return RoleSelection(
            role=_text(data.get("role"), source=f"{source}.role"),
            best_current_models=tuple(
                expect_string_list(data.get("best_current_models"), source=f"{source}.best_current_models")
            ),
            optimal_targets=tuple(expect_string_list(data.get("optimal_targets"), source=f"{source}.optimal_targets")),
            decision=_text(data.get("decision"), source=f"{source}.decision"),
        )

    def _local_deep(self, payload: Any, *, source: str) -> LocalDeepSelection:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.LOCAL_DEEP_FIELDS, source=source)
        return LocalDeepSelection(
            authority_hierarchy=tuple(
                expect_string_list(data.get("authority_hierarchy"), source=f"{source}.authority_hierarchy")
            ),
            observed_failures=tuple(
                expect_string_list(data.get("observed_failures"), source=f"{source}.observed_failures")
            ),
            target_model=_text(data.get("target_model"), source=f"{source}.target_model"),
            target_rationale=tuple(
                expect_string_list(data.get("target_rationale"), source=f"{source}.target_rationale")
            ),
        )

    def _practical_config(self, payload: Any, *, source: str) -> PracticalModelConfig:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.PRACTICAL_CONFIG_FIELDS, source=source)
        return PracticalModelConfig(
            role=_text(data.get("role"), source=f"{source}.role"),
            models=tuple(expect_string_list(data.get("models"), source=f"{source}.models")),
            note=_text(data.get("note"), source=f"{source}.note"),
        )

    def _wrapper(self, payload: Any, *, source: str) -> WrapperOnlyMode:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.WRAPPER_FIELDS, source=source)
        return WrapperOnlyMode(
            activation_settings=tuple(
                expect_string_list(data.get("activation_settings"), source=f"{source}.activation_settings")
            ),
            applies_to=tuple(expect_string_list(data.get("applies_to"), source=f"{source}.applies_to")),
            bypassed_actions=tuple(
                expect_string_list(data.get("bypassed_actions"), source=f"{source}.bypassed_actions")
            ),
            authority_boundary=_text(data.get("authority_boundary"), source=f"{source}.authority_boundary"),
            personalities=tuple(
                self._personality(item, source=f"{source}.personalities[{index}]")
                for index, item in enumerate(_list(data.get("personalities"), source=f"{source}.personalities"))
            ),
        )

    def _personality(self, payload: Any, *, source: str) -> WrapperPersonality:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.PERSONALITY_FIELDS, source=source)
        return WrapperPersonality(
            role=_text(data.get("role"), source=f"{source}.role"),
            personality=_text(data.get("personality"), source=f"{source}.personality"),
        )

    def _external(self, payload: Any, *, source: str) -> ExternalModelNotes:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.EXTERNAL_FIELDS, source=source)
        return ExternalModelNotes(
            escalation_order=tuple(expect_string_list(data.get("escalation_order"), source=f"{source}.escalation_order")),
            rules=tuple(expect_string_list(data.get("rules"), source=f"{source}.rules")),
            reference_links=tuple(expect_string_list(data.get("reference_links"), source=f"{source}.reference_links")),
        )

    def _authority_pipeline(self, payload: Any, *, source: str) -> AuthorityPipeline:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.AUTHORITY_PIPELINE_FIELDS, source=source)
        return AuthorityPipeline(steps=tuple(expect_string_list(data.get("steps"), source=f"{source}.steps")))

    def _poc_pressure(self, payload: Any, *, source: str) -> PocPressureSplit:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.POC_PRESSURE_FIELDS, source=source)
        return PocPressureSplit(
            design_surface=_text(data.get("design_surface"), source=f"{source}.design_surface"),
            execution_gate=_text(data.get("execution_gate"), source=f"{source}.execution_gate"),
            rules=tuple(expect_string_list(data.get("rules"), source=f"{source}.rules")),
        )

    def _communication(self, payload: Any, *, source: str) -> AgentCommunication:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.COMMUNICATION_FIELDS, source=source)
        return AgentCommunication(
            core_rule=_text(data.get("core_rule"), source=f"{source}.core_rule"),
            flow=tuple(expect_string_list(data.get("flow"), source=f"{source}.flow")),
            durable_channels=tuple(
                self._channel(item, source=f"{source}.durable_channels[{index}]")
                for index, item in enumerate(_list(data.get("durable_channels"), source=f"{source}.durable_channels"))
            ),
            handoff_sequence=tuple(
                expect_string_list(data.get("handoff_sequence"), source=f"{source}.handoff_sequence")
            ),
            canonical_handoff_packet_fields=tuple(
                expect_string_list(
                    data.get("canonical_handoff_packet_fields"), source=f"{source}.canonical_handoff_packet_fields"
                )
            ),
            accepted_gate_response_fields=tuple(
                expect_string_list(
                    data.get("accepted_gate_response_fields"), source=f"{source}.accepted_gate_response_fields"
                )
            ),
            validator_rejection_rules=tuple(
                expect_string_list(data.get("validator_rejection_rules"), source=f"{source}.validator_rejection_rules")
            ),
        )

    def _channel(self, payload: Any, *, source: str) -> DurableChannel:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.CHANNEL_FIELDS, source=source)
        return DurableChannel(
            channel=_text(data.get("channel"), source=f"{source}.channel"),
            carries=tuple(expect_string_list(data.get("carries"), source=f"{source}.carries")),
            used_by=tuple(expect_string_list(data.get("used_by"), source=f"{source}.used_by")),
        )


def _object(value: Any, *, source: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CatalogValidationError(f"{source} must be an object")
    return value


def _list(value: Any, *, source: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise CatalogValidationError(f"{source} must be a list")
    return value


def _text(value: Any, *, source: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CatalogValidationError(f"{source} must be a non-empty string")
    return value.strip()
