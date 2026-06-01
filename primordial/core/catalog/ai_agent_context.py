from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from primordial.core.catalog.loader import CatalogValidationError, expect_string_list, load_yaml_file, validate_allowed_fields


@dataclass(frozen=True, slots=True)
class AgentRole:
    id: str
    activation: str
    triggers: tuple[str, ...]
    outputs: tuple[str, ...]
    guardrails: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ContextLayer:
    id: str
    contents: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ClaudeEscalation:
    triggers: tuple[str, ...]
    denials: tuple[str, ...]
    flow: tuple[str, ...]
    post_response_rules: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AIAgentContext:
    id: str
    source_path: str
    status: str
    last_updated: str
    current_goals: tuple[str, ...]
    user_intents: tuple[str, ...]
    architecture_principles: tuple[str, ...]
    model_strategy: dict[str, Any]
    agent_roles: tuple[AgentRole, ...]
    evidence_claim_requirements: tuple[str, ...]
    durable_fact_denials: tuple[str, ...]
    context_layers: tuple[ContextLayer, ...]
    context_loading_rules: tuple[str, ...]
    communication_patterns: tuple[str, ...]
    efficiency_rules: tuple[str, ...]
    claude_escalation: ClaudeEscalation


class AIAgentContextCatalog:
    FILENAME = "ai_agent_current_context.yaml"
    FIELDS = {
        "id",
        "source_path",
        "status",
        "last_updated",
        "current_goals",
        "user_intents",
        "architecture_principles",
        "model_strategy",
        "agent_roles",
        "evidence_claim_requirements",
        "durable_fact_denials",
        "context_layers",
        "context_loading_rules",
        "communication_patterns",
        "efficiency_rules",
        "claude_escalation",
    }
    AGENT_ROLE_FIELDS = {"id", "activation", "triggers", "outputs", "guardrails"}
    CONTEXT_LAYER_FIELDS = {"id", "contents"}
    CLAUDE_FIELDS = {"triggers", "denials", "flow", "post_response_rules"}

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def load(self) -> AIAgentContext:
        path = self.directory / self.FILENAME
        payload = load_yaml_file(path)
        validate_allowed_fields(payload, self.FIELDS, source=str(path))
        return AIAgentContext(
            id=_text(payload.get("id"), source=f"{path}.id"),
            source_path=_text(payload.get("source_path"), source=f"{path}.source_path"),
            status=_text(payload.get("status"), source=f"{path}.status"),
            last_updated=_text(payload.get("last_updated"), source=f"{path}.last_updated"),
            current_goals=tuple(expect_string_list(payload.get("current_goals"), source=f"{path}.current_goals")),
            user_intents=tuple(expect_string_list(payload.get("user_intents"), source=f"{path}.user_intents")),
            architecture_principles=tuple(
                expect_string_list(payload.get("architecture_principles"), source=f"{path}.architecture_principles")
            ),
            model_strategy=_object(payload.get("model_strategy"), source=f"{path}.model_strategy"),
            agent_roles=tuple(
                self._agent_role(item, source=f"{path}.agent_roles[{index}]")
                for index, item in enumerate(_list(payload.get("agent_roles"), source=f"{path}.agent_roles"))
            ),
            evidence_claim_requirements=tuple(
                expect_string_list(
                    payload.get("evidence_claim_requirements"), source=f"{path}.evidence_claim_requirements"
                )
            ),
            durable_fact_denials=tuple(
                expect_string_list(payload.get("durable_fact_denials"), source=f"{path}.durable_fact_denials")
            ),
            context_layers=tuple(
                self._context_layer(item, source=f"{path}.context_layers[{index}]")
                for index, item in enumerate(_list(payload.get("context_layers"), source=f"{path}.context_layers"))
            ),
            context_loading_rules=tuple(
                expect_string_list(payload.get("context_loading_rules"), source=f"{path}.context_loading_rules")
            ),
            communication_patterns=tuple(
                expect_string_list(payload.get("communication_patterns"), source=f"{path}.communication_patterns")
            ),
            efficiency_rules=tuple(expect_string_list(payload.get("efficiency_rules"), source=f"{path}.efficiency_rules")),
            claude_escalation=self._claude_escalation(
                _object(payload.get("claude_escalation"), source=f"{path}.claude_escalation"),
                source=f"{path}.claude_escalation",
            ),
        )

    def _agent_role(self, payload: Any, *, source: str) -> AgentRole:
        if not isinstance(payload, dict):
            raise CatalogValidationError(f"{source} must be an object")
        validate_allowed_fields(payload, self.AGENT_ROLE_FIELDS, source=source)
        return AgentRole(
            id=_text(payload.get("id"), source=f"{source}.id"),
            activation=_text(payload.get("activation"), source=f"{source}.activation"),
            triggers=tuple(expect_string_list(payload.get("triggers"), source=f"{source}.triggers")),
            outputs=tuple(expect_string_list(payload.get("outputs"), source=f"{source}.outputs")),
            guardrails=tuple(expect_string_list(payload.get("guardrails"), source=f"{source}.guardrails")),
        )

    def _context_layer(self, payload: Any, *, source: str) -> ContextLayer:
        if not isinstance(payload, dict):
            raise CatalogValidationError(f"{source} must be an object")
        validate_allowed_fields(payload, self.CONTEXT_LAYER_FIELDS, source=source)
        return ContextLayer(
            id=_text(payload.get("id"), source=f"{source}.id"),
            contents=tuple(expect_string_list(payload.get("contents"), source=f"{source}.contents")),
        )

    def _claude_escalation(self, payload: dict[str, Any], *, source: str) -> ClaudeEscalation:
        validate_allowed_fields(payload, self.CLAUDE_FIELDS, source=source)
        return ClaudeEscalation(
            triggers=tuple(expect_string_list(payload.get("triggers"), source=f"{source}.triggers")),
            denials=tuple(expect_string_list(payload.get("denials"), source=f"{source}.denials")),
            flow=tuple(expect_string_list(payload.get("flow"), source=f"{source}.flow")),
            post_response_rules=tuple(
                expect_string_list(payload.get("post_response_rules"), source=f"{source}.post_response_rules")
            ),
        )


def _text(value: Any, *, source: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CatalogValidationError(f"{source} must be a non-empty string")
    return value.strip()


def _list(value: Any, *, source: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise CatalogValidationError(f"{source} must be a list")
    return value


def _object(value: Any, *, source: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise CatalogValidationError(f"{source} must be an object")
    return value
