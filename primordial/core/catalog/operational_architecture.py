from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from primordial.core.catalog.loader import CatalogValidationError, expect_string_list, load_yaml_file, validate_allowed_fields


@dataclass(frozen=True, slots=True)
class RuntimeComponent:
    name: str
    role: str


@dataclass(frozen=True, slots=True)
class RuntimeAssembly:
    entrypoint: str
    components: tuple[RuntimeComponent, ...]
    facade_methods: tuple[str, ...]
    boundaries: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class StorageModel:
    files: tuple[str, ...]
    source_of_truth: str
    required_environment: tuple[str, ...]
    records: tuple[str, ...]
    boundaries: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ScopeTargetModel:
    entrypoints: tuple[str, ...]
    target_fields: tuple[str, ...]
    input_surfaces: tuple[str, ...]
    rules: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ExecutionModel:
    tick_pipeline: tuple[str, ...]
    tick_steps: tuple[str, ...]
    modes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class WorkflowPlanningModel:
    files: tuple[str, ...]
    rules: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PolicySafetyModel:
    file: str
    evaluates_against: tuple[str, ...]
    rules: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class WorkersPrimitivesModel:
    files: tuple[str, ...]
    task_handlers: tuple[str, ...]
    manifest_paths: tuple[str, ...]
    outputs: tuple[str, ...]
    rules: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ModelRole:
    id: str
    purpose: str


@dataclass(frozen=True, slots=True)
class AIModelUse:
    files: tuple[str, ...]
    roles: tuple[ModelRole, ...]
    uses: tuple[str, ...]
    boundaries: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class OperatorChatModel:
    entrypoints: tuple[str, ...]
    storage: tuple[str, ...]
    display_rules: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AuxiliaryViews:
    findings_paths: tuple[str, ...]
    integration_files: tuple[str, ...]
    rules: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class InterfaceSurface:
    id: str
    files: tuple[str, ...]
    uses: tuple[str, ...]
    rules: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class UISyncModel:
    shared_store_items: tuple[str, ...]
    rules: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class OperationalArchitecture:
    id: str
    source_path: str
    status: str
    authority: str
    runtime_model: str
    always_on_prompt_agent: bool
    core_invariants: tuple[str, ...]
    runtime_assembly: RuntimeAssembly
    storage: StorageModel
    scope_and_targets: ScopeTargetModel
    execution_model: ExecutionModel
    workflow_planning: WorkflowPlanningModel
    policy_and_safety: PolicySafetyModel
    workers_and_primitives: WorkersPrimitivesModel
    ai_model_use: AIModelUse
    operator_chat_and_ai_thinking: OperatorChatModel
    auxiliary_views: AuxiliaryViews
    interfaces: tuple[InterfaceSurface, ...]
    ui_sync: UISyncModel
    critical_data_flow: tuple[str, ...]
    current_strengths: tuple[str, ...]
    current_weak_points: tuple[str, ...]
    safe_development_rules: tuple[str, ...]


class OperationalArchitectureCatalog:
    FILENAME = "operational_architecture.yaml"
    FIELDS = {
        "id",
        "source_path",
        "status",
        "authority",
        "runtime_model",
        "always_on_prompt_agent",
        "core_invariants",
        "runtime_assembly",
        "storage",
        "scope_and_targets",
        "execution_model",
        "workflow_planning",
        "policy_and_safety",
        "workers_and_primitives",
        "ai_model_use",
        "operator_chat_and_ai_thinking",
        "auxiliary_views",
        "interfaces",
        "ui_sync",
        "critical_data_flow",
        "current_strengths",
        "current_weak_points",
        "safe_development_rules",
    }
    RUNTIME_ASSEMBLY_FIELDS = {"entrypoint", "components", "facade_methods", "boundaries"}
    COMPONENT_FIELDS = {"name", "role"}
    STORAGE_FIELDS = {"files", "source_of_truth", "required_environment", "records", "boundaries"}
    SCOPE_TARGET_FIELDS = {"entrypoints", "target_fields", "input_surfaces", "rules"}
    EXECUTION_FIELDS = {"tick_pipeline", "tick_steps", "modes"}
    WORKFLOW_FIELDS = {"files", "rules"}
    POLICY_FIELDS = {"file", "evaluates_against", "rules"}
    WORKERS_FIELDS = {"files", "task_handlers", "manifest_paths", "outputs", "rules"}
    AI_MODEL_FIELDS = {"files", "roles", "uses", "boundaries"}
    MODEL_ROLE_FIELDS = {"id", "purpose"}
    OPERATOR_CHAT_FIELDS = {"entrypoints", "storage", "display_rules"}
    AUXILIARY_VIEWS_FIELDS = {"findings_paths", "integration_files", "rules"}
    INTERFACE_FIELDS = {"id", "files", "uses", "rules"}
    UI_SYNC_FIELDS = {"shared_store_items", "rules"}

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def load(self) -> OperationalArchitecture:
        path = self.directory / self.FILENAME
        payload = load_yaml_file(path)
        validate_allowed_fields(payload, self.FIELDS, source=str(path))
        source_path = _text(payload.get("source_path"), source=f"{path}.source_path")
        if not source_path.endswith(".md"):
            raise CatalogValidationError(f"{path}.source_path must reference a Markdown source")
        return OperationalArchitecture(
            id=_text(payload.get("id"), source=f"{path}.id"),
            source_path=source_path,
            status=_text(payload.get("status"), source=f"{path}.status"),
            authority=_text(payload.get("authority"), source=f"{path}.authority"),
            runtime_model=_text(payload.get("runtime_model"), source=f"{path}.runtime_model"),
            always_on_prompt_agent=_bool(payload.get("always_on_prompt_agent"), source=f"{path}.always_on_prompt_agent"),
            core_invariants=tuple(expect_string_list(payload.get("core_invariants"), source=f"{path}.core_invariants")),
            runtime_assembly=self._runtime_assembly(
                payload.get("runtime_assembly"), source=f"{path}.runtime_assembly"
            ),
            storage=self._storage(payload.get("storage"), source=f"{path}.storage"),
            scope_and_targets=self._scope_targets(payload.get("scope_and_targets"), source=f"{path}.scope_and_targets"),
            execution_model=self._execution_model(payload.get("execution_model"), source=f"{path}.execution_model"),
            workflow_planning=self._workflow(payload.get("workflow_planning"), source=f"{path}.workflow_planning"),
            policy_and_safety=self._policy(payload.get("policy_and_safety"), source=f"{path}.policy_and_safety"),
            workers_and_primitives=self._workers(
                payload.get("workers_and_primitives"), source=f"{path}.workers_and_primitives"
            ),
            ai_model_use=self._ai_model_use(payload.get("ai_model_use"), source=f"{path}.ai_model_use"),
            operator_chat_and_ai_thinking=self._operator_chat(
                payload.get("operator_chat_and_ai_thinking"), source=f"{path}.operator_chat_and_ai_thinking"
            ),
            auxiliary_views=self._auxiliary_views(payload.get("auxiliary_views"), source=f"{path}.auxiliary_views"),
            interfaces=tuple(
                self._interface(item, source=f"{path}.interfaces[{index}]")
                for index, item in enumerate(_list(payload.get("interfaces"), source=f"{path}.interfaces"))
            ),
            ui_sync=self._ui_sync(payload.get("ui_sync"), source=f"{path}.ui_sync"),
            critical_data_flow=tuple(
                expect_string_list(payload.get("critical_data_flow"), source=f"{path}.critical_data_flow")
            ),
            current_strengths=tuple(
                expect_string_list(payload.get("current_strengths"), source=f"{path}.current_strengths")
            ),
            current_weak_points=tuple(
                expect_string_list(payload.get("current_weak_points"), source=f"{path}.current_weak_points")
            ),
            safe_development_rules=tuple(
                expect_string_list(payload.get("safe_development_rules"), source=f"{path}.safe_development_rules")
            ),
        )

    def _runtime_assembly(self, payload: Any, *, source: str) -> RuntimeAssembly:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.RUNTIME_ASSEMBLY_FIELDS, source=source)
        return RuntimeAssembly(
            entrypoint=_text(data.get("entrypoint"), source=f"{source}.entrypoint"),
            components=tuple(
                self._component(item, source=f"{source}.components[{index}]")
                for index, item in enumerate(_list(data.get("components"), source=f"{source}.components"))
            ),
            facade_methods=tuple(expect_string_list(data.get("facade_methods"), source=f"{source}.facade_methods")),
            boundaries=tuple(expect_string_list(data.get("boundaries"), source=f"{source}.boundaries")),
        )

    def _component(self, payload: Any, *, source: str) -> RuntimeComponent:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.COMPONENT_FIELDS, source=source)
        return RuntimeComponent(
            name=_text(data.get("name"), source=f"{source}.name"),
            role=_text(data.get("role"), source=f"{source}.role"),
        )

    def _storage(self, payload: Any, *, source: str) -> StorageModel:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.STORAGE_FIELDS, source=source)
        return StorageModel(
            files=tuple(expect_string_list(data.get("files"), source=f"{source}.files")),
            source_of_truth=_text(data.get("source_of_truth"), source=f"{source}.source_of_truth"),
            required_environment=tuple(
                expect_string_list(data.get("required_environment"), source=f"{source}.required_environment")
            ),
            records=tuple(expect_string_list(data.get("records"), source=f"{source}.records")),
            boundaries=tuple(expect_string_list(data.get("boundaries"), source=f"{source}.boundaries")),
        )

    def _scope_targets(self, payload: Any, *, source: str) -> ScopeTargetModel:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.SCOPE_TARGET_FIELDS, source=source)
        return ScopeTargetModel(
            entrypoints=tuple(expect_string_list(data.get("entrypoints"), source=f"{source}.entrypoints")),
            target_fields=tuple(expect_string_list(data.get("target_fields"), source=f"{source}.target_fields")),
            input_surfaces=tuple(expect_string_list(data.get("input_surfaces"), source=f"{source}.input_surfaces")),
            rules=tuple(expect_string_list(data.get("rules"), source=f"{source}.rules")),
        )

    def _execution_model(self, payload: Any, *, source: str) -> ExecutionModel:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.EXECUTION_FIELDS, source=source)
        return ExecutionModel(
            tick_pipeline=tuple(expect_string_list(data.get("tick_pipeline"), source=f"{source}.tick_pipeline")),
            tick_steps=tuple(expect_string_list(data.get("tick_steps"), source=f"{source}.tick_steps")),
            modes=tuple(expect_string_list(data.get("modes"), source=f"{source}.modes")),
        )

    def _workflow(self, payload: Any, *, source: str) -> WorkflowPlanningModel:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.WORKFLOW_FIELDS, source=source)
        return WorkflowPlanningModel(
            files=tuple(expect_string_list(data.get("files"), source=f"{source}.files")),
            rules=tuple(expect_string_list(data.get("rules"), source=f"{source}.rules")),
        )

    def _policy(self, payload: Any, *, source: str) -> PolicySafetyModel:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.POLICY_FIELDS, source=source)
        return PolicySafetyModel(
            file=_text(data.get("file"), source=f"{source}.file"),
            evaluates_against=tuple(
                expect_string_list(data.get("evaluates_against"), source=f"{source}.evaluates_against")
            ),
            rules=tuple(expect_string_list(data.get("rules"), source=f"{source}.rules")),
        )

    def _workers(self, payload: Any, *, source: str) -> WorkersPrimitivesModel:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.WORKERS_FIELDS, source=source)
        return WorkersPrimitivesModel(
            files=tuple(expect_string_list(data.get("files"), source=f"{source}.files")),
            task_handlers=tuple(expect_string_list(data.get("task_handlers"), source=f"{source}.task_handlers")),
            manifest_paths=tuple(expect_string_list(data.get("manifest_paths"), source=f"{source}.manifest_paths")),
            outputs=tuple(expect_string_list(data.get("outputs"), source=f"{source}.outputs")),
            rules=tuple(expect_string_list(data.get("rules"), source=f"{source}.rules")),
        )

    def _ai_model_use(self, payload: Any, *, source: str) -> AIModelUse:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.AI_MODEL_FIELDS, source=source)
        return AIModelUse(
            files=tuple(expect_string_list(data.get("files"), source=f"{source}.files")),
            roles=tuple(
                self._model_role(item, source=f"{source}.roles[{index}]")
                for index, item in enumerate(_list(data.get("roles"), source=f"{source}.roles"))
            ),
            uses=tuple(expect_string_list(data.get("uses"), source=f"{source}.uses")),
            boundaries=tuple(expect_string_list(data.get("boundaries"), source=f"{source}.boundaries")),
        )

    def _model_role(self, payload: Any, *, source: str) -> ModelRole:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.MODEL_ROLE_FIELDS, source=source)
        return ModelRole(
            id=_text(data.get("id"), source=f"{source}.id"),
            purpose=_text(data.get("purpose"), source=f"{source}.purpose"),
        )

    def _operator_chat(self, payload: Any, *, source: str) -> OperatorChatModel:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.OPERATOR_CHAT_FIELDS, source=source)
        return OperatorChatModel(
            entrypoints=tuple(expect_string_list(data.get("entrypoints"), source=f"{source}.entrypoints")),
            storage=tuple(expect_string_list(data.get("storage"), source=f"{source}.storage")),
            display_rules=tuple(expect_string_list(data.get("display_rules"), source=f"{source}.display_rules")),
        )

    def _auxiliary_views(self, payload: Any, *, source: str) -> AuxiliaryViews:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.AUXILIARY_VIEWS_FIELDS, source=source)
        return AuxiliaryViews(
            findings_paths=tuple(expect_string_list(data.get("findings_paths"), source=f"{source}.findings_paths")),
            integration_files=tuple(
                expect_string_list(data.get("integration_files"), source=f"{source}.integration_files")
            ),
            rules=tuple(expect_string_list(data.get("rules"), source=f"{source}.rules")),
        )

    def _interface(self, payload: Any, *, source: str) -> InterfaceSurface:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.INTERFACE_FIELDS, source=source)
        return InterfaceSurface(
            id=_text(data.get("id"), source=f"{source}.id"),
            files=tuple(expect_string_list(data.get("files"), source=f"{source}.files")),
            uses=tuple(expect_string_list(data.get("uses"), source=f"{source}.uses")),
            rules=tuple(expect_string_list(data.get("rules"), source=f"{source}.rules")),
        )

    def _ui_sync(self, payload: Any, *, source: str) -> UISyncModel:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.UI_SYNC_FIELDS, source=source)
        return UISyncModel(
            shared_store_items=tuple(
                expect_string_list(data.get("shared_store_items"), source=f"{source}.shared_store_items")
            ),
            rules=tuple(expect_string_list(data.get("rules"), source=f"{source}.rules")),
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


def _bool(value: Any, *, source: str) -> bool:
    if type(value) is not bool:
        raise CatalogValidationError(f"{source} must be a boolean")
    return value
