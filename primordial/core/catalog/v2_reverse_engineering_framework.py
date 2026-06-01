from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from primordial.core.catalog.loader import CatalogValidationError, expect_bool, expect_string_list, load_yaml_file, validate_allowed_fields


@dataclass(frozen=True, slots=True)
class V2WorkDomain:
    id: str
    primary_questions: tuple[str, ...]
    required_artifacts: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class V2IntentGate:
    id: str
    allows: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class V2WorkflowFamily:
    id: str
    inputs: tuple[str, ...]
    steps: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class V2SensitivityClass:
    id: str
    description: str


@dataclass(frozen=True, slots=True)
class V2EvidenceStandards:
    required_fields: tuple[str, ...]
    sensitivity_classes: tuple[V2SensitivityClass, ...]


@dataclass(frozen=True, slots=True)
class V2AIControlPlane:
    allowed_outputs: tuple[str, ...]
    blocked_baseline_outputs: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class V2ReferenceAnchor:
    label: str
    url: str


@dataclass(frozen=True, slots=True)
class V2ReverseEngineeringFramework:
    id: str
    source_path: str
    status: str
    loaded_by_v1_runtime: bool
    authority: str
    purpose: tuple[str, ...]
    design_boundaries: tuple[str, ...]
    work_domains: tuple[V2WorkDomain, ...]
    control_plane_records: tuple[str, ...]
    intent_gates: tuple[V2IntentGate, ...]
    default_posture: tuple[str, ...]
    workflow_families: tuple[V2WorkflowFamily, ...]
    evidence_standards: V2EvidenceStandards
    ai_control_plane: V2AIControlPlane
    implementation_milestones: tuple[str, ...]
    official_reference_anchors: tuple[V2ReferenceAnchor, ...]


class V2ReverseEngineeringFrameworkCatalog:
    FILENAME = "v2_reverse_engineering_framework.yaml"
    FIELDS = {
        "id",
        "source_path",
        "status",
        "loaded_by_v1_runtime",
        "authority",
        "purpose",
        "design_boundaries",
        "work_domains",
        "control_plane_records",
        "intent_gates",
        "default_posture",
        "workflow_families",
        "evidence_standards",
        "ai_control_plane",
        "implementation_milestones",
        "official_reference_anchors",
    }
    DOMAIN_FIELDS = {"id", "primary_questions", "required_artifacts"}
    INTENT_GATE_FIELDS = {"id", "allows"}
    WORKFLOW_FIELDS = {"id", "inputs", "steps"}
    EVIDENCE_FIELDS = {"required_fields", "sensitivity_classes"}
    SENSITIVITY_FIELDS = {"id", "description"}
    AI_FIELDS = {"allowed_outputs", "blocked_baseline_outputs"}
    REFERENCE_FIELDS = {"label", "url"}

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def load(self) -> V2ReverseEngineeringFramework:
        path = self.directory / self.FILENAME
        payload = load_yaml_file(path)
        validate_allowed_fields(payload, self.FIELDS, source=str(path))
        source_path = _text(payload.get("source_path"), source=f"{path}.source_path")
        if not source_path.endswith(".md"):
            raise CatalogValidationError(f"{path}.source_path must reference a Markdown source")
        return V2ReverseEngineeringFramework(
            id=_text(payload.get("id"), source=f"{path}.id"),
            source_path=source_path,
            status=_text(payload.get("status"), source=f"{path}.status"),
            loaded_by_v1_runtime=expect_bool(
                payload.get("loaded_by_v1_runtime"), source=f"{path}.loaded_by_v1_runtime"
            ),
            authority=_text(payload.get("authority"), source=f"{path}.authority"),
            purpose=tuple(expect_string_list(payload.get("purpose"), source=f"{path}.purpose")),
            design_boundaries=tuple(
                expect_string_list(payload.get("design_boundaries"), source=f"{path}.design_boundaries")
            ),
            work_domains=tuple(
                self._domain(item, source=f"{path}.work_domains[{index}]")
                for index, item in enumerate(_list(payload.get("work_domains"), source=f"{path}.work_domains"))
            ),
            control_plane_records=tuple(
                expect_string_list(payload.get("control_plane_records"), source=f"{path}.control_plane_records")
            ),
            intent_gates=tuple(
                self._intent_gate(item, source=f"{path}.intent_gates[{index}]")
                for index, item in enumerate(_list(payload.get("intent_gates"), source=f"{path}.intent_gates"))
            ),
            default_posture=tuple(expect_string_list(payload.get("default_posture"), source=f"{path}.default_posture")),
            workflow_families=tuple(
                self._workflow(item, source=f"{path}.workflow_families[{index}]")
                for index, item in enumerate(
                    _list(payload.get("workflow_families"), source=f"{path}.workflow_families")
                )
            ),
            evidence_standards=self._evidence(
                payload.get("evidence_standards"), source=f"{path}.evidence_standards"
            ),
            ai_control_plane=self._ai_control_plane(
                payload.get("ai_control_plane"), source=f"{path}.ai_control_plane"
            ),
            implementation_milestones=tuple(
                expect_string_list(
                    payload.get("implementation_milestones"), source=f"{path}.implementation_milestones"
                )
            ),
            official_reference_anchors=tuple(
                self._reference(item, source=f"{path}.official_reference_anchors[{index}]")
                for index, item in enumerate(
                    _list(payload.get("official_reference_anchors"), source=f"{path}.official_reference_anchors")
                )
            ),
        )

    def _domain(self, payload: Any, *, source: str) -> V2WorkDomain:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.DOMAIN_FIELDS, source=source)
        return V2WorkDomain(
            id=_text(data.get("id"), source=f"{source}.id"),
            primary_questions=tuple(expect_string_list(data.get("primary_questions"), source=f"{source}.primary_questions")),
            required_artifacts=tuple(expect_string_list(data.get("required_artifacts"), source=f"{source}.required_artifacts")),
        )

    def _intent_gate(self, payload: Any, *, source: str) -> V2IntentGate:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.INTENT_GATE_FIELDS, source=source)
        return V2IntentGate(
            id=_text(data.get("id"), source=f"{source}.id"),
            allows=tuple(expect_string_list(data.get("allows"), source=f"{source}.allows")),
        )

    def _workflow(self, payload: Any, *, source: str) -> V2WorkflowFamily:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.WORKFLOW_FIELDS, source=source)
        return V2WorkflowFamily(
            id=_text(data.get("id"), source=f"{source}.id"),
            inputs=tuple(expect_string_list(data.get("inputs"), source=f"{source}.inputs")),
            steps=tuple(expect_string_list(data.get("steps"), source=f"{source}.steps")),
        )

    def _evidence(self, payload: Any, *, source: str) -> V2EvidenceStandards:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.EVIDENCE_FIELDS, source=source)
        return V2EvidenceStandards(
            required_fields=tuple(expect_string_list(data.get("required_fields"), source=f"{source}.required_fields")),
            sensitivity_classes=tuple(
                self._sensitivity(item, source=f"{source}.sensitivity_classes[{index}]")
                for index, item in enumerate(
                    _list(data.get("sensitivity_classes"), source=f"{source}.sensitivity_classes")
                )
            ),
        )

    def _sensitivity(self, payload: Any, *, source: str) -> V2SensitivityClass:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.SENSITIVITY_FIELDS, source=source)
        return V2SensitivityClass(
            id=_text(data.get("id"), source=f"{source}.id"),
            description=_text(data.get("description"), source=f"{source}.description"),
        )

    def _ai_control_plane(self, payload: Any, *, source: str) -> V2AIControlPlane:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.AI_FIELDS, source=source)
        return V2AIControlPlane(
            allowed_outputs=tuple(expect_string_list(data.get("allowed_outputs"), source=f"{source}.allowed_outputs")),
            blocked_baseline_outputs=tuple(
                expect_string_list(data.get("blocked_baseline_outputs"), source=f"{source}.blocked_baseline_outputs")
            ),
        )

    def _reference(self, payload: Any, *, source: str) -> V2ReferenceAnchor:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.REFERENCE_FIELDS, source=source)
        return V2ReferenceAnchor(
            label=_text(data.get("label"), source=f"{source}.label"),
            url=_text(data.get("url"), source=f"{source}.url"),
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
