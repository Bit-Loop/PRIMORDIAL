from __future__ import annotations

from dataclasses import dataclass

from primordial.core.domain.enums import MethodologyPhase, ProviderRoute, TaskKind
from primordial.core.validation.registry import (
    ValidationContext,
    ValidationIssue,
    ValidationRegistry,
    ValidationSeverity,
    ValidationStage,
)


@dataclass(slots=True, frozen=True)
class CapabilityCoverageValidator:
    plugin_id: str = "core:capability-coverage"
    priority: int = 10
    stages: tuple[ValidationStage, ...] = (
        ValidationStage.TASK_REGISTRATION,
        ValidationStage.EXECUTION_PREFLIGHT,
    )

    def validate(self, context: ValidationContext) -> list[ValidationIssue]:
        if not context.task.required_capabilities:
            return []
        covered = {
            capability
            for primitive in context.primitives
            for capability in primitive.capability_tags
        }
        missing = [capability for capability in context.task.required_capabilities if capability not in covered]
        if not missing:
            return []
        return [
            ValidationIssue(
                code="CAPABILITY_UNRESOLVED",
                message="Task requires capabilities with no approved primitive coverage.",
                severity=ValidationSeverity.ERROR,
                metadata={"missing_capabilities": missing},
            )
        ]


@dataclass(slots=True, frozen=True)
class PrimitiveManifestValidator:
    plugin_id: str = "core:primitive-manifest"
    priority: int = 20
    stages: tuple[ValidationStage, ...] = (ValidationStage.EXECUTION_PREFLIGHT,)

    def validate(self, context: ValidationContext) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []
        for primitive in context.primitives:
            if not primitive.capability_tags:
                issues.append(
                    ValidationIssue(
                        code="PRIMITIVE_MISSING_CAPABILITIES",
                        message=f"Primitive '{primitive.name}' declares no capability tags.",
                        severity=ValidationSeverity.ERROR,
                    )
                )
            if context.task.phase not in primitive.allowed_phases:
                issues.append(
                    ValidationIssue(
                        code="PRIMITIVE_PHASE_MISMATCH",
                        message=f"Primitive '{primitive.name}' is not admissible in the current methodology phase.",
                        severity=ValidationSeverity.ERROR,
                        metadata={"phase": context.task.phase.value},
                    )
                )
            if primitive.timeout_seconds <= 0:
                issues.append(
                    ValidationIssue(
                        code="PRIMITIVE_TIMEOUT_INVALID",
                        message=f"Primitive '{primitive.name}' has an invalid timeout.",
                        severity=ValidationSeverity.ERROR,
                    )
                )
        return issues


@dataclass(slots=True, frozen=True)
class EvidenceBackedTaskValidator:
    plugin_id: str = "core:evidence-backed-task"
    priority: int = 30
    stages: tuple[ValidationStage, ...] = (
        ValidationStage.TASK_REGISTRATION,
        ValidationStage.EXECUTION_PREFLIGHT,
    )

    def validate(self, context: ValidationContext) -> list[ValidationIssue]:
        task = context.task
        issues: list[ValidationIssue] = []

        if task.kind == TaskKind.CHAIN_CANDIDATES:
            verified_interests = context.store.verified_interest_count(task.target_id)
            if verified_interests < 2:
                issues.append(
                    ValidationIssue(
                        code="CHAINING_EVIDENCE_TOO_THIN",
                        message="Chain review requires at least two verified interests.",
                        severity=ValidationSeverity.ERROR,
                        metadata={"verified_interests": verified_interests},
                    )
                )

        if task.kind == TaskKind.VERIFY_HYPOTHESIS:
            verified_interests = context.store.verified_interest_count(task.target_id)
            if not task.evidence_refs and verified_interests < 1:
                issues.append(
                    ValidationIssue(
                        code="EXPLOITATION_NEEDS_EVIDENCE",
                        message="Bounded verification requires evidence references or at least one verified interest.",
                        severity=ValidationSeverity.ERROR,
                        metadata={"verified_interests": verified_interests},
                    )
                )

        if task.provider_route == ProviderRoute.REMOTE_PREMIUM or task.kind == TaskKind.REVIEW_PREMIUM_ESCALATION:
            package = task.metadata.get("escalation_package", {})
            package_refs = package.get("evidence_refs", []) if isinstance(package, dict) else []
            if not task.evidence_refs and not package_refs:
                issues.append(
                    ValidationIssue(
                        code="PREMIUM_REVIEW_NEEDS_EVIDENCE",
                        message="Premium escalation requires evidence-linked context.",
                        severity=ValidationSeverity.ERROR,
                    )
                )
            if not package:
                issues.append(
                    ValidationIssue(
                        code="PREMIUM_REVIEW_PACKAGE_MISSING",
                        message="Premium escalation requires a structured escalation package.",
                        severity=ValidationSeverity.ERROR,
                    )
                )

        return issues


@dataclass(slots=True, frozen=True)
class MethodologyTaskValidator:
    plugin_id: str = "core:methodology-task"
    priority: int = 40
    stages: tuple[ValidationStage, ...] = (
        ValidationStage.TASK_REGISTRATION,
        ValidationStage.EXECUTION_PREFLIGHT,
    )

    def validate(self, context: ValidationContext) -> list[ValidationIssue]:
        task = context.task
        issues: list[ValidationIssue] = []
        if task.phase == MethodologyPhase.EXPLOITATION and task.kind != TaskKind.VERIFY_HYPOTHESIS:
            issues.append(
                ValidationIssue(
                    code="EXPLOITATION_PHASE_KIND_MISMATCH",
                    message="Only bounded verification tasks should enter exploitation by default.",
                    severity=ValidationSeverity.WARNING,
                    metadata={"kind": task.kind.value},
                )
            )
        if task.kind == TaskKind.REVIEW_PREMIUM_ESCALATION and task.phase != MethodologyPhase.ANALYSIS:
            issues.append(
                ValidationIssue(
                    code="PREMIUM_REVIEW_PHASE_DRIFT",
                    message="Premium review tasks should remain analysis-scoped for controlled escalation handling.",
                    severity=ValidationSeverity.WARNING,
                    metadata={"phase": task.phase.value},
                )
            )
        return issues


def build_default_validation_registry() -> ValidationRegistry:
    registry = ValidationRegistry()
    registry.register(CapabilityCoverageValidator())
    registry.register(PrimitiveManifestValidator())
    registry.register(EvidenceBackedTaskValidator())
    registry.register(MethodologyTaskValidator())
    return registry
