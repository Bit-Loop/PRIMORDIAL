from __future__ import annotations

from primordial.core.storage.runtime_common import *


class RuntimeRowMappersCoreMixin:
    def _session_from_row(self, row: Any) -> Session:
        return Session(
            id=row["id"],
            methodology=MethodologyName(row["methodology"]),
            profile=ScopeProfile(row["profile"]),
            autonomy_mode=row["autonomy_mode"],
            status=SessionStatus(row["status"]),
            title=row["title"],
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _target_from_row(self, row: Any) -> Target:
        return Target(
            id=row["id"],
            handle=row["handle"],
            display_name=row["display_name"],
            profile=ScopeProfile(row["profile"]),
            in_scope=bool(row["in_scope"]),
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _scope_asset_from_row(self, row: Any) -> ScopeAsset:
        return ScopeAsset(
            id=row["id"],
            target_id=row["target_id"],
            asset=row["asset"],
            asset_type=row["asset_type"],
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
        )

    def _task_from_row(self, row: Any) -> Task:
        return Task(
            id=row["id"],
            target_id=row["target_id"],
            session_id=row["session_id"],
            phase=MethodologyPhase(row["phase"]),
            kind=TaskKind(row["kind"]),
            title=row["title"],
            summary=row["summary"],
            role=AgentRole(row["role"]),
            methodology=MethodologyName(row["methodology"]),
            required_capabilities=_load(row["required_capabilities"], []),
            evidence_refs=_load(row["evidence_refs"], []),
            metadata=_load(row["metadata"], {}),
            status=TaskStatus(row["status"]),
            priority=int(row["priority"]),
            risk_tier=RiskTier(row["risk_tier"]),
            attempts=int(row["attempts"]),
            max_attempts=int(row["max_attempts"]),
            requires_approval=bool(row["requires_approval"]),
            provider_route=ProviderRoute(row["provider_route"]) if row["provider_route"] else None,
            provider_model=row["provider_model"],
            parent_task_id=row["parent_task_id"],
            latest_run_id=row["latest_run_id"],
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _policy_decision_from_row(self, row: Any) -> PolicyDecision:
        return PolicyDecision(
            id=row["id"],
            target_id=row["target_id"],
            task_id=row["task_id"],
            action_kind=row["action_kind"],
            verdict=PolicyVerdict(row["verdict"]),
            reason=row["reason"],
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
        )

    def _task_run_from_row(self, row: Any) -> TaskRun:
        return TaskRun(
            id=row["id"],
            task_id=row["task_id"],
            status=TaskRunStatus(row["status"]),
            attempt_number=int(row["attempt_number"]),
            role=AgentRole(row["role"]),
            provider_route=ProviderRoute(row["provider_route"]),
            model_name=row["model_name"],
            cold_path=bool(row["cold_path"]),
            heartbeat_at=parse_datetime(row["heartbeat_at"]) if row["heartbeat_at"] else None,
            lease_expires_at=parse_datetime(row["lease_expires_at"]) if row["lease_expires_at"] else None,
            started_at=parse_datetime(row["started_at"]),
            finished_at=parse_datetime(row["finished_at"]) if row["finished_at"] else None,
            trace_summary=row["trace_summary"],
            error=row["error"],
            metadata=_load(row["metadata"], {}),
        )

    def _handoff_from_row(self, row: Any) -> TaskHandoff:
        return TaskHandoff(
            id=row["id"],
            task_id=row["task_id"],
            source_agent=AgentRole(row["source_agent"]),
            destination_agent=AgentRole(row["destination_agent"]),
            reason=row["reason"],
            expected_output_type=row["expected_output_type"],
            evidence_refs=_load(row["evidence_refs"], []),
            hypothesis=row["hypothesis"],
            budget=row["budget"],
            deadline_at=parse_datetime(row["deadline_at"]) if row["deadline_at"] else None,
            status=HandoffStatus(row["status"]),
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
            consumed_at=parse_datetime(row["consumed_at"]) if row["consumed_at"] else None,
        )

    def _evidence_from_row(self, row: Any) -> EvidenceRecord:
        return EvidenceRecord(
            id=row["id"],
            target_id=row["target_id"],
            task_id=row["task_id"],
            type=EvidenceType(row["type"]),
            title=row["title"],
            summary=row["summary"],
            source_ref=row["source_ref"],
            verification_status=VerificationStatus(row["verification_status"]),
            confidence=float(row["confidence"]),
            freshness=float(row["freshness"]),
            artifact_path=row["artifact_path"],
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _note_from_row(self, row: Any) -> Note:
        return Note(
            id=row["id"],
            target_id=row["target_id"],
            task_id=row["task_id"],
            title=row["title"],
            body=row["body"],
            confidence=float(row["confidence"]),
            freshness=float(row["freshness"]),
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _interest_from_row(self, row: Any) -> Interest:
        return Interest(
            id=row["id"],
            target_id=row["target_id"],
            title=row["title"],
            summary=row["summary"],
            evidence_refs=_load(row["evidence_refs"], []),
            status=InterestStatus(row["status"]),
            confidence=float(row["confidence"]),
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _finding_from_row(self, row: Any) -> Finding:
        return Finding(
            id=row["id"],
            target_id=row["target_id"],
            title=row["title"],
            summary=row["summary"],
            severity=FindingSeverity(row["severity"]),
            evidence_refs=_load(row["evidence_refs"], []),
            confidence=float(row["confidence"]),
            verification_status=VerificationStatus(row["verification_status"]),
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _memory_from_row(self, row: Any) -> MemoryEntry:
        return MemoryEntry(
            id=row["id"],
            target_id=row["target_id"],
            layer=MemoryLayer(row["layer"]),
            title=row["title"],
            summary=row["summary"],
            evidence_refs=_load(row["evidence_refs"], []),
            confidence=float(row["confidence"]),
            freshness=float(row["freshness"]),
            status=MemoryStatus(row["status"]),
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )

    def _primitive_from_row(self, row: Any) -> PrimitiveManifest:
        return PrimitiveManifest(
            id=row["id"],
            name=row["name"],
            version=row["version"],
            description=row["description"],
            capability_tags=_load(row["capability_tags"], []),
            allowed_phases=[MethodologyPhase(item) for item in _load(row["allowed_phases"], [])],
            runtime=PrimitiveRuntime(row["runtime"]),
            risk_tier=RiskTier(row["risk_tier"]),
            side_effect_level=SideEffectLevel(row["side_effect_level"]),
            required_secrets=_load(row["required_secrets"], []),
            input_schema=_load(row["input_schema"], {}),
            output_schema=_load(row["output_schema"], {}),
            timeout_seconds=int(row["timeout_seconds"]),
            retry_policy=_load(row["retry_policy"], {}),
            evidence_adapter=row["evidence_adapter"],
            sandbox_profile=row["sandbox_profile"],
            healthcheck=row["healthcheck"],
            metadata=_load(row["metadata"], {}),
            created_at=parse_datetime(row["created_at"]),
            updated_at=parse_datetime(row["updated_at"]),
        )
