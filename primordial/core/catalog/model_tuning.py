from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from primordial.core.catalog.loader import CatalogValidationError, expect_string_list, load_yaml_file, validate_allowed_fields


@dataclass(frozen=True, slots=True)
class LiveTuningConfig:
    context_length: int
    max_tokens: int
    temperature: float
    cpu_reserve_mb: int
    vram_soft_reserve_mb: int
    timeout_seconds: int


@dataclass(frozen=True, slots=True)
class TuningExecutionContext:
    runtime_cli_used: bool
    runtime_cli_skip_reason: str
    provider_level_tuner_used: bool
    sampler_sources: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TuningResult:
    status: str
    rows_recorded: int
    warnings: tuple[str, ...]
    detailed_artifact: str
    reusable_profile: str
    post_run_loaded_models_reported: bool


@dataclass(frozen=True, slots=True)
class LoadConfig:
    eval_batch_size: int
    flash_attention: bool
    offload_kv_cache_to_gpu: bool
    num_experts: int | None


@dataclass(frozen=True, slots=True)
class BestModelConfig:
    model: str
    tokens_per_second: float
    best_load_config: LoadConfig


@dataclass(frozen=True, slots=True)
class RoleGuidance:
    role: str
    relative_best: tuple[str, ...]
    why: str
    caution: str


@dataclass(frozen=True, slots=True)
class PracticalDefaults:
    small_context_workhorse: str
    next_cyber_code_candidate: str
    deep_candidate_to_retest: str
    auto_route_code_work: bool


@dataclass(frozen=True, slots=True)
class RoleFindings:
    recommendation_gate_met: bool
    guidance: str
    aggregate_row_fields: tuple[str, ...]
    roles: tuple[RoleGuidance, ...]
    practical_defaults: PracticalDefaults


@dataclass(frozen=True, slots=True)
class RuntimeSkipResult:
    stage: str
    error: str
    load_state: str


@dataclass(frozen=True, slots=True)
class RuntimeGuard:
    max_model_runtime_seconds: int
    max_model_runtime_label: str
    estimate_inputs: tuple[str, ...]
    skip_result: RuntimeSkipResult
    result_fields: tuple[str, ...]
    offload_targets: tuple[str, ...]
    eval_metadata_fields: tuple[str, ...]
    cli_override: str
    saved_artifacts_updated: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ModelTuning:
    id: str
    source_path: str
    status: str
    date: str
    live_tuning: LiveTuningConfig
    execution_context: TuningExecutionContext
    models_checked: tuple[str, ...]
    result: TuningResult
    best_configs: tuple[BestModelConfig, ...]
    role_findings: RoleFindings
    runtime_guard: RuntimeGuard
    usage_commands: tuple[str, ...]


class ModelTuningCatalog:
    FILENAME = "lmstudio_tuning.yaml"
    FIELDS = {
        "id",
        "source_path",
        "status",
        "date",
        "live_tuning",
        "execution_context",
        "models_checked",
        "result",
        "best_configs",
        "role_findings",
        "runtime_guard",
        "usage_commands",
    }
    LIVE_TUNING_FIELDS = {
        "context_length",
        "max_tokens",
        "temperature",
        "cpu_reserve_mb",
        "vram_soft_reserve_mb",
        "timeout_seconds",
    }
    EXECUTION_CONTEXT_FIELDS = {
        "runtime_cli_used",
        "runtime_cli_skip_reason",
        "provider_level_tuner_used",
        "sampler_sources",
    }
    RESULT_FIELDS = {
        "status",
        "rows_recorded",
        "warnings",
        "detailed_artifact",
        "reusable_profile",
        "post_run_loaded_models_reported",
    }
    BEST_CONFIG_FIELDS = {"model", "tokens_per_second", "best_load_config"}
    LOAD_CONFIG_FIELDS = {"eval_batch_size", "flash_attention", "offload_kv_cache_to_gpu", "num_experts"}
    ROLE_FINDINGS_FIELDS = {
        "recommendation_gate_met",
        "guidance",
        "aggregate_row_fields",
        "roles",
        "practical_defaults",
    }
    ROLE_FIELDS = {"role", "relative_best", "why", "caution"}
    PRACTICAL_DEFAULTS_FIELDS = {
        "small_context_workhorse",
        "next_cyber_code_candidate",
        "deep_candidate_to_retest",
        "auto_route_code_work",
    }
    RUNTIME_GUARD_FIELDS = {
        "max_model_runtime_seconds",
        "max_model_runtime_label",
        "estimate_inputs",
        "skip_result",
        "result_fields",
        "offload_targets",
        "eval_metadata_fields",
        "cli_override",
        "saved_artifacts_updated",
    }
    SKIP_RESULT_FIELDS = {"stage", "error", "load_state"}

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def load(self) -> ModelTuning:
        path = self.directory / self.FILENAME
        payload = load_yaml_file(path)
        validate_allowed_fields(payload, self.FIELDS, source=str(path))
        return ModelTuning(
            id=_text(payload.get("id"), source=f"{path}.id"),
            source_path=_text(payload.get("source_path"), source=f"{path}.source_path"),
            status=_text(payload.get("status"), source=f"{path}.status"),
            date=_text(payload.get("date"), source=f"{path}.date"),
            live_tuning=self._live_tuning(payload.get("live_tuning"), source=f"{path}.live_tuning"),
            execution_context=self._execution_context(
                payload.get("execution_context"), source=f"{path}.execution_context"
            ),
            models_checked=tuple(expect_string_list(payload.get("models_checked"), source=f"{path}.models_checked")),
            result=self._result(payload.get("result"), source=f"{path}.result"),
            best_configs=tuple(
                self._best_config(item, source=f"{path}.best_configs[{index}]")
                for index, item in enumerate(_list(payload.get("best_configs"), source=f"{path}.best_configs"))
            ),
            role_findings=self._role_findings(payload.get("role_findings"), source=f"{path}.role_findings"),
            runtime_guard=self._runtime_guard(payload.get("runtime_guard"), source=f"{path}.runtime_guard"),
            usage_commands=tuple(expect_string_list(payload.get("usage_commands"), source=f"{path}.usage_commands")),
        )

    def _live_tuning(self, payload: Any, *, source: str) -> LiveTuningConfig:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.LIVE_TUNING_FIELDS, source=source)
        return LiveTuningConfig(
            context_length=_int(data.get("context_length"), source=f"{source}.context_length"),
            max_tokens=_int(data.get("max_tokens"), source=f"{source}.max_tokens"),
            temperature=_number(data.get("temperature"), source=f"{source}.temperature"),
            cpu_reserve_mb=_int(data.get("cpu_reserve_mb"), source=f"{source}.cpu_reserve_mb"),
            vram_soft_reserve_mb=_int(data.get("vram_soft_reserve_mb"), source=f"{source}.vram_soft_reserve_mb"),
            timeout_seconds=_int(data.get("timeout_seconds"), source=f"{source}.timeout_seconds"),
        )

    def _execution_context(self, payload: Any, *, source: str) -> TuningExecutionContext:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.EXECUTION_CONTEXT_FIELDS, source=source)
        return TuningExecutionContext(
            runtime_cli_used=_bool(data.get("runtime_cli_used"), source=f"{source}.runtime_cli_used"),
            runtime_cli_skip_reason=_text(data.get("runtime_cli_skip_reason"), source=f"{source}.runtime_cli_skip_reason"),
            provider_level_tuner_used=_bool(
                data.get("provider_level_tuner_used"), source=f"{source}.provider_level_tuner_used"
            ),
            sampler_sources=tuple(expect_string_list(data.get("sampler_sources"), source=f"{source}.sampler_sources")),
        )

    def _result(self, payload: Any, *, source: str) -> TuningResult:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.RESULT_FIELDS, source=source)
        return TuningResult(
            status=_text(data.get("status"), source=f"{source}.status"),
            rows_recorded=_int(data.get("rows_recorded"), source=f"{source}.rows_recorded"),
            warnings=tuple(expect_string_list(data.get("warnings"), source=f"{source}.warnings")),
            detailed_artifact=_text(data.get("detailed_artifact"), source=f"{source}.detailed_artifact"),
            reusable_profile=_text(data.get("reusable_profile"), source=f"{source}.reusable_profile"),
            post_run_loaded_models_reported=_bool(
                data.get("post_run_loaded_models_reported"), source=f"{source}.post_run_loaded_models_reported"
            ),
        )

    def _best_config(self, payload: Any, *, source: str) -> BestModelConfig:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.BEST_CONFIG_FIELDS, source=source)
        return BestModelConfig(
            model=_text(data.get("model"), source=f"{source}.model"),
            tokens_per_second=_number(data.get("tokens_per_second"), source=f"{source}.tokens_per_second"),
            best_load_config=self._load_config(data.get("best_load_config"), source=f"{source}.best_load_config"),
        )

    def _load_config(self, payload: Any, *, source: str) -> LoadConfig:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.LOAD_CONFIG_FIELDS, source=source)
        return LoadConfig(
            eval_batch_size=_int(data.get("eval_batch_size"), source=f"{source}.eval_batch_size"),
            flash_attention=_bool(data.get("flash_attention"), source=f"{source}.flash_attention"),
            offload_kv_cache_to_gpu=_bool(
                data.get("offload_kv_cache_to_gpu"), source=f"{source}.offload_kv_cache_to_gpu"
            ),
            num_experts=_optional_int(data.get("num_experts"), source=f"{source}.num_experts"),
        )

    def _role_findings(self, payload: Any, *, source: str) -> RoleFindings:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.ROLE_FINDINGS_FIELDS, source=source)
        return RoleFindings(
            recommendation_gate_met=_bool(data.get("recommendation_gate_met"), source=f"{source}.recommendation_gate_met"),
            guidance=_text(data.get("guidance"), source=f"{source}.guidance"),
            aggregate_row_fields=tuple(
                expect_string_list(data.get("aggregate_row_fields"), source=f"{source}.aggregate_row_fields")
            ),
            roles=tuple(
                self._role_guidance(item, source=f"{source}.roles[{index}]")
                for index, item in enumerate(_list(data.get("roles"), source=f"{source}.roles"))
            ),
            practical_defaults=self._practical_defaults(
                data.get("practical_defaults"), source=f"{source}.practical_defaults"
            ),
        )

    def _role_guidance(self, payload: Any, *, source: str) -> RoleGuidance:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.ROLE_FIELDS, source=source)
        return RoleGuidance(
            role=_text(data.get("role"), source=f"{source}.role"),
            relative_best=tuple(expect_string_list(data.get("relative_best"), source=f"{source}.relative_best")),
            why=_text(data.get("why"), source=f"{source}.why"),
            caution=_text(data.get("caution"), source=f"{source}.caution"),
        )

    def _practical_defaults(self, payload: Any, *, source: str) -> PracticalDefaults:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.PRACTICAL_DEFAULTS_FIELDS, source=source)
        return PracticalDefaults(
            small_context_workhorse=_text(
                data.get("small_context_workhorse"), source=f"{source}.small_context_workhorse"
            ),
            next_cyber_code_candidate=_text(
                data.get("next_cyber_code_candidate"), source=f"{source}.next_cyber_code_candidate"
            ),
            deep_candidate_to_retest=_text(
                data.get("deep_candidate_to_retest"), source=f"{source}.deep_candidate_to_retest"
            ),
            auto_route_code_work=_bool(data.get("auto_route_code_work"), source=f"{source}.auto_route_code_work"),
        )

    def _runtime_guard(self, payload: Any, *, source: str) -> RuntimeGuard:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.RUNTIME_GUARD_FIELDS, source=source)
        return RuntimeGuard(
            max_model_runtime_seconds=_int(
                data.get("max_model_runtime_seconds"), source=f"{source}.max_model_runtime_seconds"
            ),
            max_model_runtime_label=_text(data.get("max_model_runtime_label"), source=f"{source}.max_model_runtime_label"),
            estimate_inputs=tuple(expect_string_list(data.get("estimate_inputs"), source=f"{source}.estimate_inputs")),
            skip_result=self._skip_result(data.get("skip_result"), source=f"{source}.skip_result"),
            result_fields=tuple(expect_string_list(data.get("result_fields"), source=f"{source}.result_fields")),
            offload_targets=tuple(expect_string_list(data.get("offload_targets"), source=f"{source}.offload_targets")),
            eval_metadata_fields=tuple(
                expect_string_list(data.get("eval_metadata_fields"), source=f"{source}.eval_metadata_fields")
            ),
            cli_override=_text(data.get("cli_override"), source=f"{source}.cli_override"),
            saved_artifacts_updated=tuple(
                expect_string_list(data.get("saved_artifacts_updated"), source=f"{source}.saved_artifacts_updated")
            ),
        )

    def _skip_result(self, payload: Any, *, source: str) -> RuntimeSkipResult:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.SKIP_RESULT_FIELDS, source=source)
        return RuntimeSkipResult(
            stage=_text(data.get("stage"), source=f"{source}.stage"),
            error=_text(data.get("error"), source=f"{source}.error"),
            load_state=_text(data.get("load_state"), source=f"{source}.load_state"),
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


def _int(value: Any, *, source: str) -> int:
    if type(value) is not int:
        raise CatalogValidationError(f"{source} must be an integer")
    return value


def _optional_int(value: Any, *, source: str) -> int | None:
    if value is None:
        return None
    return _int(value, source=source)


def _number(value: Any, *, source: str) -> float:
    if type(value) not in (int, float):
        raise CatalogValidationError(f"{source} must be a number")
    return float(value)


def _bool(value: Any, *, source: str) -> bool:
    if type(value) is not bool:
        raise CatalogValidationError(f"{source} must be a boolean")
    return value
