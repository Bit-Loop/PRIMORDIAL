from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from primordial.core.catalog.loader import CatalogValidationError, expect_bool, expect_string_list, load_yaml_file, validate_allowed_fields


@dataclass(frozen=True, slots=True)
class V2FixtureCorpus:
    id: str
    fixtures: tuple[str, ...]
    expected_checks: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class V2IntentGatePolicyTest:
    intent_id: str
    allows: tuple[str, ...]
    blocks: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class V2PolicyTests:
    intent_gate_tests: tuple[V2IntentGatePolicyTest, ...]
    safety_regression_tests: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class V2ToolRunnerTests:
    baseline_contract: tuple[str, ...]
    required_runner_suites: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class V2ReverseEngineeringTestPlan:
    id: str
    source_path: str
    status: str
    loaded_by_v1_runtime: bool
    authority: str
    test_philosophy: tuple[str, ...]
    fixture_requirements: tuple[str, ...]
    acceptance_gates: tuple[str, ...]
    failure_modes: tuple[str, ...]
    fixture_corpus: tuple[V2FixtureCorpus, ...]
    policy_tests: V2PolicyTests
    tool_runner_tests: V2ToolRunnerTests
    hardware_bench_qualification: tuple[str, ...]
    release_criteria: tuple[str, ...]


class V2ReverseEngineeringTestPlanCatalog:
    FILENAME = "v2_reverse_engineering_test_plan.yaml"
    FIELDS = {
        "id",
        "source_path",
        "status",
        "loaded_by_v1_runtime",
        "authority",
        "test_philosophy",
        "fixture_requirements",
        "acceptance_gates",
        "failure_modes",
        "fixture_corpus",
        "policy_tests",
        "tool_runner_tests",
        "hardware_bench_qualification",
        "release_criteria",
    }
    FIXTURE_CORPUS_FIELDS = {"id", "fixtures", "expected_checks"}
    POLICY_TESTS_FIELDS = {"intent_gate_tests", "safety_regression_tests"}
    INTENT_GATE_TEST_FIELDS = {"intent_id", "allows", "blocks"}
    TOOL_RUNNER_TESTS_FIELDS = {"baseline_contract", "required_runner_suites"}

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def load(self) -> V2ReverseEngineeringTestPlan:
        path = self.directory / self.FILENAME
        payload = load_yaml_file(path)
        validate_allowed_fields(payload, self.FIELDS, source=str(path))
        source_path = _text(payload.get("source_path"), source=f"{path}.source_path")
        if not source_path.endswith(".md"):
            raise CatalogValidationError(f"{path}.source_path must reference a Markdown source")
        return V2ReverseEngineeringTestPlan(
            id=_text(payload.get("id"), source=f"{path}.id"),
            source_path=source_path,
            status=_text(payload.get("status"), source=f"{path}.status"),
            loaded_by_v1_runtime=expect_bool(
                payload.get("loaded_by_v1_runtime"), source=f"{path}.loaded_by_v1_runtime"
            ),
            authority=_text(payload.get("authority"), source=f"{path}.authority"),
            test_philosophy=tuple(expect_string_list(payload.get("test_philosophy"), source=f"{path}.test_philosophy")),
            fixture_requirements=tuple(
                expect_string_list(payload.get("fixture_requirements"), source=f"{path}.fixture_requirements")
            ),
            acceptance_gates=tuple(
                expect_string_list(payload.get("acceptance_gates"), source=f"{path}.acceptance_gates")
            ),
            failure_modes=tuple(expect_string_list(payload.get("failure_modes"), source=f"{path}.failure_modes")),
            fixture_corpus=tuple(
                self._fixture_corpus(item, source=f"{path}.fixture_corpus[{index}]")
                for index, item in enumerate(_list(payload.get("fixture_corpus"), source=f"{path}.fixture_corpus"))
            ),
            policy_tests=self._policy_tests(payload.get("policy_tests"), source=f"{path}.policy_tests"),
            tool_runner_tests=self._tool_runner_tests(
                payload.get("tool_runner_tests"), source=f"{path}.tool_runner_tests"
            ),
            hardware_bench_qualification=tuple(
                expect_string_list(
                    payload.get("hardware_bench_qualification"), source=f"{path}.hardware_bench_qualification"
                )
            ),
            release_criteria=tuple(
                expect_string_list(payload.get("release_criteria"), source=f"{path}.release_criteria")
            ),
        )

    def _fixture_corpus(self, payload: Any, *, source: str) -> V2FixtureCorpus:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.FIXTURE_CORPUS_FIELDS, source=source)
        return V2FixtureCorpus(
            id=_text(data.get("id"), source=f"{source}.id"),
            fixtures=tuple(expect_string_list(data.get("fixtures"), source=f"{source}.fixtures")),
            expected_checks=tuple(expect_string_list(data.get("expected_checks"), source=f"{source}.expected_checks")),
        )

    def _policy_tests(self, payload: Any, *, source: str) -> V2PolicyTests:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.POLICY_TESTS_FIELDS, source=source)
        return V2PolicyTests(
            intent_gate_tests=tuple(
                self._intent_gate_test(item, source=f"{source}.intent_gate_tests[{index}]")
                for index, item in enumerate(
                    _list(data.get("intent_gate_tests"), source=f"{source}.intent_gate_tests")
                )
            ),
            safety_regression_tests=tuple(
                expect_string_list(data.get("safety_regression_tests"), source=f"{source}.safety_regression_tests")
            ),
        )

    def _intent_gate_test(self, payload: Any, *, source: str) -> V2IntentGatePolicyTest:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.INTENT_GATE_TEST_FIELDS, source=source)
        return V2IntentGatePolicyTest(
            intent_id=_text(data.get("intent_id"), source=f"{source}.intent_id"),
            allows=tuple(expect_string_list(data.get("allows"), source=f"{source}.allows")),
            blocks=tuple(expect_string_list(data.get("blocks"), source=f"{source}.blocks")),
        )

    def _tool_runner_tests(self, payload: Any, *, source: str) -> V2ToolRunnerTests:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.TOOL_RUNNER_TESTS_FIELDS, source=source)
        return V2ToolRunnerTests(
            baseline_contract=tuple(
                expect_string_list(data.get("baseline_contract"), source=f"{source}.baseline_contract")
            ),
            required_runner_suites=tuple(
                expect_string_list(data.get("required_runner_suites"), source=f"{source}.required_runner_suites")
            ),
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
