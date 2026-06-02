from __future__ import annotations

import base64
import json
import subprocess
import unittest
from unittest.mock import patch

from tests.support import fixture_flag
from tests.test_workflow_common import *


class CTFLiveSolverCaptureTests(WorkflowTestsBase):
    def test_planner_schedules_ctf_flag_capture_for_local_lab_http_evidence(self) -> None:
        target = self.runtime.register_target(
            handle="local-ctf-lab",
            profile=ScopeProfile.HACK_THE_BOX,
            assets=["http://127.0.0.1:3100/"],
            metadata={
                "ctf_completion_indicator": "autonomous_flags",
                "ctf_target_url": "http://127.0.0.1:3100/",
                "local_ctf_autonomous": True,
            },
        )
        self.runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=target.id,
                type=EvidenceType.TOOL_OUTPUT,
                title="HTTP probe",
                summary="Local CTF HTTP surface is reachable.",
                source_ref="fixture://local-ctf-http",
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.8,
                freshness=0.9,
                metadata={"kind": "http_probe", "effective_url": "http://127.0.0.1:3100/", "status_code": 200},
            )
        )

        report = self.runtime.run_tick(max_executions=0)

        capture_tasks = [task for task in report.created_tasks if task.kind == TaskKind.CTF_FLAG_CAPTURE]
        self.assertEqual(len(capture_tasks), 1)
        self.assertEqual(capture_tasks[0].metadata["primitive_hint"], "ctf-flag-capture")
        self.assertTrue(capture_tasks[0].metadata["closed_book"])

    def test_planner_schedules_ctf_flag_capture_for_local_kubernetes_lab_metadata(self) -> None:
        target = self.runtime.register_target(
            handle="local-kubernetes-goat-lab",
            profile=ScopeProfile.HACK_THE_BOX,
            assets=["kubernetes://kind-primordial-k8s"],
            metadata={
                "ctf_completion_indicator": "autonomous_flags",
                "ctf_target_url": "kubernetes://kind-primordial-k8s",
                "ctf_kubeconfig": "/tmp/phase5-kind.yaml",
                "target_family": "kubernetes_goat",
                "local_ctf_autonomous": True,
            },
        )
        self.runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=target.id,
                type=EvidenceType.TOOL_OUTPUT,
                title="Kubernetes readiness",
                summary="Local Kubernetes Goat cluster is reachable.",
                source_ref="fixture://local-kubernetes-readiness",
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.8,
                freshness=0.9,
                metadata={"kind": "kubernetes_cluster_readiness", "kubeconfig": "/tmp/phase5-kind.yaml"},
            )
        )

        report = self.runtime.run_tick(max_executions=0)

        capture_tasks = [task for task in report.created_tasks if task.kind == TaskKind.CTF_FLAG_CAPTURE]
        self.assertEqual(len(capture_tasks), 1)
        self.assertEqual(capture_tasks[0].metadata["primitive_hint"], "ctf-flag-capture")
        self.assertTrue(capture_tasks[0].metadata["closed_book"])

    def test_executor_captures_redacted_flag_ref_without_persisting_raw_flag(self) -> None:
        target = self.runtime.register_target(
            handle="local-ctf-lab",
            profile=ScopeProfile.HACK_THE_BOX,
            assets=["http://127.0.0.1:3100/"],
            metadata={
                "ctf_completion_indicator": "autonomous_flags",
                "ctf_target_url": "http://127.0.0.1:3100/",
                "local_ctf_autonomous": True,
            },
        )
        task = Task(
            target_id=target.id,
            phase=MethodologyPhase.ANALYSIS,
            kind=TaskKind.CTF_FLAG_CAPTURE,
            title="Run closed-book CTF flag capture",
            summary="Search local CTF surfaces for a redacted flag reference.",
            role=AgentRole.ANALYSIS_WORKER,
            risk_tier=RiskTier.MODERATE,
            required_capabilities=["ctf-flag-capture", "flag-collection"],
            metadata={"primitive_hint": "ctf-flag-capture"},
        )
        raw_flag = fixture_flag("autonomous-capture")

        with patch(
            "primordial.modes.security.execution_ctf_handler.request.urlopen",
            return_value=_FakeHttpResponse("http://127.0.0.1:3100/", b"body " + raw_flag.encode("utf-8")),
        ):
            result = self.runtime.executor.execute(task, None)

        artifact_text = Path(result.artifacts[0].path).read_text(encoding="utf-8")
        evidence = result.evidence[0]
        note = result.notes[0]

        self.assertTrue(result.success)
        self.assertTrue(evidence.metadata["captured_flag_ref"].startswith("evidence:captured-flag:"))
        self.assertEqual(evidence.metadata["captured_flag_length"], len(raw_flag))
        self.assertIn("captured_flag_sha256", evidence.metadata)
        self.assertNotIn(raw_flag, artifact_text)
        self.assertNotIn(raw_flag, json.dumps(evidence.as_payload()))
        self.assertNotIn(raw_flag, note.body)

    def test_executor_records_browser_benchmark_solve_without_flag_material(self) -> None:
        target = self.runtime.register_target(
            handle="local-browser-lab",
            profile=ScopeProfile.HACK_THE_BOX,
            assets=["http://127.0.0.1:3100/"],
            metadata={
                "ctf_completion_indicator": "autonomous_flags",
                "ctf_target_url": "http://127.0.0.1:3100/",
                "local_ctf_autonomous": True,
            },
        )
        task = Task(
            target_id=target.id,
            phase=MethodologyPhase.ANALYSIS,
            kind=TaskKind.CTF_FLAG_CAPTURE,
            title="Run closed-book CTF benchmark interaction",
            summary="Use browser-rendered local CTF state to record benchmark solves.",
            role=AgentRole.ANALYSIS_WORKER,
            risk_tier=RiskTier.MODERATE,
            required_capabilities=["ctf-flag-capture", "flag-collection"],
            metadata={"primitive_hint": "ctf-flag-capture"},
        )
        state = {"solved": False}

        def browser_interaction(_executor, url: str) -> dict[str, object]:
            state["solved"] = True
            return {
                "url": url,
                "browser_available": True,
                "returncode": 0,
                "dom_sha256": "0" * 64,
                "dom_bytes": 123,
                "captured_flag_ref": "",
                "captured_flag_sha256": "",
                "captured_flag_length": 0,
            }

        with patch(
            "primordial.modes.security.execution_ctf_handler.request.urlopen",
            side_effect=_benchmark_urlopen(state),
        ), patch(
            "primordial.modes.security.execution.PrimitiveExecutor._ctf_browser_interaction",
            autospec=True,
            side_effect=browser_interaction,
        ):
            result = self.runtime.executor.execute(task, None)

        artifact_text = Path(result.artifacts[0].path).read_text(encoding="utf-8")
        evidence = result.evidence[0]

        self.assertTrue(result.success)
        self.assertEqual(evidence.metadata["captured_flag_ref"], "")
        self.assertTrue(evidence.metadata["benchmark_solve_ref"].startswith("evidence:benchmark-solve:"))
        self.assertEqual(evidence.metadata["benchmark_solved_count"], 1)
        self.assertEqual(evidence.metadata["benchmark_solved_challenges"][0]["key"], "publicRouteChallenge")
        self.assertIn("benchmark_solve_ref", artifact_text)
        self.assertNotIn("ctf{", artifact_text.lower())

    def test_executor_uses_vulhub_cve_metadata_for_redacted_traversal_flag_capture(self) -> None:
        target = self.runtime.register_target(
            handle="local-vulhub-lab",
            profile=ScopeProfile.HACK_THE_BOX,
            assets=["http://127.0.0.1:3180/"],
            metadata={
                "ctf_completion_indicator": "autonomous_flags",
                "ctf_target_url": "http://127.0.0.1:3180/",
                "local_ctf_autonomous": True,
                "target_family": "vulhub_cve_labs",
                "vulnerability_cve_id": "CVE-2021-41773",
                "ctf_flag_container_path": "/primordial_flag.txt",
            },
        )
        task = Task(
            target_id=target.id,
            phase=MethodologyPhase.ANALYSIS,
            kind=TaskKind.CTF_FLAG_CAPTURE,
            title="Run closed-book Vulhub CTF flag capture",
            summary="Use local CVE evidence to attempt a redacted flag capture.",
            role=AgentRole.ANALYSIS_WORKER,
            risk_tier=RiskTier.MODERATE,
            required_capabilities=["ctf-flag-capture", "flag-collection"],
            metadata={"primitive_hint": "ctf-flag-capture"},
        )
        raw_flag = fixture_flag("vulhub-cve-traversal")
        requested_urls: list[str] = []

        with patch(
            "primordial.modes.security.execution_ctf_handler.request.urlopen",
            side_effect=_vulhub_urlopen(raw_flag, requested_urls),
        ):
            result = self.runtime.executor.execute(task, None)

        artifact_text = Path(result.artifacts[0].path).read_text(encoding="utf-8")
        evidence = result.evidence[0]

        self.assertTrue(result.success)
        self.assertTrue(any(".%2e" in url and "primordial_flag.txt" in url for url in requested_urls))
        self.assertTrue(evidence.metadata["captured_flag_ref"].startswith("evidence:captured-flag:"))
        self.assertEqual(evidence.metadata["captured_flag_length"], len(raw_flag))
        self.assertIn("CVE-2021-41773", json.dumps(target.metadata))
        self.assertNotIn(raw_flag, artifact_text)
        self.assertNotIn(raw_flag, json.dumps(evidence.as_payload()))

    def test_executor_captures_redacted_lab_prefixed_flag_format(self) -> None:
        target = self.runtime.register_target(
            handle="local-mbptl-lab",
            profile=ScopeProfile.HACK_THE_BOX,
            assets=["http://127.0.0.1:3183/"],
            metadata={
                "ctf_completion_indicator": "autonomous_flags",
                "ctf_target_url": "http://127.0.0.1:3183/",
                "local_ctf_autonomous": True,
            },
        )
        task = Task(
            target_id=target.id,
            phase=MethodologyPhase.ANALYSIS,
            kind=TaskKind.CTF_FLAG_CAPTURE,
            title="Run closed-book lab-prefixed CTF flag capture",
            summary="Search local CTF surfaces for a redacted lab-prefixed flag reference.",
            role=AgentRole.ANALYSIS_WORKER,
            risk_tier=RiskTier.MODERATE,
            required_capabilities=["ctf-flag-capture", "flag-collection"],
            metadata={"primitive_hint": "ctf-flag-capture"},
        )
        raw_flag = "MBPTL-" + "9" + "{" + "synthetic-lab-format" + "}"

        with patch(
            "primordial.modes.security.execution_ctf_handler.request.urlopen",
            return_value=_FakeHttpResponse("http://127.0.0.1:3183/", b"body " + raw_flag.encode("utf-8")),
        ):
            result = self.runtime.executor.execute(task, None)

        artifact_text = Path(result.artifacts[0].path).read_text(encoding="utf-8")
        evidence = result.evidence[0]

        self.assertTrue(result.success)
        self.assertTrue(evidence.metadata["captured_flag_ref"].startswith("evidence:captured-flag:"))
        self.assertEqual(evidence.metadata["captured_flag_length"], len(raw_flag))
        self.assertNotIn(raw_flag, artifact_text)
        self.assertNotIn(raw_flag, json.dumps(evidence.as_payload()))

    def test_executor_searches_metadata_service_urls_for_local_ctf_flags(self) -> None:
        target = self.runtime.register_target(
            handle="local-cicd-goat-lab",
            profile=ScopeProfile.HACK_THE_BOX,
            assets=["http://127.0.0.1:38000/"],
            metadata={
                "ctf_completion_indicator": "autonomous_flags",
                "ctf_target_url": "http://127.0.0.1:38000/",
                "ctf_service_urls": ["http://127.0.0.1:38080/"],
                "local_ctf_autonomous": True,
            },
        )
        task = Task(
            target_id=target.id,
            phase=MethodologyPhase.ANALYSIS,
            kind=TaskKind.CTF_FLAG_CAPTURE,
            title="Run closed-book multi-service CTF flag capture",
            summary="Search local service URLs for a redacted flag reference.",
            role=AgentRole.ANALYSIS_WORKER,
            risk_tier=RiskTier.MODERATE,
            required_capabilities=["ctf-flag-capture", "flag-collection"],
            metadata={"primitive_hint": "ctf-flag-capture"},
        )
        raw_flag = fixture_flag("cicd-service-url")
        requested_urls: list[str] = []

        with patch(
            "primordial.modes.security.execution_ctf_handler.request.urlopen",
            side_effect=_service_urlopen(raw_flag, requested_urls),
        ):
            result = self.runtime.executor.execute(task, None)

        artifact_text = Path(result.artifacts[0].path).read_text(encoding="utf-8")
        evidence = result.evidence[0]

        self.assertTrue(result.success)
        self.assertTrue(any(url.startswith("http://127.0.0.1:38080/") for url in requested_urls))
        self.assertTrue(evidence.metadata["captured_flag_ref"].startswith("evidence:captured-flag:"))
        self.assertNotIn(raw_flag, artifact_text)
        self.assertNotIn(raw_flag, json.dumps(evidence.as_payload()))

    def test_executor_captures_redacted_kubernetes_secret_flag(self) -> None:
        target = self.runtime.register_target(
            handle="local-kubernetes-goat-lab",
            profile=ScopeProfile.HACK_THE_BOX,
            assets=["kubernetes://kind-primordial-k8s"],
            metadata={
                "ctf_completion_indicator": "autonomous_flags",
                "ctf_target_url": "kubernetes://kind-primordial-k8s",
                "ctf_kubeconfig": "/tmp/phase5-kind.yaml",
                "ctf_tools_bin": "/tmp/tools/bin",
                "target_family": "kubernetes_goat",
                "local_ctf_autonomous": True,
            },
        )
        task = Task(
            target_id=target.id,
            phase=MethodologyPhase.ANALYSIS,
            kind=TaskKind.CTF_FLAG_CAPTURE,
            title="Run closed-book Kubernetes CTF flag capture",
            summary="Search local Kubernetes lab state for a redacted flag reference.",
            role=AgentRole.ANALYSIS_WORKER,
            risk_tier=RiskTier.MODERATE,
            required_capabilities=["ctf-flag-capture", "flag-collection"],
            metadata={"primitive_hint": "ctf-flag-capture"},
        )
        raw_flag = fixture_flag("kubernetes-secret")

        with patch(
            "primordial.modes.security.execution_ctf_handler.Path.is_file",
            return_value=True,
        ), patch(
            "primordial.modes.security.execution_ctf_handler.subprocess.run",
            side_effect=_kubectl_run(raw_flag),
        ):
            result = self.runtime.executor.execute(task, None)

        artifact_text = Path(result.artifacts[0].path).read_text(encoding="utf-8")
        evidence = result.evidence[0]

        self.assertTrue(result.success)
        self.assertEqual(evidence.metadata["kubernetes_probe_count"], 2)
        self.assertTrue(evidence.metadata["captured_flag_ref"].startswith("evidence:captured-flag:"))
        self.assertEqual(evidence.metadata["captured_flag_length"], len(raw_flag))
        self.assertNotIn(raw_flag, artifact_text)
        self.assertNotIn(raw_flag, json.dumps(evidence.as_payload()))


class _FakeHttpResponse:
    def __init__(self, url: str, body: bytes) -> None:
        self.status = 200
        self.headers = {}
        self._url = url
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def read(self, _limit: int) -> bytes:
        return self._body

    def geturl(self) -> str:
        return self._url


def _benchmark_urlopen(state: dict[str, bool]):
    def open_url(request_obj, *args, **kwargs):
        url = request_obj.full_url if hasattr(request_obj, "full_url") else str(request_obj)
        if url.endswith("/rest/admin/application-configuration"):
            body = {
                "config": {
                    "application": {
                        "securityTxt": {
                            "acknowledgements": "/#/score-board",
                        }
                    }
                }
            }
            return _FakeHttpResponse(url, json.dumps(body).encode("utf-8"))
        if url.endswith("/api/Challenges"):
            body = {
                "data": [
                    {
                        "key": "publicRouteChallenge",
                        "name": "Public Route",
                        "category": "Miscellaneous",
                        "difficulty": 1,
                        "solved": state["solved"],
                    }
                ]
            }
            return _FakeHttpResponse(url, json.dumps(body).encode("utf-8"))
        return _FakeHttpResponse(url, b"no flag here")

    return open_url


def _vulhub_urlopen(raw_flag: str, requested_urls: list[str]):
    def open_url(request_obj, *args, **kwargs):
        url = request_obj.full_url if hasattr(request_obj, "full_url") else str(request_obj)
        requested_urls.append(url)
        if ".%2e" in url and url.endswith("/primordial_flag.txt"):
            return _FakeHttpResponse(url, raw_flag.encode("utf-8"))
        return _FakeHttpResponse(url, b"vulnerable apache lab")

    return open_url


def _service_urlopen(raw_flag: str, requested_urls: list[str]):
    def open_url(request_obj, *args, **kwargs):
        url = request_obj.full_url if hasattr(request_obj, "full_url") else str(request_obj)
        requested_urls.append(url)
        if url == "http://127.0.0.1:38080/":
            return _FakeHttpResponse(url, raw_flag.encode("utf-8"))
        return _FakeHttpResponse(url, b"local service")

    return open_url


def _kubectl_run(raw_flag: str):
    def run(command, *args, **kwargs):
        if "secrets" in command:
            body = {
                "items": [
                    {
                        "data": {
                            "flag": base64.b64encode(raw_flag.encode("utf-8")).decode("ascii"),
                        }
                    }
                ]
            }
            return subprocess.CompletedProcess(command, 0, json.dumps(body), "")
        return subprocess.CompletedProcess(command, 0, json.dumps({"items": []}), "")

    return run


if __name__ == "__main__":
    unittest.main()
