from __future__ import annotations

import json
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


if __name__ == "__main__":
    unittest.main()
