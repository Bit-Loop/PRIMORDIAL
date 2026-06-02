from __future__ import annotations

import json
from pathlib import Path
from threading import Thread

from primordial.core.domain.enums import AgentRole, MethodologyPhase, RiskTier, ScopeProfile, TaskKind
from primordial.core.domain.models import Task
from primordial.labs.ctf.trajectory import emit_attempt_trajectory, ingest_attempt_trajectory_summary
from tests.support import fixture_flag
from tests.test_workflow_common import WorkflowTestsBase


class AttemptTrajectoryTests(WorkflowTestsBase):
    def test_attempt_trajectory_persists_jsonl_rows_and_redacted_rag_chunk(self) -> None:
        raw_flag = fixture_flag("trajectory-redaction")
        target = self.runtime.register_target(
            handle="nyu-littlequery",
            profile=ScopeProfile.HACK_THE_BOX,
            assets=["http://127.0.0.1:8080/"],
            metadata={
                "ctf_completion_indicator": "autonomous_flags",
                "ctf_lab_id": "nyu-ctf-bench",
                "ctf_challenge_id": "littlequery",
                "ctf_category": "web",
                "ctf_repo_relpath_sha": "a" * 64,
                "ctf_attempt_id": "attempt:littlequery",
                "ctf_ground_truth_flag_sha256": "b" * 64,
                "local_ctf_autonomous": True,
            },
        )
        task = Task(
            target_id=target.id,
            phase=MethodologyPhase.ANALYSIS,
            kind=TaskKind.CTF_FLAG_CAPTURE,
            title="Run CTF trajectory fixture",
            summary="Capture a redacted attempt trajectory.",
            role=AgentRole.ANALYSIS_WORKER,
            risk_tier=RiskTier.MODERATE,
        )
        self.runtime.store.insert_task(task)

        emit_attempt_trajectory(
            store=self.runtime.store,
            runtime_dir=self.runtime.config.runtime_dir,
            task=task,
            kind="think",
            role=AgentRole.ANALYSIS_WORKER,
            payload={"response": "try a safe probe"},
        )

        threads = [
            Thread(
                target=emit_attempt_trajectory,
                kwargs={
                    "store": self.runtime.store,
                    "runtime_dir": self.runtime.config.runtime_dir,
                    "task": task,
                    "kind": "tool_call" if index == 0 else "observation",
                    "role": AgentRole.ANALYSIS_WORKER,
                    "payload": {"body": raw_flag, "path": "/login?token=secret-value"},
                },
            )
            for index in range(2)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        emit_attempt_trajectory(
            store=self.runtime.store,
            runtime_dir=self.runtime.config.runtime_dir,
            task=task,
            kind="verdict",
            role=AgentRole.ANALYSIS_WORKER,
            payload={"flag_verification": "verified", "captured": raw_flag},
        )
        artifact = ingest_attempt_trajectory_summary(
            store=self.runtime.store,
            runtime_dir=self.runtime.config.runtime_dir,
            target_id=target.id,
            attempt_id="attempt:littlequery",
            task_id=task.id,
            outcome="solved_verified",
            flag_verification="verified",
            ground_truth_flag_sha256="b" * 64,
        )

        rows = self.runtime.store.list_attempt_trajectories(target_id=target.id, attempt_id="attempt:littlequery", limit=10)
        jsonl_path = self.runtime.config.runtime_dir / "trajectories" / target.id / "attempt_littlequery.jsonl"
        jsonl_rows = [json.loads(line) for line in jsonl_path.read_text(encoding="utf-8").splitlines()]
        chunks = self.runtime.store.list_document_chunks(target_id=target.id, metadata_filters={"corpus_type": ["ctf_trajectory"]})
        retrieved = self.runtime.rag.retrieve("solved verified trajectory", target_id=target.id, corpus_types=["ctf_trajectory"])
        combined_chunks = "\n".join([chunk.text + json.dumps(chunk.metadata, sort_keys=True) for chunk in chunks])

        self.assertIsNotNone(artifact)
        self.assertEqual([row.step_index for row in rows], list(range(4)))
        self.assertEqual([row["step_index"] for row in jsonl_rows], list(range(4)))
        self.assertEqual({row.kind for row in rows}, {"think", "tool_call", "observation", "verdict"})
        self.assertTrue(chunks)
        self.assertTrue(retrieved)
        self.assertNotIn(raw_flag, json.dumps([row.as_payload() for row in rows]))
        self.assertNotIn(raw_flag, Path(artifact.path).read_text(encoding="utf-8"))
        self.assertNotIn(raw_flag, combined_chunks)
        self.assertIn("ground_truth_flag_sha256", chunks[0].metadata)
