from __future__ import annotations

from pathlib import Path
import unittest

from primordial.labs.ctf import (
    load_ctf_lab_phase_catalog,
    load_ctf_target_manifest,
    verify_benchmark_environment,
    verify_benchmark_phase_controls,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = REPO_ROOT / "catalog" / "labs" / "ctf_lab_phases.yaml"


class CTFHarnessBenchmarkPhaseTests(unittest.TestCase):
    def test_benchmark_controls_require_rotation_reset_and_scoring_evidence(self) -> None:
        phase = load_ctf_lab_phase_catalog(CATALOG_PATH).phase(8)
        target = _benchmark_target()
        environment = verify_benchmark_environment(
            target,
            observed_assets=["ctf-dojo-target-a", "ctf-dojo-target-b"],
            evidence_refs=["evidence:benchmark-env", "evidence:benchmark-reset-a", "evidence:benchmark-reset-b"],
            reset_evidence_ref="evidence:benchmark-reset-a",
            profile="co_internal_lab",
            target_rotation=["ctf-dojo-target-a", "ctf-dojo-target-b"],
            observations={"runner": {"mode": "local_fixture"}},
        )

        result = verify_benchmark_phase_controls(
            phase,
            target,
            environment_proof=environment,
            target_rotation=[
                {
                    "id": "ctf-dojo-target-a",
                    "target_id": target.id,
                    "asset": "ctf-dojo-target-a",
                    "reset_evidence_ref": "evidence:benchmark-reset-a",
                    "evidence_ids": ["evidence:benchmark-env", "evidence:benchmark-reset-a"],
                },
                {
                    "id": "ctf-dojo-target-b",
                    "target_id": target.id,
                    "asset": "ctf-dojo-target-b",
                    "reset_evidence_ref": "evidence:benchmark-reset-b",
                    "evidence_ids": ["evidence:benchmark-env", "evidence:benchmark-reset-b"],
                },
            ],
            scoring_results=[
                {
                    "id": "score-a",
                    "target_ref": "ctf-dojo-target-a",
                    "score": 1.0,
                    "evidence_ids": ["evidence:benchmark-env"],
                },
                {
                    "id": "score-b",
                    "target_ref": "ctf-dojo-target-b",
                    "score": 0.5,
                    "evidence_ids": ["evidence:benchmark-env"],
                },
            ],
        )

        self.assertEqual(result.target_id, "ctf-dojo-benchmark-local")
        self.assertEqual(result.status, "verified")
        self.assertEqual(result.rotation_ids, ("ctf-dojo-target-a", "ctf-dojo-target-b"))
        self.assertEqual(result.scoring_result_ids, ("score-a", "score-b"))
        self.assertIn("benchmark_environment_verified", result.exit_gates)
        self.assertIn("target_rotation_and_reset_verified", result.exit_gates)
        self.assertIn("aggregate_scoring_uses_evidence_backed_results", result.exit_gates)
        self.assertIn("evidence:benchmark-reset-b", result.evidence_refs)

    def test_benchmark_controls_reject_missing_scoring_evidence(self) -> None:
        phase = load_ctf_lab_phase_catalog(CATALOG_PATH).phase(8)
        target = _benchmark_target()
        environment = verify_benchmark_environment(
            target,
            observed_assets=["ctf-dojo-target-a", "ctf-dojo-target-b"],
            evidence_refs=["evidence:benchmark-env", "evidence:benchmark-reset-a", "evidence:benchmark-reset-b"],
            reset_evidence_ref="evidence:benchmark-reset-a",
            profile="co_internal_lab",
            target_rotation=["ctf-dojo-target-a", "ctf-dojo-target-b"],
        )

        with self.assertRaisesRegex(ValueError, "evidence"):
            verify_benchmark_phase_controls(
                phase,
                target,
                environment_proof=environment,
                target_rotation=[
                    {
                        "id": "ctf-dojo-target-a",
                        "target_id": target.id,
                        "asset": "ctf-dojo-target-a",
                        "reset_evidence_ref": "evidence:benchmark-reset-a",
                        "evidence_ids": ["evidence:benchmark-env", "evidence:benchmark-reset-a"],
                    },
                    {
                        "id": "ctf-dojo-target-b",
                        "target_id": target.id,
                        "asset": "ctf-dojo-target-b",
                        "reset_evidence_ref": "evidence:benchmark-reset-b",
                        "evidence_ids": ["evidence:benchmark-env", "evidence:benchmark-reset-b"],
                    }
                ],
                scoring_results=[
                    {
                        "id": "score-a",
                        "target_ref": "ctf-dojo-target-a",
                        "score": 1.0,
                        "evidence_ids": [],
                    },
                    {
                        "id": "score-b",
                        "target_ref": "ctf-dojo-target-b",
                        "score": 0.5,
                        "evidence_ids": ["evidence:benchmark-env"],
                    }
                ],
            )

    def test_benchmark_controls_reject_rotation_asset_outside_scope(self) -> None:
        phase = load_ctf_lab_phase_catalog(CATALOG_PATH).phase(8)
        target = _benchmark_target()
        environment = verify_benchmark_environment(
            target,
            observed_assets=["ctf-dojo-target-a", "ctf-dojo-target-b"],
            evidence_refs=["evidence:benchmark-env", "evidence:benchmark-reset-a", "evidence:benchmark-reset-b"],
            reset_evidence_ref="evidence:benchmark-reset-a",
            profile="co_internal_lab",
            target_rotation=["ctf-dojo-target-a", "ctf-dojo-target-b"],
        )

        with self.assertRaisesRegex(ValueError, "lab scope"):
            verify_benchmark_phase_controls(
                phase,
                target,
                environment_proof=environment,
                target_rotation=[
                    {
                        "id": "ctf-dojo-target-a",
                        "target_id": target.id,
                        "asset": "public-ctf.example.com",
                        "reset_evidence_ref": "evidence:benchmark-reset-a",
                        "evidence_ids": ["evidence:benchmark-env", "evidence:benchmark-reset-a"],
                    },
                    {
                        "id": "ctf-dojo-target-b",
                        "target_id": target.id,
                        "asset": "ctf-dojo-target-b",
                        "reset_evidence_ref": "evidence:benchmark-reset-b",
                        "evidence_ids": ["evidence:benchmark-env", "evidence:benchmark-reset-b"],
                    }
                ],
                scoring_results=[
                    {
                        "id": "score-a",
                        "target_ref": "ctf-dojo-target-a",
                        "score": 1.0,
                        "evidence_ids": ["evidence:benchmark-env"],
                    },
                    {
                        "id": "score-b",
                        "target_ref": "ctf-dojo-target-b",
                        "score": 0.5,
                        "evidence_ids": ["evidence:benchmark-env"],
                    }
                ],
            )


def _benchmark_target():
    return load_ctf_target_manifest(
        {
            "lab_id": "ctf-dojo-benchmark-local",
            "title": "CTF-Dojo Benchmark Local",
            "platform": "benchmark",
            "category": "benchmark",
            "difficulty": "advanced",
            "target_family": "ctf_dojo",
            "source": {
                "repo_url": "https://github.com/NYU-LLM-CTF/nyu-ctf-bench",
                "path": "benchmarks",
            },
            "scope": {
                "network": "local-benchmark-fixtures",
                "assets": ["ctf-dojo-target-a", "ctf-dojo-target-b"],
            },
            "provisioning": {
                "mode": "benchmark",
                "network": "local-benchmark-fixtures",
            },
            "evidence": {"required": ["target_rotation", "reset_evidence", "scoring_evidence"]},
            "policy": {"default_intent": "recon_only"},
        }
    )


if __name__ == "__main__":
    unittest.main()
