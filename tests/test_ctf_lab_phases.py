from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from primordial.core.catalog.loader import CatalogValidationError, load_yaml_file
from primordial.labs.ctf import load_ctf_lab_phase_catalog


REPO_ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = REPO_ROOT / "catalog" / "labs" / "ctf_lab_phases.yaml"


class CTFLabPhaseCatalogTests(unittest.TestCase):
    def test_lab_phase_catalog_tracks_required_phases_in_order(self) -> None:
        catalog = load_ctf_lab_phase_catalog(CATALOG_PATH)

        self.assertEqual(catalog.version, 1)
        self.assertEqual([phase.number for phase in catalog.phases], list(range(9)))
        self.assertEqual(catalog.phase(0).id, "phase_0_harness_first")
        self.assertEqual(catalog.phase(1).name, "Phase 1 Juice Shop")
        self.assertEqual(catalog.phase(8).name, "Phase 8 DreadGOAD/CTF-Dojo/NYU CTF Bench")

    def test_phase_zero_has_harness_first_validation_gates(self) -> None:
        phase = load_ctf_lab_phase_catalog(CATALOG_PATH).phase(0)
        commands = "\n".join(phase.validation_commands)

        self.assertEqual(phase.status, "ready_for_review")
        self.assertFalse(phase.environment_proof_required)
        self.assertTrue(phase.deterministic_fixture_required)
        self.assertIn("ctf_target_manifest_contracts_pass", phase.exit_gates)
        self.assertIn("hidden_material_and_hardcode_gates_pass", phase.exit_gates)
        self.assertIn("tests.test_ctf_harness_targets", commands)
        self.assertIn("primordial.core.quality.hardcode", commands)

    def test_phase_one_juice_shop_tracks_ready_for_review_evidence(self) -> None:
        phase = load_ctf_lab_phase_catalog(CATALOG_PATH).phase(1)
        commands = "\n".join(phase.validation_commands)

        self.assertEqual(phase.status, "ready_for_review")
        self.assertTrue(phase.environment_proof_required)
        self.assertTrue(phase.deterministic_fixture_required)
        self.assertIn("local_container_environment_verified", phase.exit_gates)
        self.assertIn("closed_book_ctfd_export_loaded_without_flags", phase.exit_gates)
        self.assertIn("solve_attempts_scored_without_writeup_access", phase.exit_gates)
        self.assertEqual(
            phase.verified_environment_refs,
            ("evidence:local-container:14fdf1d29253565a", "evidence:docker-run-reset-teardown"),
        )
        self.assertIn("github_pr:32", phase.evidence_refs)
        self.assertIn("github_pr:31", phase.evidence_refs)
        self.assertIn("github_pr:30", phase.evidence_refs)
        self.assertIn("github_pr:29", phase.evidence_refs)
        self.assertIn("tests.test_ctf_harness_environment", commands)
        self.assertIn("tests.test_ctf_harness_benchmark", commands)
        self.assertIn("primordial.core.quality.hardcode", commands)

    def test_phase_two_vulhub_tracks_ready_for_review_live_lab_evidence(self) -> None:
        phase = load_ctf_lab_phase_catalog(CATALOG_PATH).phase(2)
        commands = "\n".join(phase.validation_commands)

        self.assertEqual(phase.status, "ready_for_review")
        self.assertTrue(phase.environment_proof_required)
        self.assertTrue(phase.deterministic_fixture_required)
        self.assertIn("local_container_environment_verified", phase.exit_gates)
        self.assertIn("cve_target_manifests_include_versions_and_scope", phase.exit_gates)
        self.assertIn("exploit_applicability_checked_against_observed_evidence", phase.exit_gates)
        self.assertEqual(
            phase.verified_environment_refs,
            ("evidence:local-container:a7baaf34f20aba58", "evidence:docker-run-reset-teardown"),
        )
        self.assertIn("github_pr:33", phase.evidence_refs)
        self.assertIn("github_pr:34", phase.evidence_refs)
        self.assertIn("github_pr:35", phase.evidence_refs)
        self.assertIn("evidence:local-container:a7baaf34f20aba58", phase.evidence_refs)
        self.assertIn("evidence:docker-run-reset-teardown", phase.evidence_refs)
        self.assertIn("tests.test_ctf_harness_environment", commands)
        self.assertIn("tests.test_ctf_harness_applicability", commands)
        self.assertIn("tests.test_ctf_harness_targets", commands)

    def test_phase_three_mbptl_tracks_manifest_loading_progress_without_live_lab_claim(self) -> None:
        phase = load_ctf_lab_phase_catalog(CATALOG_PATH).phase(3)
        commands = "\n".join(phase.validation_commands)

        self.assertEqual(phase.status, "in_progress")
        self.assertTrue(phase.environment_proof_required)
        self.assertTrue(phase.deterministic_fixture_required)
        self.assertIn("phase_targets_loaded_from_manifests", phase.exit_gates)
        self.assertEqual(phase.verified_environment_refs, ())
        self.assertIn("tests.test_ctf_harness_phase_targets", commands)

    def test_remaining_lab_phases_require_verified_environment_proof_before_completion(self) -> None:
        catalog = load_ctf_lab_phase_catalog(CATALOG_PATH)

        for phase in catalog.phases[4:]:
            self.assertTrue(phase.environment_proof_required)
            self.assertTrue(phase.deterministic_fixture_required)
            self.assertNotEqual(phase.status, "complete")
            self.assertEqual(phase.verified_environment_refs, ())
            self.assertEqual(phase.evidence_refs, ())

    def test_lab_phase_catalog_rejects_missing_required_phase(self) -> None:
        payload = load_yaml_file(CATALOG_PATH)
        payload["phases"] = payload["phases"][:-1]

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "ctf_lab_phases.yaml"
            path.write_text(_yaml_dump(payload), encoding="utf-8")

            with self.assertRaisesRegex(CatalogValidationError, "required lab phases"):
                load_ctf_lab_phase_catalog(path)

    def test_lab_phase_catalog_rejects_complete_phase_without_evidence(self) -> None:
        payload = load_yaml_file(CATALOG_PATH)
        payload["phases"][1]["status"] = "complete"
        payload["phases"][1]["validation_commands"] = ["python3 -m unittest tests.test_ctf_harness_targets -q"]
        payload["phases"][1]["verified_environment_refs"] = []
        payload["phases"][1]["evidence_refs"] = []

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "ctf_lab_phases.yaml"
            path.write_text(_yaml_dump(payload), encoding="utf-8")

            with self.assertRaisesRegex(CatalogValidationError, "verified_environment_refs"):
                load_ctf_lab_phase_catalog(path)


def _yaml_dump(payload: object) -> str:
    import yaml

    return yaml.safe_dump(payload, sort_keys=False)


if __name__ == "__main__":
    unittest.main()
