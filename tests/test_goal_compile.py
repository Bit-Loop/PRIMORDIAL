from __future__ import annotations

import io
import json
import shutil
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
import unittest

import yaml

from tools import goal_compile


REPO_ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_CURRENT_KEYS = {
    "raw_target_evidence",
    "target_evidence",
    "secrets",
    "secret",
    "credentials",
    "credential",
    "flags",
    "flag",
    "raw_flags",
    "request_bodies",
    "request_body",
    "sensitive_payloads",
    "payload",
}


class GoalCompileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        shutil.copytree(REPO_ROOT / "goal", self.root / "goal")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_list_shows_slice_packs(self) -> None:
        result, output = _run_goal_compile("--root", str(self.root), "--list")

        self.assertEqual(result, 0)
        self.assertIn("compiler-bootstrap", output)

    def test_selected_slice_pack_emits_compact_instruct_and_current_pointer(self) -> None:
        result, _ = _run_goal_compile("--root", str(self.root), "--slice-pack", "compiler-bootstrap")

        self.assertEqual(result, 0)
        instruct = (self.root / "codex-goal.instruct").read_text(encoding="utf-8")
        current = json.loads((self.root / ".goal" / "current.json").read_text(encoding="utf-8"))

        self.assertIn("Active slice pack: compiler-bootstrap", instruct)
        self.assertIn("Program milestone coverage:", instruct)
        self.assertIn("Missing slice-pack coverage: none", instruct)
        self.assertIn("Fully complete milestones: M0, M1, M2, M3, M7", instruct)
        self.assertIn("Not fully complete milestones: M4, M5, M6, M8", instruct)
        self.assertIn("Milestone progress:", instruct)
        self.assertIn("- M0 100% fully_complete", instruct)
        self.assertIn("RUN_DONE closes this invocation after the selected run slices are validated", instruct)
        self.assertLess(len(instruct), 12_000)
        self.assertEqual(current["active_slice_pack"], "compiler-bootstrap")
        self.assertEqual(current["active_milestones"], ["M0", "M4", "M8"])
        self.assertEqual(current["missing_milestones"], [])
        self.assertEqual(current["fully_complete_milestones"], ["M0", "M1", "M2", "M3", "M7"])
        self.assertEqual(
            current["not_fully_complete_milestones"],
            ["M4", "M5", "M6", "M8"],
        )
        self.assertEqual(current["milestone_progress"]["M0"]["completion_percent"], 100)
        self.assertTrue(current["milestone_progress"]["M0"]["evidence"])
        self.assertEqual(current["validation_tier"], "V2")
        provenance = current["generated_output_provenance"]["codex-goal.instruct"]
        self.assertEqual(sorted(provenance), ["generated_size_bytes"])
        self.assertGreater(provenance["generated_size_bytes"], 0)

    def test_current_json_exposes_partial_milestone_progress_and_evidence(self) -> None:
        result, _ = _run_goal_compile("--root", str(self.root), "--slice-pack", "context-boundaries")

        self.assertEqual(result, 0)
        current = json.loads((self.root / ".goal" / "current.json").read_text(encoding="utf-8"))

        self.assertEqual(current["overall_completion_percent"], 75)
        self.assertEqual(current["partially_complete_milestones"], ["M4", "M5", "M6", "M8"])
        self.assertEqual(current["milestone_progress"]["M1"]["completion_percent"], 100)
        self.assertEqual(current["milestone_progress"]["M1"]["status"], "fully_complete")
        self.assertTrue(current["milestone_progress"]["M1"]["evidence"])
        self.assertEqual(current["milestone_progress"]["M8"]["completion_percent"], 15)

    def test_generated_instruct_includes_multi_slice_batch_limit_and_active_slices(self) -> None:
        result, _ = _run_goal_compile("--root", str(self.root), "--slice-pack", "context-boundaries")

        self.assertEqual(result, 0)
        instruct = (self.root / "codex-goal.instruct").read_text(encoding="utf-8")
        current = json.loads((self.root / ".goal" / "current.json").read_text(encoding="utf-8"))

        self.assertIn("Max slices per run: 6", instruct)
        self.assertIn("Selected run slices:", instruct)
        self.assertIn("- context_boundary_hardening", instruct)
        self.assertEqual(current["slice_run_limit"], 6)
        self.assertEqual(
            current["active_slices"],
            [
                "context_boundary_hardening",
                "export_cleanup_boundaries",
                "sync_architecture_boundaries",
                "modular_context_refactor",
            ],
        )
        self.assertEqual(current["next_slice_pack"], "ctf-harness-controls")
        self.assertTrue(current["active_pack_complete"])
        self.assertTrue(current["advance_ready"])

    def test_generated_instruct_defines_bounded_run_done_contract(self) -> None:
        result, _ = _run_goal_compile("--root", str(self.root), "--slice-pack", "context-boundaries")

        self.assertEqual(result, 0)
        instruct = (self.root / "codex-goal.instruct").read_text(encoding="utf-8")

        self.assertIn("Run completion contract:", instruct)
        self.assertIn("This contract is for one bounded `/goal` invocation.", instruct)
        self.assertIn("RUN_DONE closes this invocation after the selected run slices are validated", instruct)
        self.assertIn("Do not self-continue after RUN_DONE", instruct)
        self.assertIn("PROGRAM_DONE remains reserved for all typed milestones", instruct)

    def test_prompt_goal_uses_advance_and_bounded_run_done(self) -> None:
        prompt = (REPO_ROOT / "prompt.goal").read_text(encoding="utf-8")

        self.assertIn("python3 tools/goal_compile.py --advance", prompt)
        self.assertIn("RUN_DONE closes the current `/goal` invocation", prompt)
        self.assertIn("Do not self-continue after RUN_DONE", prompt)
        self.assertNotIn("No `RUN_DONE` while milestone work remains", prompt)

    def test_advance_from_current_selects_next_incomplete_pack_after_completed_active_pack(self) -> None:
        _run_goal_compile("--root", str(self.root), "--slice-pack", "context-boundaries")
        milestones_path = self.root / "goal" / "fragments" / "milestones.yaml"
        data = _read_yaml(milestones_path)
        for milestone in data["milestones"]:
            if milestone["id"] in {"M1", "M2", "M3", "M7"}:
                milestone["status"] = "fully_complete"
                milestone["completion_percent"] = 100
                milestone["evidence"] = [f"completed evidence for {milestone['id']}"]
        _write_yaml(milestones_path, data)

        result, output = _run_goal_compile("--root", str(self.root), "--advance")

        self.assertEqual(result, 0)
        self.assertIn("wrote codex-goal.instruct", output)
        current = json.loads((self.root / ".goal" / "current.json").read_text(encoding="utf-8"))
        self.assertEqual(current["active_slice_pack"], "ctf-harness-controls")
        self.assertEqual(current["active_milestones"], ["M5", "M6"])

    def test_non_bootstrap_slice_pack_does_not_emit_bootstrap_specific_markdown_rule(self) -> None:
        result, _ = _run_goal_compile("--root", str(self.root), "--slice-pack", "context-boundaries")

        self.assertEqual(result, 0)
        instruct = (self.root / "codex-goal.instruct").read_text(encoding="utf-8")

        self.assertIn("Active slice pack: context-boundaries", instruct)
        self.assertNotIn("compiler-bootstrap slice", instruct)
        self.assertIn("Do not archive Markdown unless the active slice explicitly requires it.", instruct)

    def test_slice_pack_validation_commands_include_expected_test_modules(self) -> None:
        result, _ = _run_goal_compile("--root", str(self.root), "--slice-pack", "context-boundaries")

        self.assertEqual(result, 0)
        instruct = (self.root / "codex-goal.instruct").read_text(encoding="utf-8")

        self.assertIn(
            "- python3 -m unittest tests.test_context_assembler tests.test_context_sinks "
            "tests.test_rag tests.test_rag_import_validation -q",
            instruct,
        )

    def test_from_current_recompiles_active_slice_pack(self) -> None:
        _run_goal_compile("--root", str(self.root), "--slice-pack", "compiler-bootstrap")
        (self.root / "codex-goal.instruct").write_text("stale\n", encoding="utf-8")

        result, output = _run_goal_compile("--root", str(self.root), "--from-current")

        self.assertEqual(result, 0)
        self.assertIn("wrote codex-goal.instruct", output)
        instruct = (self.root / "codex-goal.instruct").read_text(encoding="utf-8")
        self.assertIn("Active slice pack: compiler-bootstrap", instruct)

    def test_verify_generated_passes_after_compile(self) -> None:
        _run_goal_compile("--root", str(self.root), "--slice-pack", "compiler-bootstrap")

        result, output = _run_goal_compile("--root", str(self.root), "--verify-generated")

        self.assertEqual(result, 0)
        self.assertIn("generated goal outputs ok", output)

    def test_verify_generated_fails_when_instruct_is_stale(self) -> None:
        _run_goal_compile("--root", str(self.root), "--slice-pack", "compiler-bootstrap")
        (self.root / "codex-goal.instruct").write_text("stale\n", encoding="utf-8")

        result, output = _run_goal_compile("--root", str(self.root), "--verify-generated")

        self.assertEqual(result, 1)
        self.assertIn("generated instruct is stale", output)

    def test_verify_generated_fails_when_current_pointer_is_stale(self) -> None:
        _run_goal_compile("--root", str(self.root), "--slice-pack", "compiler-bootstrap")
        current_path = self.root / ".goal" / "current.json"
        current = json.loads(current_path.read_text(encoding="utf-8"))
        current["validation_tier"] = "V404"
        current_path.write_text(json.dumps(current), encoding="utf-8")

        result, output = _run_goal_compile("--root", str(self.root), "--verify-generated")

        self.assertEqual(result, 1)
        self.assertIn("current task pointer field is stale: validation_tier", output)

    def test_verify_generated_fails_when_current_pointer_has_stale_extra_field(self) -> None:
        _run_goal_compile("--root", str(self.root), "--slice-pack", "compiler-bootstrap")
        current_path = self.root / ".goal" / "current.json"
        current = json.loads(current_path.read_text(encoding="utf-8"))
        current["stale_resume_note"] = "old state that should not survive regeneration"
        current_path.write_text(json.dumps(current), encoding="utf-8")

        result, output = _run_goal_compile("--root", str(self.root), "--verify-generated")

        self.assertEqual(result, 1)
        self.assertIn("current task pointer has stale extra field: stale_resume_note", output)

    def test_from_current_rejects_sensitive_current_pointer_fields(self) -> None:
        (self.root / ".goal").mkdir()
        (self.root / ".goal" / "current.json").write_text(
            json.dumps({"active_slice_pack": "compiler-bootstrap", "credentials": "do-not-store"}),
            encoding="utf-8",
        )

        result, output = _run_goal_compile("--root", str(self.root), "--from-current")

        self.assertEqual(result, 1)
        self.assertIn("current task pointer contains sensitive keys", output)

    def test_generated_instruct_references_sources_by_path(self) -> None:
        _run_goal_compile("--root", str(self.root), "--slice-pack", "compiler-bootstrap")

        instruct = (self.root / "codex-goal.instruct").read_text(encoding="utf-8")

        self.assertIn("goal/fragments/authority.yaml", instruct)
        self.assertIn("/home/bitloop/Desktop/goal-instruct-idea.md", instruct)
        self.assertNotIn("## Improvement 01", instruct)

    def test_check_catches_capability_conflict(self) -> None:
        env_path = self.root / "goal" / "fragments" / "environments.yaml"
        data = _read_yaml(env_path)
        data["capabilities"].append(
            {
                "environment": "real_world",
                "action": "lab_solve_progression",
                "decision": "allow",
                "lab_only": True,
            }
        )
        _write_yaml(env_path, data)

        result, output = _run_goal_compile("--root", str(self.root), "--check")

        self.assertEqual(result, 1)
        self.assertIn("conflicting capability decisions", output)

    def test_check_catches_slice_packs_larger_than_six_slices(self) -> None:
        slices_path = self.root / "goal" / "slices.yaml"
        data = _read_yaml(slices_path)
        data["slice_packs"][0]["slices"].extend(
            [
                {"id": "extra_one", "subsystem": "goal_compiler", "validation_tier": "V2"},
                {"id": "extra_two", "subsystem": "goal_compiler", "validation_tier": "V2"},
                {"id": "extra_three", "subsystem": "goal_compiler", "validation_tier": "V2"},
            ]
        )
        _write_yaml(slices_path, data)

        result, output = _run_goal_compile("--root", str(self.root), "--check")

        self.assertEqual(result, 1)
        self.assertIn("more than 6 slices", output)

    def test_check_allows_six_slice_pack_batch(self) -> None:
        slices_path = self.root / "goal" / "slices.yaml"
        data = _read_yaml(slices_path)
        data["slice_packs"][0]["slices"].extend(
            [
                {"id": "extra_one", "subsystem": "goal_compiler", "validation_tier": "V2"},
                {"id": "extra_two", "subsystem": "goal_compiler", "validation_tier": "V2"},
            ]
        )
        _write_yaml(slices_path, data)

        result, output = _run_goal_compile("--root", str(self.root), "--check")

        self.assertEqual(result, 0)
        self.assertIn("goal sources ok", output)

    def test_readme_is_allowed_only_when_non_authoritative(self) -> None:
        result, _ = _run_goal_compile("--root", str(self.root), "--check")
        self.assertEqual(result, 0)

        env_path = self.root / "goal" / "fragments" / "environments.yaml"
        data = _read_yaml(env_path)
        for item in data["markdown_policy"]["files"]:
            if item["path"] == "README.md":
                item["authoritative"] = True
        _write_yaml(env_path, data)

        result, output = _run_goal_compile("--root", str(self.root), "--check")

        self.assertEqual(result, 1)
        self.assertIn("README.md must remain non-authoritative", output)

    def test_local_ctf_container_can_allow_lab_progression_while_real_world_is_gated(self) -> None:
        config = goal_compile.load_goal_config(self.root)
        capabilities = config["environments"]["capabilities"]
        decisions = {
            (item["environment"], item["action"]): item["decision"]
            for item in capabilities
            if item["action"] == "lab_solve_progression"
        }

        self.assertEqual(decisions["local_ctf_container", "lab_solve_progression"], "allow")
        self.assertEqual(decisions["real_world", "lab_solve_progression"], "block")

    def test_current_json_excludes_forbidden_sensitive_fields(self) -> None:
        _run_goal_compile("--root", str(self.root), "--slice-pack", "compiler-bootstrap")

        current = json.loads((self.root / ".goal" / "current.json").read_text(encoding="utf-8"))

        self.assertFalse(FORBIDDEN_CURRENT_KEYS.intersection(current.keys()))

    def test_check_catches_unknown_milestone_and_validation_tier(self) -> None:
        slices_path = self.root / "goal" / "slices.yaml"
        data = _read_yaml(slices_path)
        data["slice_packs"][0]["milestones"].append("M404")
        data["slice_packs"][0]["validation_tier"] = "V404"
        _write_yaml(slices_path, data)

        result, output = _run_goal_compile("--root", str(self.root), "--check")

        self.assertEqual(result, 1)
        self.assertIn("unknown milestone id: M404", output)
        self.assertIn("unknown validation tier id: V404", output)

    def test_check_catches_unassigned_declared_milestone_family(self) -> None:
        slices_path = self.root / "goal" / "slices.yaml"
        data = _read_yaml(slices_path)
        for pack in data["slice_packs"]:
            pack["milestones"] = [milestone for milestone in pack["milestones"] if milestone != "M6"]
        _write_yaml(slices_path, data)

        result, output = _run_goal_compile("--root", str(self.root), "--check")

        self.assertEqual(result, 1)
        self.assertIn("milestones missing slice-pack coverage: M6", output)

    def test_check_allows_incomplete_milestone_family(self) -> None:
        milestones_path = self.root / "goal" / "fragments" / "milestones.yaml"
        data = _read_yaml(milestones_path)
        for milestone in data["milestones"]:
            if milestone["id"] == "M6":
                milestone["status"] = "in_progress"
                milestone["evidence"] = []
        _write_yaml(milestones_path, data)

        result, output = _run_goal_compile("--root", str(self.root), "--check")

        self.assertEqual(result, 0)
        self.assertIn("goal sources ok", output)

    def test_check_catches_unknown_milestone_status(self) -> None:
        milestones_path = self.root / "goal" / "fragments" / "milestones.yaml"
        data = _read_yaml(milestones_path)
        for milestone in data["milestones"]:
            if milestone["id"] == "M6":
                milestone["status"] = "complete"
        _write_yaml(milestones_path, data)

        result, output = _run_goal_compile("--root", str(self.root), "--check")

        self.assertEqual(result, 1)
        self.assertIn("unknown milestone status for M6: complete", output)

    def test_check_catches_fully_complete_milestone_without_evidence(self) -> None:
        milestones_path = self.root / "goal" / "fragments" / "milestones.yaml"
        data = _read_yaml(milestones_path)
        for milestone in data["milestones"]:
            if milestone["id"] == "M6":
                milestone["status"] = "fully_complete"
                milestone["evidence"] = []
        _write_yaml(milestones_path, data)

        result, output = _run_goal_compile("--root", str(self.root), "--check")

        self.assertEqual(result, 1)
        self.assertIn("milestone completion evidence required: M6", output)

    def test_check_catches_mixed_subsystem_or_validation_tier(self) -> None:
        slices_path = self.root / "goal" / "slices.yaml"
        data = _read_yaml(slices_path)
        data["slice_packs"][0]["slices"][0]["subsystem"] = "other"
        data["slice_packs"][0]["slices"][1]["validation_tier"] = "V1"
        _write_yaml(slices_path, data)

        result, output = _run_goal_compile("--root", str(self.root), "--check")

        self.assertEqual(result, 1)
        self.assertIn("mixes subsystems", output)
        self.assertIn("mixes validation tiers", output)

    def test_check_catches_non_exempt_markdown_rag_ingestion(self) -> None:
        env_path = self.root / "goal" / "fragments" / "environments.yaml"
        data = _read_yaml(env_path)
        for item in data["markdown_policy"]["files"]:
            if item["path"].startswith("findings/"):
                item["operational_rag_ingestible"] = True
        _write_yaml(env_path, data)

        result, output = _run_goal_compile("--root", str(self.root), "--check")

        self.assertEqual(result, 1)
        self.assertIn("non-exempt Markdown cannot be operational RAG ingestible", output)


def _read_yaml(path: Path) -> dict:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _write_yaml(path: Path, payload: dict) -> None:
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def _run_goal_compile(*args: str) -> tuple[int, str]:
    output = io.StringIO()
    with redirect_stdout(output):
        result = goal_compile.main(list(args))
    return result, output.getvalue()


if __name__ == "__main__":
    unittest.main()
