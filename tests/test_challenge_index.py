from __future__ import annotations

from pathlib import Path
import hashlib
import json
import tempfile
import unittest

from primordial.labs.ctf.challenge_index import (
    load_ctf_dojo_challenges,
    load_mbptl_challenges,
    load_nyu_ctf_bench_challenges,
    load_phase_challenge_index,
    namespaced_repo_relpath_sha,
)
from primordial.labs.ctf.hardcode import flag_sha256


class ChallengeIndexTests(unittest.TestCase):
    def test_nyu_index_enumerates_active_and_parked_runnable_challenges(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            lab_root = Path(temp_dir)
            active = lab_root / "assets/phase8-nyu-ctf-bench/test/2017/CSAW-Quals/web/littlequery"
            parked = lab_root / "assets/phase8-nyu-ctf-bench.parked-20260602T051737Z/development/2016/CSAW-Quals/web/Login"
            active.mkdir(parents=True)
            parked.mkdir(parents=True)
            active_flag = "Flag" + "{" + "Case_Sensitive_Body" + "}"
            parked_flag = "CTF" + "{" + "parked-value" + "}"
            _write_challenge(active, name="littlequery", category="web", flag=f" {active_flag} \n")
            _write_challenge(parked, name="Login", category="web", flag=parked_flag)
            (active / "docker-compose.yml").write_text("services:\n  web:\n    image: local\n", encoding="utf-8")
            (parked / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")

            result = load_nyu_ctf_bench_challenges(lab_root=lab_root, include_parked=True)

        self.assertEqual(len(result.challenges), 2)
        active_ref = next(item for item in result.challenges if item.compose_path)
        parked_ref = next(item for item in result.challenges if item.dockerfile_path)
        self.assertEqual(active_ref.repo_relpath_sha, namespaced_repo_relpath_sha("nyu-ctf-bench", active_ref.repo_relpath))
        self.assertNotEqual(
            active_ref.repo_relpath_sha,
            hashlib.sha256(active_ref.repo_relpath.encode("utf-8")).hexdigest(),
        )
        self.assertEqual(active_ref.ground_truth_flag_sha256, flag_sha256("flag" + "{" + "Case_Sensitive_Body" + "}"))
        self.assertTrue(active_ref.compose_path.endswith("docker-compose.yml"))
        self.assertTrue(parked_ref.dockerfile_path.endswith("Dockerfile"))

    def test_nyu_index_skips_malformed_metadata_with_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            lab_root = Path(temp_dir)
            challenge = lab_root / "assets/phase8-nyu-ctf-bench/test/bad"
            challenge.mkdir(parents=True)
            (challenge / "challenge.json").write_text("{bad json", encoding="utf-8")
            (challenge / "docker-compose.yml").write_text("services:\n  web:\n    image: local\n", encoding="utf-8")

            result = load_nyu_ctf_bench_challenges(lab_root=lab_root)

        self.assertEqual(result.challenges, ())
        self.assertEqual(len(result.blockers), 1)
        self.assertIn("invalid challenge metadata", result.blockers[0].reason)

    def test_mbptl_index_uses_flag_files_as_per_challenge_truth(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            lab_root = Path(temp_dir)
            root = lab_root / "assets/phase3-mbptl/mbptl"
            service = root / "service-a"
            service.mkdir(parents=True)
            compose = root / "docker-compose.yml"
            compose.write_text("services:\n  service-a:\n    build: service-a\n", encoding="utf-8")
            raw_flag = "HTB" + "{" + "service-value" + "}"
            (service / "flag.txt").write_text(f" {raw_flag}\n", encoding="utf-8")
            (service / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")

            result = load_mbptl_challenges(lab_root=lab_root)

        self.assertEqual(len(result.challenges), 1)
        ref = result.challenges[0]
        self.assertEqual(ref.lab_id, "mbptl")
        self.assertEqual(ref.repo_relpath_sha, namespaced_repo_relpath_sha("mbptl", ref.repo_relpath))
        self.assertEqual(ref.ground_truth_flag_sha256, flag_sha256("htb" + "{" + "service-value" + "}"))
        self.assertTrue(ref.compose_path.endswith("docker-compose.yml"))
        self.assertTrue(ref.dockerfile_path.endswith("Dockerfile"))

    def test_ctf_dojo_index_filters_archive_to_runnable_challenges(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            lab_root = Path(temp_dir)
            root = lab_root / "assets/phase8-ctf-dojo"
            runnable = root / "archive/event/category/name"
            skipped = root / "archive/event/category/skipped"
            runnable.mkdir(parents=True)
            skipped.mkdir(parents=True)
            (root / "ctf_archive.json").write_text(
                json.dumps(
                    {
                        "runnable": {"challenge": "Name", "category": "web", "path": "archive/event/category/name"},
                        "skipped": {"challenge": "Skipped", "category": "web", "path": "archive/event/category/skipped"},
                    }
                ),
                encoding="utf-8",
            )
            (runnable / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")

            result = load_ctf_dojo_challenges(lab_root=lab_root)

        self.assertEqual(len(result.challenges), 1)
        ref = result.challenges[0]
        self.assertEqual(ref.lab_id, "ctf-dojo")
        self.assertEqual(ref.category, "web")
        self.assertTrue(ref.dockerfile_path.endswith("Dockerfile"))

    def test_phase_index_combines_phase_eight_benchmarks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            lab_root = Path(temp_dir)
            dojo_root = lab_root / "assets/phase8-ctf-dojo"
            dojo_challenge = dojo_root / "archive/event/web/fixture"
            nyu_challenge = lab_root / "assets/phase8-nyu-ctf-bench/test/year/event/web/fixture"
            dojo_challenge.mkdir(parents=True)
            nyu_challenge.mkdir(parents=True)
            (dojo_root / "ctf_archive.json").write_text(
                json.dumps({"one": {"challenge": "Fixture", "category": "web", "path": "archive/event/web/fixture"}}),
                encoding="utf-8",
            )
            (dojo_challenge / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
            _write_challenge(nyu_challenge, name="Fixture", category="web", flag="")
            (nyu_challenge / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")

            result = load_phase_challenge_index(8, lab_root=lab_root)

        self.assertEqual({ref.lab_id for ref in result.challenges}, {"ctf-dojo", "nyu-ctf-bench"})


def _write_challenge(path: Path, *, name: str, category: str, flag: str) -> None:
    (path / "challenge.json").write_text(
        json.dumps({"name": name, "category": category, "flag": flag, "port": 80}),
        encoding="utf-8",
    )


if __name__ == "__main__":
    unittest.main()
