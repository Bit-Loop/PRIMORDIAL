from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from primordial.core.config import AppConfig
from primordial.core.local_runtime import load_project_env, maybe_start_bootstrap_postgres


class LocalRuntimeEnvTests(unittest.TestCase):
    def test_load_project_env_sets_missing_values_without_overriding_shell(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            env_path = root / "runtime" / "primordial.env"
            env_path.parent.mkdir()
            env_path.write_text(
                "\n".join(
                    [
                        "export PRIMORDIAL_DATABASE_URL='postgresql://primordial@127.0.0.1:55432/primordial'",
                        f"export PRIMORDIAL_RUNTIME_DIR='{root / 'runtime'}'",
                    ]
                ),
                encoding="utf-8",
            )

            with patch.dict(
                os.environ,
                {"PRIMORDIAL_DATABASE_URL": "postgresql://operator@example.test:5432/custom"},
                clear=True,
            ):
                loaded = load_project_env(root)

                self.assertEqual(loaded, env_path)
                self.assertEqual(os.environ["PRIMORDIAL_DATABASE_URL"], "postgresql://operator@example.test:5432/custom")
                self.assertEqual(os.environ["PRIMORDIAL_RUNTIME_DIR"], str(root / "runtime"))

    def test_app_config_loads_project_env_before_reading_database_url(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            env_path = root / "runtime" / "primordial.env"
            env_path.parent.mkdir()
            env_path.write_text(
                "export PRIMORDIAL_DATABASE_URL='postgresql://primordial@127.0.0.1:55432/primordial'\n",
                encoding="utf-8",
            )

            with patch.dict(os.environ, {}, clear=True):
                config = AppConfig.from_env(project_root=root)

                self.assertEqual(config.database_url, "postgresql://primordial@127.0.0.1:55432/primordial")

    def test_app_config_enables_use_only_wrapper_mode_from_env(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with patch.dict(
                os.environ,
                {
                    "PRIMORDIAL_DATABASE_URL": "postgresql://primordial@127.0.0.1:55432/primordial",
                    "PRIMORDIAL_USE_ONLY_WRAPPER_MODE": "1",
                },
                clear=True,
            ):
                config = AppConfig.from_env(project_root=root)

        self.assertTrue(config.use_only_wrapper_mode)

    def test_bootstrap_postgres_auto_start_is_limited_to_bootstrap_port(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            data_dir = root / "runtime" / "postgres" / "data"
            data_dir.mkdir(parents=True)
            (data_dir / "PG_VERSION").write_text("17\n", encoding="utf-8")

            with patch.dict(
                os.environ,
                {"PRIMORDIAL_DATABASE_URL": "postgresql://primordial@127.0.0.1:5432/primordial"},
                clear=True,
            ), patch("primordial.core.local_runtime.subprocess.run") as run:
                self.assertFalse(maybe_start_bootstrap_postgres(root))
                run.assert_not_called()

    def test_bootstrap_postgres_auto_start_uses_pg_ctl_without_shell(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            data_dir = root / "runtime" / "postgres" / "data"
            data_dir.mkdir(parents=True)
            (data_dir / "PG_VERSION").write_text("17\n", encoding="utf-8")

            with patch.dict(
                os.environ,
                {"PRIMORDIAL_DATABASE_URL": "postgresql://primordial@127.0.0.1:55432/primordial"},
                clear=True,
            ), patch("primordial.core.local_runtime.shutil.which", return_value="/usr/bin/pg_ctl"), patch(
                "primordial.core.local_runtime.subprocess.run"
            ) as run:
                run.side_effect = [
                    subprocess.CompletedProcess(args=["pg_ctl", "status"], returncode=3),
                    subprocess.CompletedProcess(args=["pg_ctl", "start"], returncode=0),
                ]

                self.assertTrue(maybe_start_bootstrap_postgres(root))

                self.assertEqual(run.call_args_list[0].args[0], ["/usr/bin/pg_ctl", "-D", str(data_dir), "status"])
                start_args = run.call_args_list[1].args[0]
                self.assertEqual(start_args[0:4], ["/usr/bin/pg_ctl", "-D", str(data_dir), "-l"])
                self.assertIn("-p 55432", start_args[start_args.index("-o") + 1])


if __name__ == "__main__":
    unittest.main()
