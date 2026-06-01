from __future__ import annotations

import subprocess
import unittest

from primordial.app.gpu_metrics import parse_nvidia_smi_gpu_metrics, read_gpu_metrics


class GpuMetricsTests(unittest.TestCase):
    def test_parse_nvidia_smi_gpu_metrics_uses_memory_total_for_free_and_percent(self) -> None:
        payload = parse_nvidia_smi_gpu_metrics("34, 10, 2048, 8192, 61\n")

        self.assertTrue(payload["available"])
        self.assertEqual(payload["percent"], 34.0)
        self.assertEqual(payload["memory_used_mb"], 2048.0)
        self.assertEqual(payload["memory_free_mb"], 6144.0)
        self.assertEqual(payload["memory_percent"], 25.0)
        self.assertEqual(payload["temperature_c"], 61.0)
        self.assertIsNone(payload["error"])

    def test_read_gpu_metrics_reports_missing_nvidia_smi_without_running_command(self) -> None:
        called = False

        def fake_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            nonlocal called
            called = True
            return subprocess.CompletedProcess([], 0, stdout="", stderr="")

        payload = read_gpu_metrics(which=lambda _name: None, run=fake_run)

        self.assertFalse(called)
        self.assertFalse(payload["available"])
        self.assertEqual(payload["error"], "nvidia-smi not found")

    def test_read_gpu_metrics_reports_command_errors(self) -> None:
        def fake_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess([], 7, stdout="", stderr="driver unavailable")

        payload = read_gpu_metrics(which=lambda _name: "/usr/bin/nvidia-smi", run=fake_run)

        self.assertFalse(payload["available"])
        self.assertEqual(payload["error"], "driver unavailable")


if __name__ == "__main__":
    unittest.main()
