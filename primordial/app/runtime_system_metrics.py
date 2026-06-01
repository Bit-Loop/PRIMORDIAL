from __future__ import annotations

from primordial.app.runtime_deps import (
    os,
    Path,
    read_gpu_metrics,
)

class RuntimeSystemMetricsMixin:
    def _read_cpu_metrics(self) -> dict[str, object]:
        cpu_count = max(1, os.cpu_count() or 1)
        load_1 = load_5 = load_15 = 0.0
        if hasattr(os, "getloadavg"):
            try:
                load_1, load_5, load_15 = os.getloadavg()
            except OSError:
                pass
        percent = None
        try:
            with Path("/proc/stat").open("r", encoding="utf-8") as handle:
                first_line = handle.readline().strip()
            fields = [int(value) for value in first_line.split()[1:]]
            if len(fields) >= 4:
                idle = fields[3] + (fields[4] if len(fields) > 4 else 0)
                total = sum(fields)
                previous = self._cpu_sample
                self._cpu_sample = (idle, total)
                if previous is not None:
                    idle_delta = idle - previous[0]
                    total_delta = total - previous[1]
                    if total_delta > 0:
                        percent = max(0.0, min(100.0, 100.0 * (1.0 - (idle_delta / total_delta))))
        except OSError:
            percent = None
        if percent is None:
            percent = max(0.0, min(100.0, (load_1 / cpu_count) * 100.0))
        memory_total_mb = None
        memory_available_mb = None
        memory_free_mb = None
        try:
            meminfo: dict[str, float] = {}
            with Path("/proc/meminfo").open("r", encoding="utf-8") as handle:
                for line in handle:
                    key, _, remainder = line.partition(":")
                    parts = remainder.strip().split()
                    if not parts:
                        continue
                    try:
                        meminfo[key] = float(parts[0]) / 1024.0
                    except ValueError:
                        continue
            memory_total_mb = meminfo.get("MemTotal")
            memory_available_mb = meminfo.get("MemAvailable")
            memory_free_mb = meminfo.get("MemFree")
        except OSError:
            pass
        if memory_available_mb is None:
            memory_available_mb = memory_free_mb
        memory_percent = None
        if memory_total_mb and memory_available_mb is not None:
            memory_percent = max(0.0, min(100.0, 100.0 * (1.0 - (memory_available_mb / memory_total_mb))))
        memory = {
            "percent": round(memory_percent, 1) if memory_percent is not None else 0.0,
            "used_mb": round(memory_total_mb - memory_available_mb, 1) if memory_total_mb is not None and memory_available_mb is not None else None,
            "available_mb": round(memory_available_mb, 1) if memory_available_mb is not None else None,
            "free_mb": round(memory_free_mb, 1) if memory_free_mb is not None else None,
            "total_mb": round(memory_total_mb, 1) if memory_total_mb is not None else None,
        }
        return {
            "available": True,
            "percent": round(percent, 1),
            "load_1": round(load_1, 2),
            "load_5": round(load_5, 2),
            "load_15": round(load_15, 2),
            "cpu_count": cpu_count,
            "memory": memory,
            "memory_available_mb": round(memory_available_mb, 1) if memory_available_mb is not None else None,
            "memory_free_mb": round(memory_free_mb, 1) if memory_free_mb is not None else None,
            "memory_total_mb": round(memory_total_mb, 1) if memory_total_mb is not None else None,
            "memory_percent": round(memory_percent, 1) if memory_percent is not None else None,
        }

    def _read_network_metrics(self, now: float) -> dict[str, object]:
        try:
            rx_total = 0
            tx_total = 0
            with Path("/proc/net/dev").open("r", encoding="utf-8") as handle:
                for line in handle.readlines()[2:]:
                    name, _, counters = line.partition(":")
                    iface = name.strip()
                    if not iface or iface == "lo":
                        continue
                    fields = counters.split()
                    if len(fields) < 16:
                        continue
                    rx_total += int(fields[0])
                    tx_total += int(fields[8])
        except (OSError, ValueError):
            return {
                "available": False,
                "rx_bytes_per_sec": 0.0,
                "tx_bytes_per_sec": 0.0,
                "rx_label": "0 B/s",
                "tx_label": "0 B/s",
            }
        previous = self._network_sample
        self._network_sample = (rx_total, tx_total, now)
        rx_rate = tx_rate = 0.0
        if previous is not None:
            elapsed = max(0.001, now - previous[2])
            rx_rate = max(0.0, (rx_total - previous[0]) / elapsed)
            tx_rate = max(0.0, (tx_total - previous[1]) / elapsed)
        return {
            "available": True,
            "rx_bytes": rx_total,
            "tx_bytes": tx_total,
            "rx_bytes_per_sec": round(rx_rate, 2),
            "tx_bytes_per_sec": round(tx_rate, 2),
            "rx_label": self._bytes_per_second_label(rx_rate),
            "tx_label": self._bytes_per_second_label(tx_rate),
        }

    def _bytes_per_second_label(self, value: float) -> str:
        units = ("B/s", "KB/s", "MB/s", "GB/s")
        current = float(value)
        unit = units[0]
        for unit in units:
            if current < 1024.0 or unit == units[-1]:
                break
            current /= 1024.0
        if unit == "B/s":
            return f"{int(current)} {unit}"
        return f"{current:.1f} {unit}"

    def _read_gpu_metrics(self) -> dict[str, object]:
        return read_gpu_metrics()
