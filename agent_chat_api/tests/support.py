from __future__ import annotations

import io
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

PACKAGE_PARENT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = Path(__file__).resolve().parents[1]

if str(PACKAGE_PARENT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_PARENT))


def write_executable(path: Path, source: str) -> Path:
    path.write_text(source, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


class FakeSocket:
    def __init__(self, request: bytes) -> None:
        self._reader = io.BytesIO(request)
        self._writer = io.BytesIO()

    def makefile(self, mode: str, *args: Any, **kwargs: Any) -> io.BytesIO:
        if "r" in mode:
            return self._reader
        return self._writer

    def sendall(self, data: bytes) -> None:
        self._writer.write(data)

    def response_bytes(self) -> bytes:
        return self._writer.getvalue()


def run_handler_raw(
    handler_cls: type,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], str]:
    body = b""
    header_lines = [f"{method} {path} HTTP/1.1", "Host: test.local"]
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        header_lines.extend(["Content-Type: application/json", f"Content-Length: {len(body)}"])
    for name, value in (headers or {}).items():
        header_lines.append(f"{name}: {value}")
    raw_request = ("\r\n".join(header_lines) + "\r\n\r\n").encode("utf-8") + body
    sock = FakeSocket(raw_request)
    handler_cls(sock, ("127.0.0.1", 12345), object())
    raw_response = sock.response_bytes()
    header_block, _, response_body = raw_response.partition(b"\r\n\r\n")
    header_lines = header_block.splitlines()
    status_line = header_lines[0].decode("iso-8859-1")
    status = int(status_line.split(" ")[1])
    response_headers: dict[str, str] = {}
    for line in header_lines[1:]:
        decoded = line.decode("iso-8859-1")
        name, separator, value = decoded.partition(":")
        if separator:
            response_headers[name.strip().lower()] = value.strip()
    return status, response_headers, response_body.decode("utf-8")


def run_handler(
    handler_cls: type,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    status, _headers, body = run_handler_raw(handler_cls, method, path, payload, headers)
    return status, json.loads(body or "{}")


def temporary_executable(root: Path, name: str, body: str) -> Path:
    bin_dir = root / ".test-bin"
    bin_dir.mkdir(exist_ok=True)
    return write_executable(
        bin_dir / name,
        "#!/usr/bin/env python3\n"
        "import sys\n"
        + body.lstrip(),
    )


def remove_test_bin(root: Path) -> None:
    bin_dir = root / ".test-bin"
    if not bin_dir.exists():
        return
    for path in sorted(bin_dir.iterdir(), reverse=True):
        if path.is_file():
            path.unlink()
    os.rmdir(bin_dir)
