from __future__ import annotations

import base64
import hashlib
import re
from urllib import parse

from primordial.adapters.caido_constants import REQUEST_LINE_RE
from primordial.adapters.caido_models import ParsedRawRequest


def parse_raw_request(raw_request: str, *, max_bytes: int = 262_144) -> ParsedRawRequest:
    raw = raw_request.replace("\r\n", "\n").replace("\r", "\n")
    raw = raw.strip("\n")
    if not raw:
        raise ValueError("raw request is required")
    raw_bytes = raw.encode("utf-8", errors="replace")
    if len(raw_bytes) > max_bytes:
        raise ValueError(f"raw request exceeds {max_bytes} bytes")
    if "\x00" in raw:
        raise ValueError("raw request must not contain NUL bytes")
    request_lines = REQUEST_LINE_RE.findall(raw)
    if len(request_lines) > 1:
        raise ValueError("raw Replay send accepts one HTTP request at a time")
    lines = raw.split("\n")
    request_line = lines[0].strip()
    parts = request_line.split()
    if len(parts) != 3 or not parts[2].upper().startswith("HTTP/"):
        raise ValueError("raw request must start with an HTTP request line")
    method = parts[0].upper()
    if not re.fullmatch(r"[A-Z][A-Z0-9-]{0,31}", method):
        raise ValueError("raw request method is malformed")
    request_target = parts[1]
    headers = _parse_headers(lines[1:])
    absolute = parse.urlsplit(request_target)
    host_header = headers.get("host", "")
    host_value = absolute.netloc if absolute.scheme in {"http", "https"} and absolute.netloc else host_header
    if not host_value:
        raise ValueError("raw request must include a Host header or absolute request URL")
    host, header_port = split_host_port(host_value)
    if not host:
        raise ValueError("raw request host is malformed")
    explicit_port = absolute.port if absolute.scheme in {"http", "https"} and absolute.port else header_port
    is_tls = absolute.scheme == "https" or explicit_port == 443
    port = explicit_port or (443 if is_tls else 80)
    if not (1 <= int(port) <= 65535):
        raise ValueError("raw request port is out of range")
    path = _request_path(request_target, absolute)
    return ParsedRawRequest(
        method=method,
        host=host,
        port=int(port),
        is_tls=is_tls,
        sni=host,
        path=path,
        raw=raw,
        raw_base64=base64.b64encode(raw.encode("utf-8")).decode("ascii"),
        raw_sha256=hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        headers=headers,
    )


def split_host_port(value: str) -> tuple[str, int | None]:
    cleaned = value.strip()
    if not cleaned:
        return "", None
    parsed = parse.urlsplit(f"//{cleaned}")
    host = parsed.hostname or cleaned
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("raw request host port is malformed") from exc
    return host.strip("[]").lower(), port


def _parse_headers(lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in lines:
        if line == "":
            break
        if ":" not in line:
            raise ValueError("raw request contains a malformed header")
        name, value = line.split(":", 1)
        header_name = name.strip().lower()
        if not header_name:
            raise ValueError("raw request contains an empty header name")
        headers[header_name] = value.strip()
    return headers


def _request_path(request_target: str, absolute: parse.SplitResult) -> str:
    if absolute.scheme in {"http", "https"}:
        path = absolute.path or "/"
        return f"{path}?{absolute.query}" if absolute.query else path
    return request_target or "/"
