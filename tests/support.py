from __future__ import annotations

import json
from pathlib import Path
from urllib import parse


def write_scope_file(root: Path, *, targets: list[dict[str, object]], profile: str = "hack_the_box") -> Path:
    path = root / "scope.json"
    path.write_text(json.dumps({"profile": profile, "targets": targets}, indent=2))
    return path


def build_probe_fixture(url: str) -> dict[str, object]:
    parsed = parse.urlsplit(url)
    return {
        "asset_label": parsed.netloc or parsed.path,
        "requested_url": url,
        "effective_url": url,
        "status_code": 200,
        "content_type": "text/html; charset=utf-8",
        "headers": {"server": "fixture", "content-type": "text/html; charset=utf-8"},
        "title": "Pirate Fixture",
        "page_links": ["/login?next=/dashboard", "/admin"],
        "scripts": ["/static/app.js"],
        "forms": ["/session"],
        "resolved_ips": ["127.0.0.1"],
        "discovery_results": [
            {"path": "/robots.txt", "url": parse.urljoin(url, "/robots.txt"), "status": 200, "content_type": "text/plain"},
            {"path": "/login", "url": parse.urljoin(url, "/login"), "status": 200, "content_type": "text/html"},
            {"path": "/admin", "url": parse.urljoin(url, "/admin"), "status": 403, "content_type": "text/plain"},
            {"path": "/api/", "url": parse.urljoin(url, "/api/"), "status": 401, "content_type": "application/json"},
        ],
        "ssl_verification_disabled": False,
        "host_header": "",
    }
