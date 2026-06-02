from __future__ import annotations

import re
from urllib import parse


SECRET_VALUE_RE = re.compile(
    r"(?i)\b(api[_-]?key|token|secret|password|passwd|pwd|webhook|authorization)\b([\"']?\s*[:=]\s*[\"']?)([^\"'\s,}]{4,})"
)
BEARER_RE = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/\-]+=*")
FLAG_RE = re.compile(r"(?i)\b(?:flag|htb|thm)\{[^}\s]{4,}\}")
URL_RE = re.compile(r"https?://[^\s`<>\"]+")


def redact_sensitive_text(value: str) -> str:
    redacted = SECRET_VALUE_RE.sub(lambda match: f"{match.group(1)}{match.group(2)}[redacted]", str(value or ""))
    redacted = BEARER_RE.sub(lambda match: f"{match.group(1)}[redacted]", redacted)
    redacted = FLAG_RE.sub("[redacted-flag]", redacted)
    return redact_url_queries(redacted)


def redact_url_queries(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        raw_url = match.group(0)
        parsed = parse.urlsplit(raw_url)
        if not parsed.query:
            return raw_url
        query = parse.urlencode([(key, "[redacted]") for key, _ in parse.parse_qsl(parsed.query, keep_blank_values=True)])
        return parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))

    return URL_RE.sub(replace, value)
