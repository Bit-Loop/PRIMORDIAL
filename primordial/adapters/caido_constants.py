from __future__ import annotations

import re

DEFAULT_GRAPHQL_URL = "http://127.0.0.1:8650/graphql"
LEGACY_DEFAULT_GRAPHQL_URLS = {
    "http://127.0.0.1:8080/graphql",
    "http://localhost:8080/graphql",
}

REQUEST_SUMMARY_FIELDS = """
    id
    host
    port
    method
    path
    query
    isTls
    length
    createdAt
    source
    metadata { id color }
    response {
        id
        statusCode
        length
        roundtripTime
        createdAt
    }
"""

SENSITIVE_HEADER_RE = re.compile(
    r"^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-csrf-token|csrf-token)\s*:",
    re.IGNORECASE,
)
SENSITIVE_PARAM_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|access_token|refresh_token|api[_-]?key|secret)=([^&\s]+)"
)
REQUEST_LINE_RE = re.compile(r"^[A-Z][A-Z0-9-]{0,31}\s+\S+\s+HTTP/\d(?:\.\d)?\s*$", re.MULTILINE)
