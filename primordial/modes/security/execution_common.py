from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
from typing import Callable
from urllib import error, parse, request
import xml.etree.ElementTree as ET

from primordial.core.config import AppConfig
from primordial.core.credentials import CredentialStore
from primordial.core.domain.constants import (
    REMOTE_ADMIN_PORTS,
    SERVICE_DISCOVERY_PORTS,
    SERVICE_NAME_BY_PORT,
)
from primordial.core.domain.enums import (
    AgentRole,
    ArtifactKind,
    EventType,
    EvidenceType,
    ExternalSyncKind,
    FindingSeverity,
    InterestStatus,
    NotificationChannel,
    RiskTier,
    TaskKind,
    VerificationStatus,
)
from primordial.core.domain.models import (
    AgentTrace,
    ArtifactRecord,
    ContextSlice,
    EventRecord,
    EvidenceRecord,
    ExternalSyncJob,
    Finding,
    Interest,
    Note,
    NotificationRecord,
    PrimitiveManifest,
    Task,
    TaskExecutionResult,
    TaskHandoff,
)
from primordial.core.intent.models import OperatorIntentPolicy
from primordial.core.primitives.aliases import primitives_for_hint
from primordial.core.primitives.catalog import PrimitiveCatalog
from primordial.core.storage.runtime import RuntimeStore


AiGenerateCallable = Callable[[Task, str, str, float], dict[str, object] | None]


AUTH_KEYWORDS = ("login", "signin", "sign-in", "auth", "session", "account", "admin")
DISCOVERY_PATHS = (
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/login",
    "/admin",
    "/api/",
)
# SERVICE_DISCOVERY_PORTS, SERVICE_NAME_BY_PORT, REMOTE_ADMIN_PORTS are
# imported from primordial.core.domain.constants — edit them there, not here.
CONTENT_DISCOVERY_EXTENSIONS = ("", ".aspx", ".asp", ".txt", ".config", ".html")
CONTENT_DISCOVERY_INTERESTING_STATUS = {200, 204, 301, 302, 307, 308, 401, 403}
EXPLOIT_RESEARCH_SUPPRESSED_TERMS = (
    "denial of service",
    " dos",
    "/dos/",
    "ddos",
    "crash",
    "stack overflow",
    "buffer overflow",
    "resource exhaustion",
    "memory exhaustion",
)
EXPLOIT_RESEARCH_LOCAL_TERMS = (
    "/local/",
    " local ",
    "privilege escalation",
    "priv esc",
    "unquoted service path",
)
EXPLOIT_RESEARCH_RCE_TERMS = (
    "remote code execution",
    " rce",
    "/rce/",
    "command execution",
    "code execution",
)
EXPLOIT_RESEARCH_HTTP_TRASH_PREFIXES = ("http/1.", "content-length:", "content-type:", "last-modified:")


class _SurfaceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._in_title = False
        self._title_chunks: list[str] = []
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[str] = []

    @property
    def title(self) -> str:
        return " ".join(chunk.strip() for chunk in self._title_chunks if chunk.strip()).strip()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {key: value for key, value in attrs}
        if tag == "title":
            self._in_title = True
            return
        if tag == "a" and attr_map.get("href"):
            self.links.append(attr_map["href"])
        elif tag == "script" and attr_map.get("src"):
            self.scripts.append(attr_map["src"])
        elif tag == "form" and attr_map.get("action"):
            self.forms.append(attr_map["action"])

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title_chunks.append(data)
