from __future__ import annotations

import hashlib

import io

import json

import threading

import tempfile

import time

import unittest

from pathlib import Path

from unittest.mock import patch

from primordial.config import AppConfig

from primordial.adapters.caido import CaidoIntegrationService

from primordial.core.domain.enums import (
    AgentRole,
    ArtifactKind,
    EvidenceType,
    EventType,
    InterestStatus,
    MethodologyPhase,
    NotificationChannel,
    NotificationStatus,
    PrimitiveRuntime,
    RiskTier,
    ProviderRoute,
    ScopeProfile,
    SideEffectLevel,
    TaskKind,
    TaskRunStatus,
    TaskStatus,
    VerificationStatus,
)

from primordial.core.domain.models import (
    AgentTrace,
    ArtifactRecord,
    EventRecord,
    EvidenceRecord,
    Interest,
    NotificationRecord,
    OperatorMessage,
    PrimitiveManifest,
    Task,
    TaskRun,
)

from primordial.core.providers.ollama import OllamaModelListResult, OllamaPreloadResult, OllamaResponse

from primordial.core.web.app import PrimordialWebApp, WebResponse

from primordial.core.web.server import _WebConsoleRequestHandler

from primordial.runtime import PrimordialRuntime

from tests.support import build_probe_fixture, fixture_ip, write_scope_file

MANIFESTS_DIR = Path(__file__).resolve().parents[1] / "manifests"

ALPHA_IP = fixture_ip(10, 10, 10, 10)

HELIX_IP = fixture_ip(10, 129, 54, 140)

PIRATE_IP = fixture_ip(10, 129, 47, 117)

REPLACEMENT_IP = fixture_ip(10, 129, 99, 99)

UPDATED_IP = fixture_ip(10, 129, 244, 95)

class WebConsoleTestsBase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.root = root
        config = AppConfig.from_env(project_root=root)
        config.manifests_dir = MANIFESTS_DIR
        config.rag.embeddings.provider = "deterministic_hash"
        config.ensure_directories()
        self.scope_path = write_scope_file(
            root,
            targets=[
                {
                    "handle": "pirate.htb",
                    "display_name": "Pirate Fixture",
                    "in_scope": True,
                    "assets": [{"asset": "http://pirate.htb/", "asset_type": "webapp"}],
                }
            ],
        )
        self.runtime = PrimordialRuntime(config)
        self.runtime.initialize()
        self.runtime.import_scope(self.scope_path)
        self.app = PrimordialWebApp(self.runtime)
        self.probe_patcher = patch(
            "primordial.modes.security.execution.PrimitiveExecutor._probe_url",
            autospec=True,
            side_effect=lambda _executor, **kwargs: build_probe_fixture(kwargs["url"]),
        )
        self.probe_patcher.start()

    def tearDown(self) -> None:
        self.probe_patcher.stop()
        self.runtime.shutdown()
        self.temp_dir.cleanup()

    def _write_rag_chunks(self, records: list[dict[str, object]]) -> Path:
        chunks_dir = self.root / "rag_chunks"
        chunks_dir.mkdir(parents=True, exist_ok=True)
        chunks_file = chunks_dir / "chunks.jsonl"
        chunks_file.write_text("\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8")
        return chunks_dir

__all__ = [name for name in globals() if not name.startswith("__")]
