from __future__ import annotations

import json

import io

import tempfile

import unittest

from pathlib import Path

from unittest.mock import patch

from urllib import error

from primordial.config import AppConfig

from primordial.runtime import PrimordialRuntime

from primordial.core.domain.enums import (
    AgentRole,
    EvidenceType,
    EventType,
    ExternalSyncKind,
    ExternalSyncStatus,
    InterestStatus,
    MethodologyPhase,
    ProviderRoute,
    RiskTier,
    ScopeProfile,
    TaskKind,
    TaskRunStatus,
    TaskStatus,
    VerificationStatus,
)

from primordial.core.domain.models import (
    EscalationPackage,
    EvidenceRecord,
    ExternalSyncJob,
    Interest,
    Target,
    Task,
    TaskExecutionResult,
    TaskRun,
    utc_now,
)

from primordial.core.domain.models import OrchestrationReport

from primordial.core.web.app import PrimordialWebApp

from tests.support import build_probe_fixture, fixture_ip, fixture_secret, write_scope_file

MANIFESTS_DIR = Path(__file__).resolve().parents[1] / "manifests"

ACTIVE_IP = fixture_ip(10, 129, 47, 117)

CORRECTED_IP = fixture_ip(10, 129, 244, 95)

INVALID_IP = fixture_ip(10, 129, 244, 220)

class WorkflowTestsBase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        config = AppConfig.from_env(project_root=root)
        config.manifests_dir = MANIFESTS_DIR
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
        self.target = self.runtime.store.list_targets()[0]
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

__all__ = [name for name in globals() if not name.startswith("__")]
