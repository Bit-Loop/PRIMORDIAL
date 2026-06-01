from __future__ import annotations

import json

import tempfile

import unittest

from pathlib import Path

from unittest.mock import patch

from primordial.config import AppConfig

from primordial.core.domain.enums import (
    AgentRole,
    EvidenceType,
    MethodologyPhase,
    NotificationChannel,
    RiskTier,
    ScopeProfile,
    TaskKind,
    TaskRunStatus,
    TaskStatus,
    VerificationStatus,
)

from primordial.core.domain.models import EvidenceRecord, Task

from primordial.core.domain.models import TaskRun

from primordial.core.providers.agent_chat import AgentChatResponse

from primordial.core.providers.ollama import OllamaModelListResult

from primordial.runtime import PrimordialRuntime

from tests.support import build_probe_fixture, fixture_ip, fixture_secret, write_scope_file

MANIFESTS_DIR = Path(__file__).resolve().parents[1] / "manifests"

PIRATE_IP = fixture_ip(10, 129, 47, 117)

class RuntimeIntegrationTestsBase(unittest.TestCase):
    pass

__all__ = [name for name in globals() if not name.startswith("__")]
