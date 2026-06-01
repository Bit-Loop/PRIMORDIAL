from __future__ import annotations

import tempfile

import unittest

from pathlib import Path

from unittest.mock import patch

from primordial.config import AppConfig

from primordial.app.runtime import PrimordialRuntime

from primordial.core.autonomy import FailureDiagnosis, MethodologyCompiler, ScriptSafetyValidator, ToolInventory, ToolingGap, ToolingGapResolver

from primordial.core.autonomy.failure import FailureCategory

from primordial.core.autonomy.tools import GiveUpWithReason, ToolSubstitution

from primordial.core.catalog.capabilities import CapabilityCatalog

from primordial.core.catalog.interpolation import interpolate_argv

from primordial.core.catalog.loader import CatalogValidationError

from primordial.core.catalog.playbooks import PlaybookCatalog

from primordial.core.domain.enums import EvidenceType, ScopeProfile, VerificationStatus

from primordial.core.domain.enums import AgentRole, MethodologyPhase, TaskKind

from primordial.core.domain.models import EvidenceRecord, Target, Task

from primordial.core.intent.models import KerberosPolicy, OperatorIntentPolicy

from primordial.core.intent import OperatorIntentRegistry

from primordial.core.primitives.catalog import PrimitiveCatalog

from tests.support import fixture_ip, write_scope_file

REPO_ROOT = Path(__file__).resolve().parents[1]

MANIFESTS_DIR = REPO_ROOT / "manifests"

CATALOG_DIR = REPO_ROOT / "catalog"

LAB_IP = fixture_ip(10, 10, 10, 10)

INTERPOLATION_IP = fixture_ip(10, 0, 0, 1)

class OperatorIntentCatalogAutonomyTestsBase(unittest.TestCase):
    pass

__all__ = [name for name in globals() if not name.startswith("__")]
