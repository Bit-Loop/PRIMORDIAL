from __future__ import annotations

import base64

import io

import json

import tempfile

import unittest

from pathlib import Path

from unittest.mock import patch

from primordial.adapters.caido import CaidoIntegrationService

from primordial.config import AppConfig

from primordial.core.credentials import CredentialStore

from primordial.core.domain.enums import ScopeProfile

from primordial.runtime import PrimordialRuntime

from tests.support import fixture_ip

ACTIVE_IP = fixture_ip(10, 129, 244, 95)

class CaidoAndSkillTestsBase(unittest.TestCase):
    pass

__all__ = [name for name in globals() if not name.startswith("__")]
