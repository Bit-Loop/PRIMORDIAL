from __future__ import annotations

import unittest

from primordial.labs.ctf import BenchmarkRun

from tests.support import fixture_flag

class BenchmarkRunContractTestsBase(unittest.TestCase):
    pass

__all__ = [name for name in globals() if not name.startswith("__")]
