from __future__ import annotations

import unittest

from primordial.labs.ctf import HardcodeScanner

from tests.support import fixture_flag, fixture_ip, fixture_secret

class HardcodeScannerContractTestsBase(unittest.TestCase):
    pass

__all__ = [name for name in globals() if not name.startswith("__")]
