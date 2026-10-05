#!/usr/bin/env python3
"""Exercise EXE name/ordinal/delay resolution and fail-closed missing exports."""
from pathlib import Path
import importlib.util
import sys
import unittest

root = Path(__file__).resolve().parent
sys.path.insert(0, str(root / 'tools'))
spec = importlib.util.spec_from_file_location('fixtures', root / 'reference-inputs/tests/host/check-desktop-symbol-audit.py')
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)

class ExecutableAuditTests(fixtures.SymbolTests):
    def test_executable_resolution(self):
        for arch in ('aarch64', 'arm64ec'):
            with self.subTest(arch=arch):
                self.arch = arch
                self.make_farm()
                self.put(self.overlay, 'installer.exe', imports=[('host.dll', ['Present', 7])],
                         delayed=[('host.dll', ['Present'])])
                result = self.run_audit(modules=['installer.exe'])
                self.assertTrue(result['passed'])
                self.assertEqual(result['counts']['checked_import_symbols'], 3)
                self.assertEqual(result['counts']['exports'], 0)
                for symbol in ('Missing', 8):
                    self.put(self.overlay, 'installer.exe', imports=[('host.dll', [symbol])])
                    with self.assertRaisesRegex(ValueError, 'unresolved'):
                        self.run_audit(modules=['installer.exe'])

suite = unittest.TestSuite([ExecutableAuditTests('test_executable_resolution')])
result = unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(not result.wasSuccessful())
