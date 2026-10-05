#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Production diagnostic helper and malformed-evidence checks; no Wine/iOS run."""
import importlib.util
import contextlib
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
CANARY = ROOT / "tests/desktop/msi_wow64"
sys.path.insert(0, str(CANARY))
import madeira_reference as GATE

GOOD = """MADEIRA-MSI-WOW64: START parent-pid 101
MADEIRA-MSI-WOW64: PASS parent-guest-base-zero 0
MADEIRA-MSI-WOW64: ACTION positive-return 0
MADEIRA-MSI-WOW64: PASS parent-guest-base-zero 0
MADEIRA-MSI-WOW64: PASS child-syswow64-image 202
MADEIRA-MSI-WOW64: PASS child-guest-base-high 10
MADEIRA-MSI-WOW64: PASS child-guest-base-low 0
MADEIRA-MSI-WOW64: PASS child-pid 202
MADEIRA-MSI-WOW64: PASS positive-round 1
MADEIRA-MSI-WOW64: ACTION positive-return 0
MADEIRA-MSI-WOW64: PASS parent-guest-base-zero 0
MADEIRA-MSI-WOW64: PASS child-syswow64-image 202
MADEIRA-MSI-WOW64: PASS child-guest-base-high 10
MADEIRA-MSI-WOW64: PASS child-guest-base-low 0
MADEIRA-MSI-WOW64: PASS child-pid 202
MADEIRA-MSI-WOW64: PASS positive-round 2
MADEIRA-MSI-WOW64: PASS missing-export-rejected 1603
MADEIRA-MSI-WOW64: PASS parent-guest-base-zero 0
MADEIRA-MSI-WOW64: PASS child-syswow64-image 202
MADEIRA-MSI-WOW64: PASS child-guest-base-high 10
MADEIRA-MSI-WOW64: PASS child-guest-base-low 0
MADEIRA-MSI-WOW64: PASS session-close 0
MADEIRA-MSI-WOW64: PASS child-exit 202
MADEIRA-MSI-WOW64: PASS final 0
"""


class EvidenceTests(unittest.TestCase):
    def test_complete_log_with_optional_child_stderr(self):
        result = GATE.verify_madeira_proof(GOOD, 0)
        self.assertTrue(result["child_process_termination_proven"])
        self.assertTrue(result["child_live_after_negative_control"])
        self.assertEqual(result["guest_base"], 0xa00000000)
        self.assertEqual(result, GATE.verify_madeira_proof(GOOD + "MADEIRA-MSI-WOW64: CA-PROOF 202\n", 0))

    def test_each_required_row_is_required(self):
        for line in GOOD.splitlines(keepends=True):
            with self.subTest(line=line), self.assertRaises(ValueError):
                GATE.verify_madeira_proof(GOOD.replace(line, "", 1), 0)

    def test_reject_mismatched_identity_window_or_failure(self):
        mutations = [
            GOOD.replace("parent-guest-base-zero 0", "parent-guest-base-zero 1"),
            GOOD.replace("child-syswow64-image 202", "child-syswow64-image 303"),
            GOOD.replace("child-exit 202", "child-exit 303"),
            GOOD.replace("child-guest-base-high 10", "child-guest-base-high 0"),
            GOOD.replace("child-guest-base-high 10", "child-guest-base-high 11", 1),
            GOOD.replace("child-guest-base-low 0", "child-guest-base-low 1"),
            GOOD.replace("child-guest-base-low 0", "child-guest-base-low 65536"),
            GOOD.replace("child-guest-base-high 10", "child-guest-base-high 4294967295").replace("child-guest-base-low 0", "child-guest-base-low 1"),
            GOOD.replace("child-guest-base-high 10", "child-guest-base-high 4294967296"),
            GOOD.replace("PASS child-exit", "FAIL child-exit"),
            GOOD.replace("PASS child-exit 202", "PASS child-exit no"),
            GOOD + "MADEIRA-MSI-WOW64: PASS parent-guest-base-zero 0\n",
            GOOD + "MADEIRA-MSI-WOW64: PASS unsupported-guarantee 1\n",
            GOOD.replace("PASS child-exit 202\nMADEIRA-MSI-WOW64: PASS final 0", "PASS final 0\nMADEIRA-MSI-WOW64: PASS child-exit 202"),
        ]
        for log in mutations:
            with self.subTest(log=log), self.assertRaises(ValueError):
                GATE.verify_madeira_proof(log, 0)
        for code in (1, 124, -9):
            with self.subTest(code=code), self.assertRaises(ValueError):
                GATE.verify_madeira_proof(GOOD, code)

    def test_negative_control_requires_live_same_child_before_close(self):
        before, after = GOOD.split("PASS missing-export-rejected 1603\n", 1)
        for changed in (after.replace("parent-guest-base-zero 0", "parent-guest-base-zero 1"),
                        after.replace("child-syswow64-image 202", "child-syswow64-image 303"),
                        after.replace("child-guest-base-high 10", "child-guest-base-high 11"),
                        after.replace("PASS child-syswow64-image 202", "FAIL child-not-live 202")):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                GATE.verify_madeira_proof(before + "PASS missing-export-rejected 1603\n" + changed, 0)

    def test_default_windows_reference_stays_opt_in(self):
        host = (CANARY / "canary_host.c").read_text()
        self.assertEqual(host.count("#if defined(MADEIRA_I386_DIAGNOSTIC) && MADEIRA_I386_DIAGNOSTIC == 1"), 5)
        self.assertNotIn("MADEIRA_I386_DIAGNOSTIC", (CANARY / "build_msvc.cmd").read_text())
        self.assertNotIn("MADEIRA_I386_DIAGNOSTIC", (CANARY / "windows_reference.py").read_text())

    def test_growing_log_is_read_with_a_bound(self):
        class GrowingLog(io.BytesIO):
            requested = None
            def read(self, size=-1):
                self.requested = size
                return super().read(size)
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "runtime.log"
            path.write_text("small before opening")
            stream = GrowingLog(b"x" * (GATE.MAX_LOG + 10))
            with mock.patch.object(Path, "open", return_value=stream), \
                 mock.patch.object(sys, "argv", ["verify", str(path), "--exit-code", "0"]), \
                 contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                GATE.main()
            self.assertEqual(stream.requested, GATE.MAX_LOG + 1)

    def test_production_helper_api_failure_paths(self):
        with tempfile.TemporaryDirectory(prefix="madeira-diagnostic-unit-") as name:
            executable = Path(name) / "unit"
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-I", str(CANARY),
                            str(ROOT / "tests/host/fixtures/msi-madeira-runtime.c"), "-o", str(executable)], check=True)
            subprocess.run([str(executable)], check=True, timeout=5)


if __name__ == "__main__":
    unittest.main()
