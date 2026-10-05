#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Regression checks for evidence required from the Windows reference canary."""
import importlib.util
import contextlib
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "msi_windows_reference", ROOT / "tests/desktop/msi_wow64/windows_reference.py")
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)

GOOD = """MADEIRA-MSI-WOW64: START parent-pid 101
MADEIRA-MSI-WOW64: PASS missing-export-rejected 1603
MADEIRA-MSI-WOW64: PASS child-pid 202
MADEIRA-MSI-WOW64: PASS positive-round 1
MADEIRA-MSI-WOW64: PASS child-pid 202
MADEIRA-MSI-WOW64: PASS positive-round 2
MADEIRA-MSI-WOW64: PASS session-close 0
MADEIRA-MSI-WOW64: PASS final 0
"""


class ProofTests(unittest.TestCase):
    def test_real_effects_are_required_and_child_stderr_is_optional(self):
        result = GATE.verify_proof(GOOD, 0)
        self.assertEqual(result["child_pids"], [202, 202])
        self.assertFalse(result["child_process_termination_proven"])
        self.assertEqual(GATE.verify_proof(GOOD + "MADEIRA-MSI-WOW64: CA-PROOF 202\n", 0), result)
        self.assertEqual(GATE.verify_proof(GOOD.replace("rejected 1603", "rejected 1627"), 0)["missing_export_error"], 1627)

    def test_exit_zero_and_a_final_line_are_insufficient(self):
        for output in ("", "MADEIRA-MSI-WOW64: PASS final 0\n",
                       GOOD.replace("MADEIRA-MSI-WOW64: PASS positive-round 2\n", ""),
                       GOOD.replace("MADEIRA-MSI-WOW64: PASS session-close 0\n", "")):
            with self.subTest(output=output), self.assertRaises(ValueError):
                GATE.verify_proof(output, 0)

    def test_negative_control_cannot_be_silently_ignored(self):
        for output in (GOOD.replace("rejected 1603", "rejected 0"),
                       GOOD.replace("PASS missing-export-rejected", "FAIL missing-export-reported-success"),
                       GOOD.replace("MADEIRA-MSI-WOW64: PASS missing-export-rejected 1603\n", "")):
            with self.subTest(output=output), self.assertRaises(ValueError):
                GATE.verify_proof(output, 0)

    def test_cross_process_identity_and_exact_rounds_are_required(self):
        for output in (GOOD.replace("child-pid 202", "child-pid 101"),
                       GOOD.replace("child-pid 202", "child-pid 0"),
                       GOOD.replace("child-pid 202", "child-pid 4294967296"),
                       GOOD.replace("positive-round 2", "positive-round 1"),
                       GOOD + "MADEIRA-MSI-WOW64: START parent-pid 303\n",
                       GOOD + "MADEIRA-MSI-WOW64: PASS final 0\n"):
            with self.subTest(output=output), self.assertRaises(ValueError):
                GATE.verify_proof(output, 0)

    def test_failure_timeout_and_malformed_values_are_rejected(self):
        with self.assertRaises(ValueError):
            GATE.verify_proof(GOOD, 124)
        for output in (GOOD + "MADEIRA-MSI-WOW64: FAIL watchdog-timeout 124\n",
                       GOOD.replace("rejected 1603", "rejected nope"),
                       GOOD.replace("session-close 0", "session-close 5")):
            with self.subTest(output=output), self.assertRaises(ValueError):
                GATE.verify_proof(output, 0)

    def test_timeout_prints_bounded_diagnostics_without_claiming_success(self):
        def timeout(argv, **kwargs):
            kwargs["stdout"].write(b"ignored prefix" + b"x" * 64 + b"partial diagnostic\n")
            raise subprocess.TimeoutExpired(argv, 1)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = io.StringIO()
            with mock.patch.object(GATE.subprocess, "run", side_effect=timeout), \
                 mock.patch.object(GATE, "MAX_LOG", 32), \
                 contextlib.redirect_stdout(output), self.assertRaises(subprocess.TimeoutExpired):
                GATE.logged(["owned-canary"], root, {}, root / "timeout.log", 1)
            self.assertIn("partial diagnostic", output.getvalue())
            self.assertNotIn("ignored prefix", output.getvalue())
            self.assertLessEqual(len(output.getvalue().encode()), 32)
            self.assertTrue((root / "timeout.log").is_file())


class WorkflowTests(unittest.TestCase):
    def test_reference_scope_is_public_bounded_and_source_owned(self):
        text = (ROOT / ".github/workflows/msi-windows-reference.yml").read_text()
        self.assertIn("runs-on: windows-2025", text)
        self.assertIn("timeout-minutes: 10", text)
        self.assertIn("github.repository == 'Mi-Yomi/Madeira'", text)
        self.assertIn("github.event.repository.private == false", text)
        self.assertIn("github.ref == 'refs/heads/compatibility/desktop-apps'", text)
        self.assertIn("persist-credentials: false", text)
        self.assertIn("contents: read", text)
        self.assertIn("check-msi-windows-reference.py", text)
        self.assertIn('windows_reference.py --work-root "$env:RUNNER_TEMP/', text)
        for forbidden in ("actions/upload-artifact@", "actions/cache@", "secrets.",
                          "curl ", "Invoke-WebRequest", "choco ", "winget ", "msiexec /i"):
            self.assertNotIn(forbidden, text)
        self.assertEqual(text.count("uses:"), 1)
        self.assertNotIn("MsiInstallProduct", (ROOT / "tests/desktop/msi_wow64/canary_host.c").read_text())


if __name__ == "__main__":
    unittest.main()
